from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

from app.analysis import AnalysisResult, BaseAnalyzer
from app.analysis.sca.gradle import Dependency, GradleProject, parse_build_gradle
from app.analysis.sca.version import format_ranges, version_in_ranges
from app.core.models import Finding
from app.core.source import SourceTree


class AdvisoryDatabaseError(RuntimeError):
    pass


class AdvisoryDatabase:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.by_coordinate: dict[tuple[str, str], list[dict]] = {}
        self.meta: dict = {}
        self.loaded = False
        self.error: str | None = None
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            self.error = f"Справочник уязвимостей не найден: {self.path}"
            return
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            self.error = f"Не удалось прочитать справочник уязвимостей: {exc}"
            return
        if not isinstance(data, dict) or data.get("formatVersion") != 1:
            self.error = "Неподдерживаемый формат справочника уязвимостей"
            return
        self.meta = {
            "formatVersion": data.get("formatVersion"),
            "ecosystem": data.get("ecosystem"),
            "snapshot": data.get("snapshot", {}),
            "count": len(data.get("vulnerabilities", [])),
        }
        for advisory in data.get("vulnerabilities", []):
            group = advisory.get("group")
            artifact = advisory.get("artifact")
            if not group or not artifact or not advisory.get("ranges"):
                continue
            self.by_coordinate.setdefault((group, artifact), []).append(advisory)
        self.loaded = True

    def lookup(self, group: str, artifact: str) -> list[dict]:
        return self.by_coordinate.get((group, artifact), [])


@lru_cache(maxsize=8)
def _cached_db(path: str, mtime_ns: int) -> AdvisoryDatabase:

    return AdvisoryDatabase(Path(path))


def load_advisory_db(path: Path) -> AdvisoryDatabase:
    path = Path(path)
    try:
        mtime = path.stat().st_mtime_ns
    except OSError:
        mtime = 0
    return _cached_db(str(path), mtime)


def _advisory_ids(advisory: dict) -> list[str]:
    ids = [str(advisory.get("id"))] if advisory.get("id") else []
    ids.extend(str(alias) for alias in advisory.get("aliases", []) if alias)
    return list(dict.fromkeys(ids))


def _preferred_advisory_id(advisory: dict) -> str:
    ids = _advisory_ids(advisory)
    for candidate in ids:
        if candidate.startswith("CVE-"):
            return candidate
    return ids[0] if ids else ""


def _gradle_project_roots(tree: SourceTree, fallback: Path) -> list[Path]:
    """Найти корни Gradle-проектов, включая вложенные каталоги.

    При клонировании репозитория по URL корнем является весь репозиторий,
    а сам Gradle-проект может лежать в подпапке (например training-project/).
    """
    roots: set[Path] = set()
    for source_file in tree.files:
        if Path(source_file.rel_path).name != "build.gradle.kts":
            continue
        roots.add(source_file.abs_path.parent.resolve())
    if (fallback / "build.gradle.kts").exists():
        roots.add(fallback.resolve())
    return sorted(roots)


class SCAAnalyzer(BaseAnalyzer):
    name = "sca"
    title = "Уязвимые зависимости (SCA)"

    def __init__(self, db_path: Path | str):
        self.db_path = Path(db_path)

    def analyze(self, tree: SourceTree) -> AnalysisResult:
        root = tree.root if tree.root.is_dir() else tree.root.parent
        project_roots = _gradle_project_roots(tree, root)
        projects = [parse_build_gradle(project_root) for project_root in project_roots]
        if not projects:
            projects = [parse_build_gradle(root)]

        dependencies = []
        files_scanned: list[str] = []
        warnings: list[str] = []
        for project in projects:
            dependencies.extend(project.dependencies)
            files_scanned.extend(project.files_scanned)
            warnings.extend(project.warnings)
        # Один и тот же координата может встретиться в корневом и вложенном build-файле.
        unique_dependencies = []
        seen_dependencies: set[tuple[str, str, str | None, str, int]] = set()
        for dependency in dependencies:
            key = (
                dependency.group,
                dependency.artifact,
                dependency.version,
                dependency.file,
                dependency.line,
            )
            if key in seen_dependencies:
                continue
            seen_dependencies.add(key)
            unique_dependencies.append(dependency)

        database = load_advisory_db(self.db_path)
        if database.error and database.error not in warnings:
            warnings.append(database.error)
        findings: list[Finding] = []
        seen: set[tuple[str, str, str, str]] = set()
        matched_dependencies = 0

        for dependency in unique_dependencies:
            advisories = database.lookup(dependency.group, dependency.artifact) if database.loaded else []
            dependency_matched = False
            for advisory in advisories:
                if not version_in_ranges(dependency.version or "", advisory.get("ranges", [])):
                    continue
                advisory_id = _preferred_advisory_id(advisory)
                key = (
                    dependency.group,
                    dependency.artifact,
                    dependency.version or "",
                    advisory_id,
                )
                if key in seen:
                    continue
                seen.add(key)
                dependency_matched = True
                findings.append(_to_finding(dependency, advisory, advisory_id))
            if dependency_matched:
                matched_dependencies += 1

        return self._result(
            findings,
            len(files_scanned),
            dependencies=len(unique_dependencies),
            matched_dependencies=matched_dependencies,
            advisories_loaded=database.meta.get("count", 0),
            db_path=str(self.db_path),
            db_loaded=database.loaded,
            warnings=warnings,
        )


def _to_finding(dependency: Dependency, advisory: dict, advisory_id: str) -> Finding:
    ids = _advisory_ids(advisory)
    fixed = advisory.get("fixedVersions", [])
    ranges = format_ranges(advisory.get("ranges", []))
    cvss = advisory.get("cvss", [])
    score = ""
    if cvss and isinstance(cvss[0], dict):
        raw_score = str(cvss[0].get("score") or "")
        if raw_score and not raw_score.startswith("CVSS:"):
            score = f", CVSS {raw_score}"
    remediation = (
        f"Обновить зависимость {dependency.group}:{dependency.artifact} до исправленной версии "
        f"{', '.join(fixed)}."
        if fixed
        else f"Обновить зависимость {dependency.group}:{dependency.artifact} до поддерживаемой версии."
    )
    description = (
        f"Зависимость {dependency.group}:{dependency.artifact}:{dependency.version} "
        f"попадает в уязвимый диапазон {ranges} ({advisory_id}{score}). "
        f"Сверено со справочником уязвимостей Maven из учебного набора."
    )
    alternates: list[dict] = []
    if (
        dependency.version_line
        and dependency.version_file
        and (dependency.version_file != dependency.file or dependency.version_line != dependency.line)
    ):
        alternates.append(
            {
                "path": dependency.version_file,
                "line": dependency.version_line,
                "endLine": dependency.version_line,
                "reason": "Объявление версии",
            }
        )
    return Finding(
        category="SCA",
        class_name="known-vulnerable-dependency",
        path=dependency.file,
        line=dependency.line,
        end_line=dependency.line,
        severity=advisory.get("severity", "MEDIUM"),
        message=(
            f"Уязвимая зависимость {dependency.group}:{dependency.artifact}:{dependency.version}: "
            f"{advisory_id}"
        ),
        description=description,
        remediation=remediation,
        cwe=None,
        rule_id=str(advisory.get("id") or advisory_id),
        evidence=f"{dependency.group}:{dependency.artifact}:{dependency.version}",
        confidence=0.95,
        detector="sca-gradle",
        group=dependency.group,
        artifact=dependency.artifact,
        version=dependency.version,
        advisory_id=advisory_id,
        advisory_ids=ids,
        alternate_locations=alternates,
        extra={
            "range": ranges,
            "fixed_versions": fixed,
            "cvss": cvss,
            "sources": advisory.get("sources", []),
            "scope": dependency.scope,
            "version_kind": dependency.version_kind,
            "version_source": {
                "path": dependency.version_file,
                "line": dependency.version_line,
            },
            "declared_coordinate": dependency.raw,
        },
    )
