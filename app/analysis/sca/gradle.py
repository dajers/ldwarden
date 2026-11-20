from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from app.analysis.sca.version import parse_version

CONFIGURATIONS = {
    "implementation",
    "api",
    "compileOnly",
    "compileOnlyApi",
    "runtimeOnly",
    "testImplementation",
    "testCompileOnly",
    "testRuntimeOnly",
    "annotationProcessor",
    "kapt",
    "ksp",
    "platform",
    "enforcedPlatform",
    "developmentOnly",
    "productionRuntimeOnly",
}

COORDINATE_RE = re.compile(
    r"^(?P<group>[A-Za-z0-9_.\-]+):(?P<artifact>[A-Za-z0-9_.\-]+)(?::(?P<version>[^:\s]+))?$"
)
VAL_CONST_RE = re.compile(
    r"^\s*(?:(?:private|public|internal|protected|const|override)\s+)*val\s+"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*(?::\s*[^=]+)?=\s*(?P<expr>.+?)\s*$"
)
PROPERTY_RE = re.compile(r'^\s*(?P<key>[A-Za-z0-9_.\-]+)\s*=\s*(?P<value>.*?)\s*$')
GRADLE_PROP_RE = re.compile(
    r'providers\.gradleProperty\(\s*"(?P<key>[^"]+)"\s*\)'
    r'(?:\.(?:get|getOrNull|orNull))?'
    r'(?:\s*\?:\s*"(?P<fallback>[^"]*)")?'
)
LOCK_RE = re.compile(
    r"^(?P<group>[A-Za-z0-9_.\-]+):(?P<artifact>[A-Za-z0-9_.\-]+):(?P<version>[^=\s]+)="
)


@dataclass
class Constant:
    name: str
    value: str | None
    line: int
    source_file: str
    source_line: int
    resolved: bool = False


@dataclass
class Dependency:
    group: str
    artifact: str
    version: str | None
    file: str
    line: int
    scope: str = "implementation"
    raw: str = ""
    version_file: str = ""
    version_line: int | None = None
    version_kind: str = ""
    warnings: list[str] = field(default_factory=list)

    @property
    def coordinate(self) -> str:
        return f"{self.group}:{self.artifact}"


@dataclass
class GradleProject:
    dependencies: list[Dependency] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    files_scanned: list[str] = field(default_factory=list)


def strip_kotlin_strings_and_comments(text: str) -> str:
    """Blank out comments and string bodies while preserving positions/newlines."""
    out = list(text)
    length = len(text)
    i = 0
    while i < length:
        char = text[i]
        nxt = text[i + 1] if i + 1 < length else ""
        if char == "/" and nxt == "/":
            while i < length and text[i] != "\n":
                out[i] = " "
                i += 1
            continue
        if char == "/" and nxt == "*":
            out[i] = out[i + 1] = " "
            i += 2
            while i < length and not (text[i] == "*" and i + 1 < length and text[i + 1] == "/"):
                if text[i] != "\n":
                    out[i] = " "
                i += 1
            if i < length:
                out[i] = " "
                if i + 1 < length:
                    out[i + 1] = " "
                i += 2
            continue
        if text.startswith('"""', i):
            out[i] = out[i + 1] = out[i + 2] = " "
            i += 3
            while i < length and not text.startswith('"""', i):
                if text[i] != "\n":
                    out[i] = " "
                i += 1
            if i < length:
                out[i] = out[i + 1] = out[i + 2] = " "
                i += 3
            continue
        if char in {'"', "'"}:
            quote = char
            out[i] = " "
            i += 1
            while i < length:
                if text[i] == "\\":
                    out[i] = " "
                    if i + 1 < length:
                        out[i + 1] = " "
                    i += 2
                    continue
                if text[i] == quote:
                    out[i] = " "
                    i += 1
                    break
                if text[i] != "\n":
                    out[i] = " "
                i += 1
            continue
        i += 1
    return "".join(out)


def _match_brace(sanitized: str, open_index: int) -> int:
    depth = 0
    for index in range(open_index, len(sanitized)):
        char = sanitized[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return index
    return -1


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def parse_properties(path: Path, rel: str) -> dict[str, Constant]:
    constants: dict[str, Constant] = {}
    text = _read(path)
    for index, line in enumerate(text.splitlines(), 1):
        if not line.strip() or line.lstrip().startswith(("#", "!")):
            continue
        match = PROPERTY_RE.match(line)
        if not match:
            continue
        key = match.group("key")
        value = match.group("value")
        constants[key] = Constant(
            name=key,
            value=value,
            line=index,
            source_file=rel,
            source_line=index,
            resolved=True,
        )
    return constants


def parse_lockfile(path: Path, rel: str) -> dict[tuple[str, str], Constant]:
    locked: dict[tuple[str, str], Constant] = {}
    text = _read(path)
    for index, line in enumerate(text.splitlines(), 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        match = LOCK_RE.match(line)
        if not match:
            continue
        locked[(match.group("group"), match.group("artifact"))] = Constant(
            name=f"{match.group('group')}:{match.group('artifact')}",
            value=match.group("version"),
            line=index,
            source_file=rel,
            source_line=index,
            resolved=True,
        )
    return locked


def parse_constants(text: str, rel: str, properties: dict[str, Constant]) -> dict[str, Constant]:
    constants: dict[str, Constant] = {}
    for index, line in enumerate(text.splitlines(), 1):
        match = VAL_CONST_RE.match(line)
        if not match:
            continue
        name = match.group("name")
        expr = match.group("expr").strip()

        literal = re.fullmatch(r'"((?:\\.|[^"\\])*)"', expr)
        if literal:
            constants[name] = Constant(name, literal.group(1), index, rel, index, True)
            continue

        parts = [part.strip() for part in re.split(r"\s+\+\s+", expr) if part.strip()]
        if parts and all(re.fullmatch(r'"(?:\\.|[^"\\])*"', part) for part in parts):
            value = "".join(part[1:-1] for part in parts)
            constants[name] = Constant(name, value, index, rel, index, True)
            continue

        prop = GRADLE_PROP_RE.search(expr)
        if prop:
            key = prop.group("key")
            if key in properties:
                source = properties[key]
                constants[name] = Constant(
                    name, source.value, index, source.source_file, source.source_line, True
                )
            elif prop.group("fallback") is not None:
                constants[name] = Constant(name, prop.group("fallback"), index, rel, index, True)
            else:
                constants[name] = Constant(name, None, index, rel, index, False)
            continue

        prop_call = re.search(r'(?:rootProject\.)?property\(\s*"([^"]+)"\s*\)', expr)
        if prop_call:
            key = prop_call.group(1)
            if key in properties:
                source = properties[key]
                constants[name] = Constant(
                    name, source.value, index, source.source_file, source.source_line, True
                )
            continue

        constants[name] = Constant(name, None, index, rel, index, False)

    source_lines = text.splitlines()
    for _ in range(2):
        for constant in constants.values():
            if constant.value is not None:
                continue
            if not (0 < constant.line <= len(source_lines)):
                continue
            declaration = VAL_CONST_RE.match(source_lines[constant.line - 1])
            if not declaration:
                continue
            expression = declaration.group("expr").strip()
            reference = re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", expression)
            if reference and reference.group(0) in constants:
                target = constants[reference.group(0)]
                if target.value is not None:
                    constant.value = target.value
                    constant.source_file = target.source_file
                    constant.source_line = target.source_line
                    constant.resolved = True
    return constants


def parse_version_catalog(path: Path, rel: str) -> tuple[dict[str, Constant], dict[str, tuple[str, Constant]]]:
    text = _read(path)
    versions: dict[str, Constant] = {}
    libraries: dict[str, tuple[str, Constant]] = {}
    section = ""
    for index, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("[") and stripped.endswith("]"):
            section = stripped[1:-1].strip()
            continue
        if section == "versions":
            match = re.match(r'^(?P<key>[A-Za-z0-9_.\-]+)\s*=\s*"(?P<value>[^"]+)"', stripped)
            if match:
                versions[match.group("key")] = Constant(
                    match.group("key"), match.group("value"), index, rel, index, True
                )
        elif section == "libraries":
            match = re.match(r'^(?P<alias>[A-Za-z0-9_.\-]+)\s*=\s*\{(?P<body>.*)\}\s*$', stripped)
            if not match:
                continue
            alias = match.group("alias")
            body = match.group("body")
            module_match = re.search(r'module\s*=\s*"([^"]+)"', body)
            version_match = re.search(r'version\s*=\s*"([^"]+)"', body)
            ref_match = re.search(r'version\.ref\s*=\s*"([^"]+)"', body)
            if not module_match:
                continue
            module = module_match.group("module")
            if version_match:
                constant = Constant(alias, version_match.group(1), index, rel, index, True)
            elif ref_match and ref_match.group(1) in versions:
                constant = versions[ref_match.group(1)]
            else:
                constant = Constant(alias, None, index, rel, index, False)
                constant.source_file = rel
            libraries[alias] = (module, constant)
    return versions, libraries


def _scope_for_line(lines: list[str], index: int) -> str:
    for probe in range(index, max(-1, index - 4), -1):
        line = lines[probe]
        for configuration in CONFIGURATIONS:
            if re.search(rf"\b{configuration}\b", line):
                return configuration
    return "implementation"


def _resolve_version(
    raw: str,
    constants: dict[str, Constant],
    declaration_file: str,
    declaration_line: int,
    locked: dict[tuple[str, str], Constant],
    group: str,
    artifact: str,
) -> tuple[str | None, str, int | None, str, list[str]]:
    warnings: list[str] = []
    if not raw:
        locked_entry = locked.get((group, artifact))
        if locked_entry and locked_entry.value:
            return locked_entry.value, locked_entry.source_file, locked_entry.source_line, "lockfile", warnings
        warnings.append(f"Версия {group}:{artifact} не объявлена явно и не найдена в lockfile")
        return None, declaration_file, declaration_line, "unknown", warnings
    text = raw.strip()
    name = None
    if text.startswith("${") and text.endswith("}"):
        name = text[2:-1]
    elif text.startswith("$"):
        name = text[1:]
    elif re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", text) and text in constants:
        name = text
    if name is not None:
        constant = constants.get(name)
        if constant and constant.value:
            if parse_version(constant.value) is None:
                warnings.append(f"Версия {group}:{artifact} содержит квалификатор: {constant.value}")
                return None, constant.source_file, constant.source_line, "constant", warnings
            return (
                constant.value,
                constant.source_file,
                constant.source_line,
                "constant" if constant.source_file == declaration_file else "property",
                warnings,
            )
        warnings.append(f"Не удалось разрешить версию {group}:{artifact} из переменной {name}")
        return None, declaration_file, declaration_line, "unknown", warnings
    if parse_version(text) is None:
        warnings.append(f"Версия {group}:{artifact} не является числовой: {text}")
        return None, declaration_file, declaration_line, "literal", warnings
    return text, declaration_file, declaration_line, "literal", warnings


def parse_build_gradle(root: Path) -> GradleProject:
    root = Path(root)
    project = GradleProject()
    build_path = root / "build.gradle.kts"
    if not build_path.exists():
        project.warnings.append("build.gradle.kts не найден: SCA-анализ пропущен")
        return project
    rel_build = build_path.relative_to(root).as_posix()
    text = _read(build_path)
    project.files_scanned.append(rel_build)

    properties: dict[str, Constant] = {}
    for name in ("gradle.properties", "gradle-local.properties"):
        prop_path = root / name
        if prop_path.exists():
            rel_prop = prop_path.relative_to(root).as_posix()
            properties.update(parse_properties(prop_path, rel_prop))
            project.files_scanned.append(rel_prop)

    constants = parse_constants(text, rel_build, properties)

    locked: dict[tuple[str, str], Constant] = {}
    for name in ("gradle.lockfile", "buildscript-gradle.lockfile"):
        lock_path = root / name
        if lock_path.exists():
            rel_lock = lock_path.relative_to(root).as_posix()
            locked.update(parse_lockfile(lock_path, rel_lock))
            project.files_scanned.append(rel_lock)

    catalog_libs: dict[str, tuple[str, Constant]] = {}
    catalog_path = root / "gradle" / "libs.versions.toml"
    if catalog_path.exists():
        rel_catalog = catalog_path.relative_to(root).as_posix()
        _versions, catalog_libs = parse_version_catalog(catalog_path, rel_catalog)
        project.files_scanned.append(rel_catalog)

    sanitized = strip_kotlin_strings_and_comments(text)
    block_match = re.search(r"\bdependencies\s*\{", sanitized)
    if not block_match:
        project.warnings.append("Блок dependencies { } не найден")
        return project
    open_index = sanitized.index("{", block_match.start())
    close_index = _match_brace(sanitized, open_index)
    if close_index < 0:
        project.warnings.append("Не удалось найти конец блока dependencies")
        return project

    block_start_line = _line_of(text, open_index)
    block_end_line = _line_of(text, close_index)
    lines = text.splitlines()

    for line_number in range(block_start_line, block_end_line + 1):
        line = lines[line_number - 1]
        if not line.strip() or line.lstrip().startswith("//"):
            continue
        scope = _scope_for_line(lines, line_number - 1)

        for accessor in re.finditer(r"\blibs\.([A-Za-z0-9_.]+)", line):
            alias = accessor.group(1)
            candidate_keys = [alias, alias.replace(".", "-"), alias.replace("-", ".")]
            entry = next((catalog_libs[key] for key in candidate_keys if key in catalog_libs), None)
            if not entry:
                project.warnings.append(f"Не найден alias каталога версий: libs.{alias}")
                continue
            module, constant = entry
            coordinate = f"{module}:{constant.value}" if constant.value else module
            _append_dependency(
                project,
                coordinate,
                rel_build,
                line_number,
                scope,
                raw=accessor.group(0),
                constants=constants,
                locked=locked,
                version_override=constant,
            )

        for literal in re.finditer(r'"([^"\n]*)"', line):
            raw = literal.group(1)
            coordinate_match = COORDINATE_RE.match(raw)
            if not coordinate_match:
                continue
            if coordinate_match.group("artifact") in CONFIGURATIONS:
                continue
            if raw in CONFIGURATIONS:
                continue
            _append_dependency(
                project,
                raw,
                rel_build,
                line_number,
                scope,
                raw=raw,
                constants=constants,
                locked=locked,
            )


    seen: set[tuple[str, str, str | None, int]] = set()
    unique: list[Dependency] = []
    for dependency in project.dependencies:
        key = (dependency.group, dependency.artifact, dependency.version, dependency.line)
        if key in seen:
            continue
        seen.add(key)
        unique.append(dependency)
    project.dependencies = unique
    return project


def _append_dependency(
    project: GradleProject,
    coordinate: str,
    file: str,
    line: int,
    scope: str,
    *,
    raw: str,
    constants: dict[str, Constant],
    locked: dict[tuple[str, str], Constant],
    version_override: Constant | None = None,
) -> None:
    match = COORDINATE_RE.match(coordinate)
    if not match:
        return
    group = match.group("group")
    artifact = match.group("artifact")
    raw_version = match.group("version") or ""
    if version_override is not None:
        if not version_override.value:
            project.warnings.append(f"Не удалось разрешить версию {group}:{artifact} из каталога")
            return
        version = version_override.value
        version_file = version_override.source_file
        version_line = version_override.source_line
        version_kind = "catalog"
        warnings: list[str] = []
    else:
        version, version_file, version_line, version_kind, warnings = _resolve_version(
            raw_version, constants, file, line, locked, group, artifact
        )
    if version is None:
        project.warnings.extend(warnings or [f"Пропущена зависимость без версии: {coordinate}"])
        return
    project.dependencies.append(
        Dependency(
            group=group,
            artifact=artifact,
            version=version,
            file=file,
            line=line,
            scope=scope,
            raw=raw,
            version_file=version_file,
            version_line=version_line,
            version_kind=version_kind,
            warnings=warnings,
        )
    )
