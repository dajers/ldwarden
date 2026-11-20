from __future__ import annotations

import fnmatch
import os
import shutil
import subprocess
import tempfile
import uuid
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from urllib.parse import urlparse

from app.config import Settings

LANG_BY_EXT = {
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".gradle": "gradle",
    ".java": "java",
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".go": "go",
    ".rb": "ruby",
    ".php": "php",
    ".cs": "csharp",
    ".rs": "rust",
    ".sh": "shell",
    ".bash": "shell",
    ".ps1": "powershell",
    ".yml": "yaml",
    ".yaml": "yaml",
    ".json": "json",
    ".toml": "toml",
    ".properties": "properties",
    ".xml": "xml",
    ".sql": "sql",
    ".html": "html",
    ".htm": "html",
    ".md": "markdown",
    ".txt": "text",
    ".env": "dotenv",
    ".conf": "config",
    ".cfg": "config",
    ".ini": "config",
    ".tf": "terraform",
    ".dockerfile": "dockerfile",
}

TEXT_EXTENSIONS = set(LANG_BY_EXT) | {
    ".gradle.kts",
    ".env.example",
    ".dockerfile",
    ".lock",
    ".lockfile",
    ".gitignore",
    ".sql",
    ".csv",
}

SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".gradle",
    ".idea",
    ".vscode",
    ".mvn",
    "build",
    "out",
    "target",
    "dist",
    "node_modules",
    "venv",
    ".venv",
    "env",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".tox",
    "coverage",
    ".next",
    ".nuxt",
    "vendor",
    "bin",
    "obj",
    ".cache",
    "llms",
}

SKIP_SUFFIXES = {
    ".class",
    ".jar",
    ".war",
    ".ear",
    ".zip",
    ".tar",
    ".gz",
    ".tgz",
    ".bz2",
    ".xz",
    ".7z",
    ".rar",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
    ".ico",
    ".svg",
    ".pdf",
    ".doc",
    ".docx",
    ".xls",
    ".xlsx",
    ".ppt",
    ".pptx",
    ".mp3",
    ".mp4",
    ".mov",
    ".avi",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".so",
    ".dll",
    ".dylib",
    ".exe",
    ".bin",
    ".gguf",
    ".onnx",
    ".pt",
    ".db",
    ".sqlite",
    ".sqlite3",
    ".pyc",
    ".pyo",
}

SKIP_NAMES = {
    ".DS_Store",
    "Thumbs.db",
    "desktop.ini",
    ".gitignore",
    ".gitattributes",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "gradle-wrapper.jar",
}

SOURCE_META_SUFFIX = ".meta.json"


def is_junk_name(name: str) -> bool:
    return name.startswith("._") or name in SKIP_NAMES or name.startswith(".AppleDouble")


def language_for_path(path: str | Path) -> str:
    name = Path(path).name.lower()
    if name == "build.gradle.kts" or name == "settings.gradle.kts":
        return "gradle-kts"
    if name == "gradle.properties":
        return "properties"
    if name == "dockerfile" or name.startswith("dockerfile."):
        return "dockerfile"
    suffix = Path(name).suffix.lower()
    return LANG_BY_EXT.get(suffix, "text" if suffix in TEXT_EXTENSIONS else "unknown")


def is_probably_text(path: Path) -> bool:
    try:
        with path.open("rb") as handle:
            chunk = handle.read(4096)
    except OSError:
        return False
    if not chunk:
        return True
    if b"\x00" in chunk:
        return False

    try:
        chunk.decode("utf-8")
    except UnicodeDecodeError:
        try:
            chunk.decode("latin-1")
        except UnicodeDecodeError:
            return False
    return True


@dataclass
class SourceFile:
    abs_path: Path
    rel_path: str
    language: str
    size: int = 0
    _text: str | None = None
    _error: str | None = None

    @property
    def text(self) -> str:
        if self._text is None:
            try:
                self._text = self.abs_path.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                self._error = str(exc)
                self._text = ""
        return self._text

    @property
    def lines(self) -> list[str]:
        return self.text.splitlines()

    @property
    def line_count(self) -> int:
        return len(self.lines)

    def read_lines(self, start: int = 1, end: int | None = None) -> list[str]:
        lines = self.lines
        start = max(1, start)
        end = len(lines) if end is None else min(len(lines), end)
        return lines[start - 1 : end]


@dataclass
class SourceTree:
    root: Path
    label: str
    kind: str
    files: list[SourceFile] = field(default_factory=list)
    skipped: int = 0
    warnings: list[str] = field(default_factory=list)

    def by_language(self, *languages: str) -> list[SourceFile]:
        wanted = {lang.lower() for lang in languages}
        return [f for f in self.files if f.language in wanted]

    def find(self, rel_or_name: str) -> SourceFile | None:
        rel_or_name = rel_or_name.replace("\\", "/").lstrip("./")
        for source_file in self.files:
            if source_file.rel_path == rel_or_name or Path(source_file.rel_path).name == rel_or_name:
                return source_file
        return None

    def read(self, rel_path: str) -> str:
        source_file = self.find(rel_path)
        return source_file.text if source_file else ""

    @property
    def stats(self) -> dict:
        by_lang: dict[str, int] = {}
        for file in self.files:
            by_lang[file.language] = by_lang.get(file.language, 0) + 1
        return {
            "files": len(self.files),
            "skipped": self.skipped,
            "by_language": dict(sorted(by_lang.items(), key=lambda item: (-item[1], item[0]))),
            "warnings": self.warnings,
        }

    def to_dict(self) -> dict:
        return {
            "label": self.label,
            "kind": self.kind,
            "root": str(self.root),
            **self.stats,
        }


def build_tree(
    root: Path,
    *,
    label: str | None = None,
    kind: str = "path",
    max_files: int = 20_000,
    max_file_bytes: int = 2 * 1024 * 1024,
    include: list[str] | None = None,
    exclude: list[str] | None = None,
) -> SourceTree:
    root = Path(root).resolve()
    tree = SourceTree(root=root, label=label or root.name, kind=kind)
    if root.is_file():
        if root.stat().st_size <= max_file_bytes and is_probably_text(root):
            tree.files.append(
                SourceFile(root, root.name, language_for_path(root), root.stat().st_size)
            )
        else:
            tree.skipped += 1
        return tree
    if not root.is_dir():
        raise FileNotFoundError(f"Источник не найден: {root}")

    include_patterns = include or []
    exclude_patterns = exclude or []
    for current, dirnames, filenames in os.walk(root, followlinks=False):
        current_path = Path(current)
        dirnames[:] = sorted(
            d
            for d in dirnames
            if d not in SKIP_DIRS and not d.startswith(".") and not is_junk_name(d)
        )
        for filename in sorted(filenames):
            if is_junk_name(filename):
                tree.skipped += 1
                continue
            path = current_path / filename
            try:
                rel = path.relative_to(root).as_posix()
            except ValueError:
                tree.skipped += 1
                continue
            if include_patterns and not any(fnmatch.fnmatch(rel, p) for p in include_patterns):
                continue
            if exclude_patterns and any(fnmatch.fnmatch(rel, p) for p in exclude_patterns):
                continue
            if path.suffix.lower() in SKIP_SUFFIXES:
                tree.skipped += 1
                continue
            if path.is_symlink():
                try:
                    path.resolve().relative_to(root)
                except (ValueError, OSError):
                    tree.skipped += 1
                    tree.warnings.append(f"Пропущена символьная ссылка за пределами проекта: {rel}")
                    continue
            try:
                size = path.stat().st_size
            except OSError:
                tree.skipped += 1
                continue
            if size > max_file_bytes:
                tree.skipped += 1
                tree.warnings.append(f"Пропущен большой файл: {rel} ({size} байт)")
                continue
            language = language_for_path(path)
            if language == "unknown" or not is_probably_text(path):
                tree.skipped += 1
                continue
            tree.files.append(SourceFile(abs_path=path, rel_path=rel, language=language, size=size))
            if len(tree.files) >= max_files:
                tree.warnings.append(
                    f"Достигнут лимит {max_files} файлов; часть проекта не проанализирована"
                )
                return tree
    return tree


class SourceService:
    def __init__(self, settings: Settings):
        self.settings = settings


    def normalize_target(self, target: dict | str | None) -> dict:
        if target is None or target == "":
            return {"kind": "default"}
        if isinstance(target, str):
            return {"kind": "path", "path": target}
        if not isinstance(target, dict):
            raise ValueError("target должен быть строкой или объектом")
        kind = str(target.get("kind") or "path").lower()
        if kind not in {"default", "path", "source", "git"}:
            raise ValueError(f"Неизвестный тип источника: {kind}")
        return {**target, "kind": kind}

    def resolve(self, target: dict | str | None, include: list[str] | None = None, exclude: list[str] | None = None) -> SourceTree:
        target = self.normalize_target(target)
        kind = target["kind"]
        if kind == "default":
            root = self.settings.default_target
            label = "training-project"
        elif kind == "path":
            raw = target.get("path") or str(self.settings.default_target)
            root = self.settings.resolve_allowed_path(raw)
            try:
                label = root.relative_to(self.settings.base_dir).as_posix()
            except ValueError:
                label = root.name
        elif kind == "source":
            source_id = str(target.get("id") or target.get("source_id") or "")
            root = self.settings.source_dir(source_id)
            if not root.exists():
                raise FileNotFoundError(f"Источник {source_id} не найден")
            meta = self.read_source_meta(source_id)
            stored_root = meta.get("root")
            if stored_root:
                candidate = Path(stored_root).resolve()
                if candidate == root.resolve() or root.resolve() in candidate.parents:
                    root = candidate
            elif root.is_dir():
                root = self._strip_single_root(root)
            label = meta.get("name") or source_id
        elif kind == "git":
            root = self._clone_git(str(target.get("url") or ""), str(target.get("ref") or ""))
            label = root.name
        else:
            raise ValueError(f"Неизвестный тип источника: {kind}")
        tree = build_tree(
            root,
            label=label,
            kind=kind,
            max_files=self.settings.max_files,
            max_file_bytes=self.settings.max_file_bytes,
            include=include,
            exclude=exclude,
        )
        return tree


    def create_from_zip(self, file_storage, name: str | None = None) -> dict:
        source_id = uuid.uuid4().hex[:16]
        dest = self.settings.source_dir(source_id)
        dest.mkdir(parents=True, exist_ok=False)
        tmp_path = self.settings.tmp_dir / f"{source_id}.zip"
        try:
            file_storage.save(str(tmp_path))
            size = tmp_path.stat().st_size
            if size > self.settings.max_upload_bytes:
                raise ValueError(
                    f"Архив больше допустимого размера ({size} > {self.settings.max_upload_bytes})"
                )
            self._safe_extract_zip(tmp_path, dest)
            root = self._strip_single_root(dest)
            file_count = sum(1 for p in root.rglob("*") if p.is_file())
            meta = {
                "id": source_id,
                "name": (name or file_storage.filename or "uploaded-source").strip()[:120],
                "kind": "upload",
                "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "files": file_count,
            }
            meta["root"] = str(root)
            self._write_source_meta(source_id, meta)
            return meta
        except Exception:
            shutil.rmtree(dest, ignore_errors=True)
            raise
        finally:
            tmp_path.unlink(missing_ok=True)

    def _safe_extract_zip(self, archive: Path, dest: Path) -> None:
        if not zipfile.is_zipfile(archive):
            raise ValueError("Файл не является ZIP-архивом")
        total = 0
        with zipfile.ZipFile(archive) as zf:
            infos = zf.infolist()
            if len(infos) > self.settings.max_zip_entries:
                raise ValueError("В архиве слишком много файлов")
            for info in infos:
                total += info.file_size
                if total > self.settings.max_zip_uncompressed:
                    raise ValueError("Распакованный архив слишком большой")
                if info.compress_size and info.file_size / max(info.compress_size, 1) > 500:
                    raise ValueError("Подозрительный коэффициент сжатия (zip bomb)")
                name = info.filename.replace("\\", "/")
                if not name or name.endswith("/"):
                    continue
                if name.startswith("/") or ".." in PurePosixPath(name).parts:
                    raise ValueError(f"Небезопасный путь в архиве: {name}")
                if is_junk_name(PurePosixPath(name).name):
                    continue
                mode = info.external_attr >> 16
                if mode and (mode & 0o170000) == 0o120000:
                    raise ValueError(f"Символьные ссылки в архиве запрещены: {name}")
                target = (dest / name).resolve()
                if dest not in target.parents and target != dest:
                    raise ValueError(f"Путь выходит за пределы каталога: {name}")
                target.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(info, "r") as src, target.open("wb") as out:
                    shutil.copyfileobj(src, out, length=1024 * 1024)

    def _strip_single_root(self, dest: Path) -> Path:
        entries = [p for p in dest.iterdir() if p.name != SOURCE_META_SUFFIX]
        if len(entries) == 1 and entries[0].is_dir():
            return entries[0]
        return dest

    def _meta_path(self, source_id: str) -> Path:
        return self.settings.sources_dir / f"{source_id}{SOURCE_META_SUFFIX}"

    def _write_source_meta(self, source_id: str, meta: dict) -> None:
        import json

        self._meta_path(source_id).write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")

    def read_source_meta(self, source_id: str) -> dict:
        import json

        path = self._meta_path(source_id)
        if not path.exists():
            return {}
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except ValueError:
            return {}

    def list_sources(self) -> list[dict]:
        result = []
        for path in sorted(self.settings.sources_dir.glob(f"*{SOURCE_META_SUFFIX}")):
            source_id = path.name[: -len(SOURCE_META_SUFFIX)]
            meta = self.read_source_meta(source_id)
            if meta:
                meta["exists"] = self.settings.source_dir(source_id).exists()
                result.append(meta)
        return result

    def delete_source(self, source_id: str) -> None:
        root = self.settings.source_dir(source_id)
        if root.exists():
            shutil.rmtree(root)
        self._meta_path(source_id).unlink(missing_ok=True)


    def _clone_git(self, url: str, ref: str) -> Path:
        if not url:
            raise ValueError("Не указан URL репозитория")
        parsed = urlparse(url)
        if parsed.scheme != "https" or not parsed.hostname:
            raise ValueError("Разрешены только HTTPS-ссылки на репозитории")
        if parsed.username or parsed.password:
            raise ValueError("Учётные данные в URL запрещены; используйте токен в настройках CI")
        allowed = {h.lower() for h in self.settings.allowed_git_hosts}
        if not allowed:
            raise PermissionError(
                "Клонирование репозиториев отключено. Задайте LDWARDEN_ALLOWED_GIT_HOSTS "
                "(например, github.com) или загрузите ZIP."
            )
        if parsed.hostname.lower() not in allowed:
            raise PermissionError(f"Хост {parsed.hostname} не входит в allow-list")
        if ref and not all(ch.isalnum() or ch in "._/-" for ch in ref):
            raise ValueError("Некорректное имя ветки/тега")
        source_id = uuid.uuid4().hex[:16]
        dest = self.settings.source_dir(source_id)
        dest.mkdir(parents=True, exist_ok=False)
        cmd = ["git", "clone", "--depth", "1", "--no-tags", "--single-branch"]
        if ref:
            cmd += ["--branch", ref]
        cmd += [url, str(dest)]
        env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": "echo"}
        try:
            proc = subprocess.run(
                cmd,
                check=False,
                capture_output=True,
                text=True,
                timeout=self.settings.git_timeout,
                env=env,
            )
            if proc.returncode != 0:
                raise RuntimeError(f"git clone завершился с ошибкой: {proc.stderr[-500:]}")
            shutil.rmtree(dest / ".git", ignore_errors=True)
            meta = {
                "id": source_id,
                "name": parsed.path.rsplit("/", 1)[-1].removesuffix(".git") or "git-source",
                "kind": "git",
                "url": url,
                "ref": ref,
                "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            }
            self._write_source_meta(source_id, meta)
            return dest
        except Exception:
            shutil.rmtree(dest, ignore_errors=True)
            raise


def temporary_directory(settings: Settings, prefix: str = "run-") -> Path:
    return Path(tempfile.mkdtemp(prefix=prefix, dir=str(settings.tmp_dir)))
