#!/usr/bin/env python3
"""Собрать переносимый архив LDWarden без venv, data, .env и моделей."""
from __future__ import annotations

import argparse
import os
import stat
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VERSION = "1.0.0"
INCLUDE = [
    "app",
    "training-main",
    "scripts",
    "requirements.txt",
    "requirements-ai.txt",
    "start.sh",
    "start.bat",
    "LDWarden.command",
    ".env.example",
    "README.md",
]
SKIP_DIRS = {
    "__pycache__",
    ".git",
    ".idea",
    ".vscode",
    "venv",
    "data",
    "dist",
    "llms",
}
SKIP_FILES = {
    ".env",
    ".DS_Store",
}
SKIP_SUFFIXES = {".pyc", ".pyo", ".gguf", ".sqlite", ".db"}


def iter_files(target: Path, include_models: bool):
    if target.is_file():
        yield target
        return
    for current, dirs, files in os.walk(target):
        current_path = Path(current)
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        for name in sorted(files):
            path = current_path / name
            if name in SKIP_FILES or path.suffix.lower() in SKIP_SUFFIXES:
                continue
            if "models" in path.parts and not include_models:
                continue
            yield path


def add_file(archive: zipfile.ZipFile, path: Path, arc_root: str) -> None:
    arcname = f"{arc_root}/{path.relative_to(ROOT).as_posix()}"
    info = zipfile.ZipInfo.from_file(path, arcname)
    mode = stat.S_IMODE(path.stat().st_mode)
    info.external_attr = (mode & 0xFFFF) << 16
    with path.open("rb") as handle:
        archive.writestr(info, handle.read())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Собрать портативный ZIP LDWarden")
    parser.add_argument("--version", default=VERSION, help="Версия для имени корня архива")
    parser.add_argument("--output", default="", help="Путь к ZIP (по умолчанию dist/ldwarden-portable-<version>.zip)")
    parser.add_argument("--include-models", action="store_true", help="Включить llms/*.gguf (архив будет очень большим)")
    args = parser.parse_args(argv)

    version = args.version.lstrip("v")
    output = Path(args.output or (ROOT / "dist" / f"ldwarden-portable-{version}.zip")).expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    arc_root = f"ldwarden-{version}"

    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
        for item in INCLUDE:
            target = ROOT / item
            if not target.exists():
                print(f"пропуск (нет файла): {item}", file=sys.stderr)
                continue
            for path in iter_files(target, args.include_models):
                add_file(archive, path, arc_root)

        if args.include_models:
            models_dir = ROOT / "llms"
            for path in sorted(models_dir.glob("*.gguf")):
                add_file(archive, path, arc_root)

        # Пустая папка llms нужна для локальной модели после распаковки.
        info = zipfile.ZipInfo(f"{arc_root}/llms/README.txt")
        info.external_attr = (0o644 & 0xFFFF) << 16
        archive.writestr(info, "Положите сюда GGUF-модель или настройте universal API в .env.\n")

    size_mb = output.stat().st_size / (1024 * 1024)
    print(f"Готово: {output} ({size_mb:.1f} MB)")
    print(f"Корень архива: {arc_root}/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
