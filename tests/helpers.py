from __future__ import annotations

import tempfile
from pathlib import Path

from app.api.app import create_app
from app.config import Settings


def make_settings(**overrides) -> Settings:
    tmp = Path(tempfile.mkdtemp(prefix="ldw-tests-"))
    values = {
        "data_dir": tmp,
        "db_path": tmp / "test.db",
        "sources_dir": tmp / "sources",
        "tmp_dir": tmp / "tmp",
        "secret_key_path": tmp / "secret.key",
        "llm_provider": "fake",
        "seed_templates": True,
        "enable_scheduler": False,
    }
    values.update(overrides)
    settings = Settings(**values)
    settings.ensure_dirs()
    return settings


def make_app(**overrides):
    settings = make_settings(**overrides)
    return create_app(settings), settings
