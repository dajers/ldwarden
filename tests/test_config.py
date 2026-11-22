from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from app.config import Settings


class RelativePathSettingsTests(unittest.TestCase):
    def test_relative_paths_resolve_from_project_root(self):
        root = Path(tempfile.mkdtemp(prefix="ldw-relative-")).resolve()
        settings = Settings(
            base_dir=root,
            data_dir="data",
            db_path="data/test.db",
            sources_dir="data/sources",
            tmp_dir="data/tmp",
            secret_key_path="data/secret.key",
            default_target="training-project",
            vulnerability_db_path="data/vulnerabilities.json",
            workflow_templates_dir="templates",
            frontend_dir="frontend",
            allowed_roots=["training-project", "data/sources"],
            llm_models_dir="models",
            llm_model_path="models/model.gguf",
            seed_templates=False,
        )
        self.assertEqual(settings.data_dir, root / "data")
        self.assertEqual(settings.db_path, root / "data" / "test.db")
        self.assertEqual(settings.secret_key_path, root / "data" / "secret.key")
        self.assertEqual(settings.default_target, root / "training-project")
        self.assertEqual(settings.llm_models_dir, root / "models")
        self.assertEqual(settings.llm_model_path, root / "models" / "model.gguf")
        self.assertEqual(settings.allowed_roots, [root / "training-project", root / "data" / "sources"])
