from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from app.config import Settings
from app.db import close_db
from app.nodes.ai_node import AIAnalyzeNode
from tests.helpers import make_app, make_settings


class ModelsTests(unittest.TestCase):
    def setUp(self):
        self.models_dir = Path(tempfile.mkdtemp(prefix="ldw-models-"))
        (self.models_dir / "one.gguf").write_bytes(b"GGUF")
        self.app, self.settings = make_app(llm_models_dir=self.models_dir)
        self.client = self.app.test_client()

    def tearDown(self):
        close_db()

    def test_models_are_discovered(self):
        response = self.client.get("/api/models")
        self.assertEqual(response.status_code, 200)
        items = response.get_json()["items"]
        self.assertEqual([item["id"] for item in items], ["one.gguf"])

    def test_ai_model_override_is_relative_to_models_dir(self):
        resolved = AIAnalyzeNode._local_model_path(self.settings, "one.gguf")
        self.assertEqual(Path(resolved), (self.models_dir / "one.gguf").resolve())

    def test_auto_uses_default_model(self):
        resolved = AIAnalyzeNode._local_model_path(self.settings, "auto")
        self.assertEqual(Path(resolved), self.settings.llm_model_path)


class ModelPathTests(unittest.TestCase):
    def _settings(self, value: str):
        root = Path(tempfile.mkdtemp(prefix="ldw-model-heal-"))
        (root / "llms").mkdir()
        (root / "llms" / "m.gguf").write_bytes(b"GGUF")
        return Settings(
            base_dir=root,
            llm_models_dir=root / "llms",
            llm_model_path=value,
        )

    def test_relative_path_is_resolved_from_project_root(self):
        settings = self._settings("llms/m.gguf")
        self.assertEqual(settings.llm_model_path, (settings.base_dir / "llms" / "m.gguf").resolve())
        self.assertEqual(settings.effective_llm_provider, "local")

    def test_extra_directory_prefix_is_healed(self):
        settings = self._settings("ldwarden/llms/m.gguf")
        self.assertEqual(settings.llm_model_path, (settings.base_dir / "llms" / "m.gguf").resolve())
        self.assertEqual(settings.effective_llm_provider, "local")
