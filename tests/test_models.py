from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

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
