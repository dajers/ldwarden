from __future__ import annotations

import unittest

from app.db import close_db
from tests.helpers import make_app


class CiIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.app, self.settings = make_app(llm_provider="fake")
        self.client = self.app.test_client()

    def tearDown(self):
        close_db()

    def test_snippets_include_gate_and_artifacts(self):
        response = self.client.get("/api/ci/snippets?workflow_id=tpl-ci-gate&base_url=https://demo.example")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        github = data["github_actions"]
        gitlab = data["gitlab_ci"]
        self.assertIn("actions/upload-artifact@v4", github)
        self.assertIn("/api/ci/run", github)
        self.assertIn("/api/ci/report/", github)
        self.assertIn("exit_code", github)
        self.assertIn("artifacts:", gitlab)
        self.assertIn("/api/ci/report/", gitlab)
        self.assertEqual(data["base_url"], "https://demo.example")

    def test_ci_report_endpoint(self):
        run = self.client.post(
            "/api/workflows/tpl-full-audit/runs", json={"wait": True, "target": {"kind": "default"}}
        ).get_json()
        response = self.client.get(f"/api/ci/report/{run['id']}?format=json")
        self.assertEqual(response.status_code, 200)
        self.assertIn("application/json", response.content_type)
        self.assertGreater(len(response.get_json()["findings"]), 0)
