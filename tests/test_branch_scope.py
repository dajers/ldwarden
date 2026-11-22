from __future__ import annotations

import unittest

from app.db import close_db
from tests.helpers import make_app


class BranchScopeTests(unittest.TestCase):
    def setUp(self):
        self.app, self.settings = make_app(llm_provider="fake")
        self.client = self.app.test_client()

    def tearDown(self):
        close_db()

    def test_report_uses_only_connected_scanner_branch(self):
        graph = {
            "nodes": [
                {"id": "t", "type": "trigger.manual", "position": {"x": 0, "y": 0}, "data": {}},
                {"id": "src", "type": "source.target", "position": {"x": 150, "y": 0}, "data": {}},
                {"id": "secret", "type": "scan.secrets", "position": {"x": 300, "y": 0}, "data": {}},
                {"id": "sast", "type": "scan.sast", "position": {"x": 300, "y": 150}, "data": {}},
                {
                    "id": "report",
                    "type": "report.build",
                    "position": {"x": 450, "y": 150},
                    "data": {"params": {"formats": ["json"], "include_ai": False}},
                },
            ],
            "edges": [
                {"id": "e1", "source": "t", "target": "src"},
                {"id": "e2", "source": "src", "target": "secret"},
                {"id": "e3", "source": "src", "target": "sast"},
                {"id": "e4", "source": "sast", "target": "report"},
            ],
        }
        created = self.client.post("/api/workflows", json={"name": "scope", "graph": graph}).get_json()
        run = self.client.post(
            f"/api/workflows/{created['id']}/runs", json={"wait": True, "target": {"kind": "default"}}
        ).get_json()
        self.assertEqual(run["status"], "success")
        self.assertEqual(run["summary"]["findings"]["total"], 10)
        report = self.client.get(f"/api/runs/{run['id']}/report?format=json").get_json()
        self.assertEqual({item["category"] for item in report["findings"]}, {"SAST"})
        self.assertEqual(len(report["findings"]), 5)
