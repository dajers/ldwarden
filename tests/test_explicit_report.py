from __future__ import annotations

import unittest

from app.db import close_db
from tests.helpers import make_app


class ExplicitReportTests(unittest.TestCase):
    def setUp(self):
        self.app, self.settings = make_app(llm_provider="fake", seed_templates=False)
        self.client = self.app.test_client()

    def tearDown(self):
        close_db()

    def test_notification_without_report_node_does_not_create_report(self):
        graph = {
            "nodes": [
                {"id": "t", "type": "trigger.manual", "position": {"x": 0, "y": 0}, "data": {}},
                {
                    "id": "n",
                    "type": "notify.webhook",
                    "position": {"x": 250, "y": 0},
                    "data": {"params": {"url": "local://inbox"}},
                },
            ],
            "edges": [{"id": "e1", "source": "t", "target": "n"}],
        }
        created = self.client.post("/api/workflows", json={"name": "no report", "graph": graph}).get_json()
        run = self.client.post(f"/api/workflows/{created['id']}/runs", json={"wait": True}).get_json()
        self.assertEqual(run["status"], "success")
        self.assertEqual(run["summary"]["notification"]["status"], "sent")
        self.assertEqual(self.client.get(f"/api/runs/{run['id']}/report?format=md").status_code, 404)
        self.assertEqual(self.client.get(f"/api/runs/{run['id']}/report?format=html").status_code, 404)
