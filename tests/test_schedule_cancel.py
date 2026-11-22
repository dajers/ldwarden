from __future__ import annotations

import json
import unittest

from app.db import WorkflowRow, close_db
from tests.helpers import make_app


class ScheduleCancelTests(unittest.TestCase):
    def setUp(self):
        self.app, self.settings = make_app(llm_provider="fake", seed_templates=False)
        self.client = self.app.test_client()

    def tearDown(self):
        close_db()

    def test_cancel_scheduled_process_disables_it(self):
        graph = {
            "nodes": [
                {
                    "id": "schedule",
                    "type": "trigger.schedule",
                    "position": {"x": 0, "y": 0},
                    "data": {
                        "params": {
                            "enabled": True,
                            "mode": "weekly",
                            "run_time": "09:00",
                            "weekday": "1",
                            "timezone": "UTC",
                        }
                    },
                }
            ],
            "edges": [],
        }
        created = self.client.post("/api/workflows", json={"name": "schedule", "graph": graph}).get_json()
        schedules = self.client.get("/api/schedules").get_json()
        self.assertEqual(schedules["count"], 1)
        response = self.client.post(
            "/api/schedules/cancel",
            json={"workflow_id": created["id"], "node_id": "schedule"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.get_json()["cancelled"])
        self.assertEqual(self.client.get("/api/schedules").get_json()["count"], 0)
        row = WorkflowRow.get_by_id(created["id"])
        node = json.loads(row.graph)["nodes"][0]
        self.assertFalse(node["data"]["params"]["enabled"])
