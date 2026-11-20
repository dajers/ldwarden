from __future__ import annotations

import unittest

from app.core.models import Finding, NodeResult
from tests.helpers import make_app
from app.db import close_db


def _condition_graph() -> dict:
    return {
        "nodes": [
            {"id": "t", "type": "trigger.manual", "position": {"x": 0, "y": 0}, "data": {}},
            {"id": "scan", "type": "scan.secrets", "position": {"x": 250, "y": 0}, "data": {}},
            {
                "id": "cond",
                "type": "logic.if",
                "position": {"x": 500, "y": 0},
                "data": {"params": {"field": "findings.total", "operator": "gt", "value": "0"}},
            },
            {"id": "report", "type": "report.build", "position": {"x": 750, "y": -100}, "data": {}},
            {
                "id": "notify",
                "type": "notify.send",
                "position": {"x": 750, "y": 100},
                "data": {"params": {"channel": "webhook", "url": "local://inbox"}},
            },
        ],
        "edges": [
            {"id": "e1", "source": "t", "target": "scan"},
            {"id": "e2", "source": "scan", "target": "cond"},
            {"id": "e3", "source": "cond", "target": "report", "sourceHandle": "true"},
            {"id": "e4", "source": "cond", "target": "notify", "sourceHandle": "false"},
        ],
    }


class EngineTests(unittest.TestCase):
    def setUp(self):
        self.app, self.settings = make_app()
        self.client = self.app.test_client()

    def tearDown(self):
        close_db()

    def test_condition_skips_other_branch(self):
        created = self.client.post(
            "/api/workflows", json={"name": "Condition", "graph": _condition_graph()}
        ).get_json()
        run = self.client.post(
            f"/api/workflows/{created['id']}/runs", json={"wait": True}
        ).get_json()
        self.assertEqual(run["status"], "success")
        nodes = run["summary"]["nodes"]
        self.assertEqual(nodes["report"]["status"], "success")
        self.assertEqual(nodes["notify"]["status"], "skipped")
        self.assertEqual(nodes["cond"]["active_handles"], ["true"])

    def test_disabled_node_is_skipped(self):
        graph = {
            "nodes": [
                {"id": "t", "type": "trigger.manual", "position": {"x": 0, "y": 0}, "data": {}},
                {
                    "id": "n",
                    "type": "notify.send",
                    "position": {"x": 250, "y": 0},
                    "data": {"disabled": True, "params": {"channel": "webhook", "url": "local://inbox"}},
                },
            ],
            "edges": [{"id": "e1", "source": "t", "target": "n"}],
        }
        created = self.client.post("/api/workflows", json={"name": "Disabled", "graph": graph}).get_json()
        run = self.client.post(f"/api/workflows/{created['id']}/runs", json={"wait": True}).get_json()
        self.assertEqual(run["status"], "success")
        self.assertEqual(run["summary"]["nodes"]["n"]["status"], "skipped")

    def test_gate_blocks_run(self):
        graph = {
            "nodes": [
                {"id": "t", "type": "trigger.manual", "position": {"x": 0, "y": 0}, "data": {}},
                {"id": "scan", "type": "scan.sca", "position": {"x": 250, "y": 0}, "data": {}},
                {
                    "id": "gate",
                    "type": "control.severity_gate",
                    "position": {"x": 500, "y": 0},
                    "data": {"params": {"threshold": "HIGH", "blocking": True}},
                },
                {"id": "r", "type": "report.build", "position": {"x": 750, "y": 0}, "data": {}},
            ],
            "edges": [
                {"id": "e1", "source": "t", "target": "scan"},
                {"id": "e2", "source": "scan", "target": "gate"},
                {"id": "e3", "source": "gate", "target": "r", "sourceHandle": "pass"},
                {"id": "e4", "source": "gate", "target": "r", "sourceHandle": "fail"},
            ],
        }
        created = self.client.post("/api/workflows", json={"name": "Gate", "graph": graph}).get_json()
        run = self.client.post(f"/api/workflows/{created['id']}/runs", json={"wait": True}).get_json()
        self.assertEqual(run["status"], "failed")
        self.assertFalse(run["gate"]["passed"])
        self.assertEqual(run["summary"]["nodes"]["r"]["status"], "success")

    def test_logic_helpers(self):
        from app.nodes.logic import evaluate, resolve_field

        context = {"findings": {"total": 3, "CRITICAL": 1}}
        self.assertEqual(resolve_field(context, "findings.CRITICAL"), 1)
        self.assertEqual(resolve_field(context, "findings.critical"), 1)
        self.assertTrue(evaluate(3, "gt", "1"))
        self.assertTrue(evaluate("abc", "regex", "^a"))
        self.assertTrue(evaluate(["x", "y"], "contains", "y"))


if __name__ == "__main__":
    unittest.main()
