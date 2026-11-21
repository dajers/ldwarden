from __future__ import annotations

import unittest

from app.db import close_db
from unittest.mock import patch

from tests.helpers import make_app


class SeparateNotifyNodesTests(unittest.TestCase):
    def setUp(self):
        self.app, self.settings = make_app()
        self.client = self.app.test_client()

    def tearDown(self):
        close_db()

    def _run(self, node_type: str, params: dict):
        graph = {
            "nodes": [
                {"id": "t", "type": "trigger.manual", "position": {"x": 0, "y": 0}, "data": {}},
                {
                    "id": "n",
                    "type": node_type,
                    "position": {"x": 250, "y": 0},
                    "data": {"params": params},
                },
            ],
            "edges": [{"id": "e1", "source": "t", "target": "n"}],
        }
        created = self.client.post("/api/workflows", json={"name": node_type, "graph": graph})
        self.assertEqual(created.status_code, 201, created.get_json())
        run = self.client.post(
            f"/api/workflows/{created.get_json()['id']}/runs", json={"wait": True}
        ).get_json()
        self.assertEqual(run["status"], "success")
        return run["summary"]["notification"]

    def test_telegram_attaches_html_report(self):
        sent: dict = {}

        class DocumentClient:
            def __init__(self, *args, **kwargs):
                pass

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def post(self, url, data=None, files=None, json=None):
                sent["url"] = url
                sent["data"] = data or {}
                sent["files"] = files or {}
                return type("Response", (), {"status_code": 200, "raise_for_status": lambda self: None})()

        with patch("httpx.Client", DocumentClient):
            notification = self._run(
                "notify.telegram",
                {"bot_token": "123:ABC", "chat_id": "42", "attach_report": True},
            )
        self.assertEqual(notification["status"], "sent")
        self.assertIn("sendDocument", sent["url"])
        name, content, mime = sent["files"]["document"]
        self.assertEqual(name, "ldwarden-report.html")
        self.assertEqual(mime, "text/html")
        self.assertIn(b"<!doctype html>", content)
        self.assertIn("находок", sent["data"]["caption"])

    def test_telegram_dry_run(self):
        notification = self._run(
            "notify.telegram", {"bot_token": "123:secret", "chat_id": "42", "dry_run": True}
        )
        self.assertEqual(notification["channel"], "telegram")
        self.assertEqual(notification["status"], "skipped")

    def test_webhook_dry_run(self):
        notification = self._run("notify.webhook", {"url": "local://inbox", "dry_run": True})
        self.assertEqual(notification["channel"], "webhook")
        self.assertEqual(notification["status"], "skipped")
