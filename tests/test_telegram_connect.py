from __future__ import annotations

import unittest
from unittest.mock import patch

from app.db import TelegramLinkRow, close_db
from tests.helpers import make_app


class FakeResponse:
    def __init__(self, data: dict, status_code: int = 200):
        self._data = data
        self.status_code = status_code

    def json(self):
        return self._data


class FakeTelegramClient:
    bot_username = "ldw_test_bot"
    updates: list[dict] = []
    conflict = False
    calls: list[tuple[str, dict]] = []

    def __init__(self, *args, **kwargs):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def post(self, url, json):
        FakeTelegramClient.calls.append((url, json))
        if url.endswith("/getMe"):
            return FakeResponse({"ok": True, "result": {"id": 1, "username": self.bot_username}})
        if url.endswith("/getUpdates"):
            if self.conflict:
                return FakeResponse(
                    {
                        "ok": False,
                        "description": "Conflict: can't use getUpdates method while webhook is active",
                    },
                    409,
                )
            return FakeResponse({"ok": True, "result": self.updates})
        return FakeResponse({"ok": False, "description": "unknown method"}, 400)


class TelegramConnectTests(unittest.TestCase):
    def setUp(self):
        self.app, self.settings = make_app(telegram_bot_token="123:ABC")
        self.client = self.app.test_client()
        FakeTelegramClient.updates = []
        FakeTelegramClient.conflict = False
        FakeTelegramClient.calls = []

    def tearDown(self):
        close_db()

    def _connect(self):
        with patch("httpx.Client", FakeTelegramClient):
            response = self.client.post("/api/telegram/connect")
        self.assertEqual(response.status_code, 200)
        return response.get_json()

    def _make_workflow(self):
        graph = {
            "nodes": [
                {"id": "t", "type": "trigger.manual", "position": {"x": 0, "y": 0}, "data": {}},
                {
                    "id": "notify",
                    "type": "notify.send",
                    "position": {"x": 250, "y": 0},
                    "data": {"params": {"channel": "webhook", "url": "local://inbox", "dry_run": True}},
                },
            ],
            "edges": [{"id": "e1", "source": "t", "target": "notify"}],
        }
        response = self.client.post("/api/workflows", json={"name": "Telegram link", "graph": graph})
        self.assertEqual(response.status_code, 201)
        return response.get_json()["id"]

    def test_connect_returns_deep_link(self):
        data = self._connect()
        self.assertEqual(data["bot_username"], "ldw_test_bot")
        self.assertIn("https://t.me/ldw_test_bot?start=", data["connect_url"])
        self.assertIn(data["state"], data["connect_url"])

    def test_poll_finds_chat_after_start(self):
        data = self._connect()
        state = data["state"]
        FakeTelegramClient.updates = [
            {
                "update_id": 10,
                "message": {
                    "text": f"/start {state}",
                    "chat": {"id": 42, "type": "private", "first_name": "Ivan"},
                },
            }
        ]
        with patch("httpx.Client", FakeTelegramClient):
            response = self.client.get(f"/api/telegram/chats?state={state}")
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertFalse(payload["waiting"])
        self.assertEqual(payload["items"][0]["chat_id"], 42)
        self.assertEqual(payload["items"][0]["title"], "Ivan")

    def test_link_updates_workflow_and_notification_uses_chat(self):
        data = self._connect()
        state = data["state"]
        FakeTelegramClient.updates = [
            {
                "update_id": 10,
                "message": {
                    "text": f"/start {state}",
                    "chat": {"id": 42, "type": "private", "first_name": "Ivan"},
                },
            }
        ]
        workflow_id = self._make_workflow()
        with patch("httpx.Client", FakeTelegramClient):
            self.client.get(f"/api/telegram/chats?state={state}")
            response = self.client.post(
                "/api/telegram/link",
                json={"state": state, "chat_id": "42", "workflow_id": workflow_id},
            )
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload["link"]["chat_id"], "42")
        notify = next(
            node
            for node in payload["workflow"]["graph"]["nodes"]
            if node["type"] == "notify.send"
        )
        self.assertEqual(notify["data"]["params"]["channel"], "telegram")
        self.assertEqual(notify["data"]["params"]["chat_id"], "42")
        self.assertIsNotNone(TelegramLinkRow.select().first())

        run = self.client.post(
            f"/api/workflows/{workflow_id}/runs", json={"wait": True}
        ).get_json()
        notification = run["summary"]["notification"]
        self.assertEqual(notification["channel"], "telegram")
        self.assertEqual(notification["target"], "chat:42")
        self.assertEqual(notification["status"], "skipped")

    def test_link_requires_seen_chat(self):
        data = self._connect()
        with patch("httpx.Client", FakeTelegramClient):
            response = self.client.post(
                "/api/telegram/link", json={"state": data["state"], "chat_id": "42"}
            )
        self.assertEqual(response.status_code, 400)

    def test_webhook_conflict_is_reported(self):
        data = self._connect()
        FakeTelegramClient.conflict = True
        with patch("httpx.Client", FakeTelegramClient):
            response = self.client.get(f"/api/telegram/chats?state={data['state']}")
        self.assertEqual(response.status_code, 409)
        self.assertIn("webhook", response.get_json()["error"]["message"].lower())


class TelegramConnectNoTokenTests(unittest.TestCase):
    def setUp(self):
        self.app, _settings = make_app()
        self.client = self.app.test_client()

    def tearDown(self):
        close_db()

    def test_connect_requires_token(self):
        response = self.client.post("/api/telegram/connect")
        self.assertEqual(response.status_code, 400)
        self.assertIn("LDWARDEN_TELEGRAM_BOT_TOKEN", response.get_json()["error"]["message"])


if __name__ == "__main__":
    unittest.main()
