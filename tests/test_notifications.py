from __future__ import annotations

import unittest
from unittest.mock import patch

from app.config import load_settings
from app.services.notifications import NotificationService


class FakeResponse:
    def __init__(self, status_code: int = 200, error: Exception | None = None):
        self.status_code = status_code
        self._error = error

    def raise_for_status(self):
        if self._error is not None:
            raise self._error


class FakeClient:
    calls: list[tuple[str, dict]] = []

    def __init__(self, *args, **kwargs):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def post(self, url, json):
        FakeClient.calls.append((url, json))
        return FakeResponse()


class TelegramTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.settings = load_settings({"seed_templates": False})
        cls.service = NotificationService(cls.settings)

    def setUp(self):
        FakeClient.calls = []
        self.inbox_patch = patch.object(self.service, "_store_inbox")
        self.inbox_patch.start()
        self.addCleanup(self.inbox_patch.stop)

    def test_dry_run_does_not_call_api(self):
        result = self.service._telegram(
            {"bot_token": "123:ABC", "chat_id": "42", "dry_run": True}, "report", None
        )
        self.assertEqual(result.status, "skipped")
        self.assertEqual(FakeClient.calls, [])

    def test_missing_credentials_skipped(self):
        result = self.service._telegram({}, "report", None)
        self.assertEqual(result.status, "skipped")
        self.assertIn("bot_token", result.message)

    def test_sends_report_and_chunks_long_text(self):
        token = "123456:telegram-secret-token"
        body = "x" * 5000
        with patch("httpx.Client", FakeClient):
            result = self.service._telegram(
                {"bot_token": token, "chat_id": "42"}, body, "run-1"
            )
        self.assertEqual(result.status, "sent")
        self.assertEqual(result.target, "chat:42")
        self.assertEqual(len(FakeClient.calls), 2)
        self.assertTrue(all("sendMessage" in url for url, _payload in FakeClient.calls))
        self.assertTrue(all(len(payload["text"]) <= 3900 for _, payload in FakeClient.calls))
        self.assertTrue(all(payload["chat_id"] == "42" for _, payload in FakeClient.calls))
        self.assertNotIn(token, result.message)

    def test_token_is_not_leaked_in_error(self):
        token = "123456:telegram-secret-token"
        error = RuntimeError(f"HTTP error for https://api.telegram.org/bot{token}/sendMessage")
        with patch("httpx.Client", FakeClient), patch.object(
            FakeResponse, "raise_for_status", side_effect=error
        ):
            result = self.service._telegram(
                {"bot_token": token, "chat_id": "42"}, "report", None
            )
        self.assertEqual(result.status, "error")
        self.assertNotIn(token, result.message)


if __name__ == "__main__":
    unittest.main()
