from __future__ import annotations

import unittest
from unittest.mock import patch

from app.config import load_settings
from app.services.notifications import NotificationService
from app.services.telegram import TelegramError, TelegramService


class FakeResponse:
    def __init__(self, status_code: int = 200, error: Exception | None = None, text: str = ""):
        self.status_code = status_code
        self._error = error
        self.text = text

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

    def test_sends_markdown_v2(self):
        service = self.service
        sent: list[dict] = []

        class CaptureClient:
            def __init__(self, *args, **kwargs):
                pass

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def post(self, url, json):
                sent.append(json)
                return FakeResponse()

        with patch("httpx.Client", CaptureClient):
            result = service._telegram(
                {"bot_token": "123:ABC", "chat_id": "42"},
                "# Отчёт\n\n**Итог**\n\n- пункт",
                "run-1",
            )
        self.assertEqual(result.status, "sent")
        self.assertEqual(sent[0]["parse_mode"], "MarkdownV2")
        self.assertIn("*Отчёт*", sent[0]["text"])
        self.assertIn("*Итог*", sent[0]["text"])
        self.assertIn("• пункт", sent[0]["text"])

    def test_falls_back_to_plain_text_on_parse_error(self):
        service = self.service
        sent: list[dict] = []

        class FlakyClient:
            def __init__(self, *args, **kwargs):
                pass

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def post(self, url, json):
                sent.append(dict(json))
                if len(sent) == 1:
                    return FakeResponse(400, text="Bad Request: can't parse entities")
                return FakeResponse()

        with patch("httpx.Client", FlakyClient):
            result = service._telegram(
                {"bot_token": "123:ABC", "chat_id": "42"}, "# Отчёт", "run-1"
            )
        self.assertEqual(result.status, "sent")
        self.assertNotIn("parse_mode", sent[1])
        self.assertEqual(sent[1]["text"], "# Отчёт")

    def test_sends_html_report_as_document(self):
        sent: list[dict] = []

        class DocumentClient:
            def __init__(self, *args, **kwargs):
                pass

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def post(self, url, data=None, files=None, json=None):
                sent.append({"url": url, "data": data or {}, "files": files or {}})
                return FakeResponse()

        with patch("httpx.Client", DocumentClient):
            result = self.service._telegram(
                {"bot_token": "123:ABC", "chat_id": "42"},
                "текст отчёта",
                "run-1",
                html_report="<!doctype html><h1>Отчёт</h1>",
                caption="LDWarden: success · находок 5",
            )
        self.assertEqual(result.status, "sent")
        self.assertIn("sendDocument", sent[0]["url"])
        self.assertEqual(sent[0]["data"]["caption"], "LDWarden: success · находок 5")
        name, content, mime = sent[0]["files"]["document"]
        self.assertEqual(name, "ldwarden-report.html")
        self.assertEqual(mime, "text/html")
        self.assertIn(b"<!doctype html>", content)

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


class TelegramConnectTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.settings = load_settings({"seed_templates": False})

    def test_connect_uses_node_token(self):
        service = TelegramService(self.settings)
        calls = []

        def fake_api(method, payload, token=None):
            calls.append((method, token))
            return {"ok": True, "result": {"username": "demo_bot", "id": 1}}

        with patch.object(service, "_api", side_effect=fake_api):
            session = service.connect(bot_token="123:ABC")
        self.assertEqual(calls, [("getMe", "123:ABC")])
        self.assertEqual(session["bot_username"], "demo_bot")
        self.assertIn("t.me/demo_bot", session["connect_url"])

    def test_poll_uses_session_token(self):
        service = TelegramService(self.settings)
        seen = []

        def fake_api(method, payload, token=None):
            seen.append((method, token))
            result = {"username": "demo_bot"} if method == "getMe" else []
            return {"ok": True, "result": result}

        with patch.object(service, "_api", side_effect=fake_api):
            session = service.connect(bot_token="123:ABC")
            service.poll(session["state"])
        self.assertEqual(seen[1], ("getUpdates", "123:ABC"))

    def test_connect_without_token_raises(self):
        settings = load_settings({"seed_templates": False})
        settings.telegram_bot_token = ""
        with self.assertRaises(TelegramError):
            TelegramService(settings).connect()


if __name__ == "__main__":
    unittest.main()
