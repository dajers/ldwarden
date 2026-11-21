from __future__ import annotations

import hashlib
import hmac
import json
import re
from dataclasses import dataclass, field
from ipaddress import ip_address
from urllib.parse import urlparse, urlunparse

from app.config import Settings
from app.services.telegram_format import split_markdown, to_telegram_markdown
from app.db import InboxMessageRow, j_dumps

SENSITIVE_HEADERS = {"authorization", "x-api-key", "cookie", "proxy-authorization"}


@dataclass
class NotificationResult:
    status: str
    channel: str
    target: str = ""
    message: str = ""
    details: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "status": self.status,
            "channel": self.channel,
            "target": self.target,
            "message": self.message,
            "details": self.details,
        }


def _safe_error(exc: Exception, secrets: list[str]) -> str:
    text = str(exc)
    for secret in secrets:
        if secret and len(secret) >= 4:
            text = text.replace(secret, "***")

    text = re.sub(r"//[^/@\s]+@", "//***@", text)
    return text[:500]


def _safe_target(url: str) -> str:
    if not url or url.startswith("local://"):
        return url
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        return url
    host = parsed.hostname or ""
    if parsed.port:
        host = f"{host}:{parsed.port}"
    return urlunparse((parsed.scheme, host, parsed.path, "", "", ""))


class NotificationService:
    def __init__(self, settings: Settings):
        self.settings = settings

    def send(
        self,
        channel: str,
        params: dict,
        *,
        body: str,
        subject: str,
        run_id: str | None = None,
        html_report: str | None = None,
        caption: str | None = None,
    ) -> NotificationResult:
        channel = (channel or "webhook").lower()
        if channel == "webhook":
            return self._webhook(params, body, subject, run_id)
        if channel == "telegram":
            return self._telegram(
                params, body, run_id, html_report=html_report, caption=caption
            )
        return NotificationResult("error", channel, message=f"Неизвестный канал: {channel}")


    def _webhook(self, params: dict, body: str, subject: str, run_id: str | None) -> NotificationResult:
        url = str(params.get("url") or "").strip()
        method = str(params.get("method") or "POST").upper()
        dry_run = bool(params.get("dry_run"))
        if not url:
            return NotificationResult("skipped", "webhook", message="URL вебхука не задан")
        safe_url = _safe_target(url)
        if dry_run:
            self._store_inbox(run_id, "webhook", safe_url, subject, body, {}, "dry_run")
            return NotificationResult("skipped", "webhook", safe_url, "Dry-run: доставка не выполнялась")
        if url.startswith("local://"):
            self._store_inbox(run_id, "webhook", safe_url, subject, body, {}, "received")
            return NotificationResult(
                "sent",
                "webhook",
                safe_url,
                "Доставлено в локальный демонстрационный inbox",
                {"inbox": "/api/dev/inbox"},
            )
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return NotificationResult("error", "webhook", safe_url, "Разрешены только http(s):// или local://")
        if self._is_blocked_host(parsed.hostname):
            return NotificationResult("error", "webhook", safe_url, "Хост вебхука запрещён политикой безопасности")
        headers = {}
        raw_headers = params.get("headers")
        if isinstance(raw_headers, dict):
            headers = {str(k): str(v) for k, v in raw_headers.items()}
        headers.setdefault("Content-Type", "application/json")
        payload = {
            "run_id": run_id,
            "subject": subject,
            "text": body,
            "source": "LDWarden",
        }
        secret = str(params.get("secret") or "")
        raw_body = json.dumps(payload, ensure_ascii=False)
        if secret:
            signature = hmac.new(secret.encode(), raw_body.encode(), hashlib.sha256).hexdigest()
            headers["X-LDWarden-Signature"] = f"sha256={signature}"
        try:
            import httpx

            timeout = float(params.get("timeout") or 20)
            with httpx.Client(timeout=timeout, follow_redirects=False) as client:
                response = client.request(method, url, content=raw_body, headers=headers)
                response.raise_for_status()
            self._store_inbox(run_id, "webhook", safe_url, subject, body, headers, "sent")
            return NotificationResult(
                "sent",
                "webhook",
                safe_url,
                f"HTTP {response.status_code}",
                {"status_code": response.status_code},
            )
        except Exception as exc:
            self._store_inbox(run_id, "webhook", safe_url, subject, body, headers, "error")
            return NotificationResult(
                "error",
                "webhook",
                safe_url,
                f"Ошибка доставки: {_safe_error(exc, [secret])}",
            )


    def _telegram(
        self,
        params: dict,
        body: str,
        run_id: str | None,
        html_report: str | None = None,
        caption: str | None = None,
    ) -> NotificationResult:
        token = str(params.get("bot_token") or "")
        chat_id = str(params.get("chat_id") or "")
        dry_run = bool(params.get("dry_run"))
        target = f"chat:{chat_id}" if chat_id else "telegram"
        if dry_run:
            self._store_inbox(run_id, "telegram", target, "Telegram", body, {}, "dry_run")
            return NotificationResult("skipped", "telegram", target, "Dry-run: сообщение не отправлено")
        if not token or not chat_id:
            return NotificationResult("skipped", "telegram", target, "Не заданы bot_token/chat_id")
        try:
            import httpx

            if html_report:
                url = f"https://api.telegram.org/bot{token}/sendDocument"
                files = {
                    "document": (
                        "ldwarden-report.html",
                        html_report.encode("utf-8"),
                        "text/html",
                    )
                }
                data = {
                    "chat_id": chat_id,
                    "caption": (caption or "LDWarden: отчёт о проверке")[:1024],
                }
                with httpx.Client(timeout=60) as client:
                    response = client.post(url, data=data, files=files)
                    response.raise_for_status()
                size_kb = max(1, round(len(html_report.encode("utf-8")) / 1024))
                self._store_inbox(run_id, "telegram", target, "Telegram", body, {}, "sent")
                return NotificationResult(
                    "sent",
                    "telegram",
                    target,
                    f"HTML-отчёт отправлен файлом ({size_kb} КБ)",
                    {"status_code": response.status_code, "file": "ldwarden-report.html"},
                )

            url = f"https://api.telegram.org/bot{token}/sendMessage"
            chunks = split_markdown(body, 3000)
            last_status = 0
            with httpx.Client(timeout=30) as client:
                for chunk in chunks:
                    formatted = to_telegram_markdown(chunk)
                    if len(formatted) > 4000:
                        payload = {
                            "chat_id": chat_id,
                            "text": chunk,
                            "disable_web_page_preview": True,
                        }
                    else:
                        payload = {
                            "chat_id": chat_id,
                            "text": formatted,
                            "parse_mode": "MarkdownV2",
                            "disable_web_page_preview": True,
                        }
                    response = client.post(url, json=payload)
                    if response.status_code == 400 and "parse" in str(response.text).lower():
                        payload.pop("parse_mode", None)
                        payload["text"] = chunk
                        response = client.post(url, json=payload)
                    last_status = response.status_code
                    response.raise_for_status()
            self._store_inbox(run_id, "telegram", target, "Telegram", body, {}, "sent")
            return NotificationResult(
                "sent", "telegram", target, f"Отправлено частей: {len(chunks)}", {"status_code": last_status}
            )
        except Exception as exc:
            self._store_inbox(run_id, "telegram", target, "Telegram", body, {}, "error")
            return NotificationResult(
                "error", "telegram", target, f"Ошибка Telegram: {_safe_error(exc, [token])}"
            )

    def _is_blocked_host(self, hostname: str) -> bool:
        lowered = hostname.lower()
        if lowered in {"metadata.google.internal", "metadata", "169.254.169.254"}:
            return True
        try:
            address = ip_address(lowered)
        except ValueError:
            address = None
        if address is not None:
            if address.is_link_local or address.is_multicast or address.is_unspecified:
                return True
            if (address.is_loopback or address.is_private) and not self.settings.allow_local_webhooks:
                return True
        if lowered in {"localhost", "127.0.0.1", "::1"} and not self.settings.allow_local_webhooks:
            return True
        return False

    def _store_inbox(
        self,
        run_id: str | None,
        channel: str,
        target: str,
        subject: str,
        body: str,
        headers: dict,
        status: str,
    ) -> None:
        safe_headers = {
            key: ("***" if key.lower() in SENSITIVE_HEADERS else value)
            for key, value in (headers or {}).items()
        }
        try:
            InboxMessageRow.create(
                run_id=run_id,
                channel=channel,
                target=target[:500],
                subject=subject[:300],
                body=body[:200_000],
                headers=j_dumps(safe_headers),
                status=status,
            )
        except Exception:

            pass


