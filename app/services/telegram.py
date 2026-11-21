from __future__ import annotations

import re
import secrets
import time
from typing import Any

import httpx

from app.config import Settings
from app.db import TelegramLinkRow, WorkflowRow, j_dumps, j_loads, utcnow


class TelegramError(RuntimeError):
    def __init__(self, message: str, status: int = 502):
        super().__init__(message)
        self.status = status


class TelegramService:
    TTL_SECONDS = 15 * 60
    MAX_STATES = 100

    def __init__(self, settings: Settings):
        self.settings = settings
        self._states: dict[str, dict[str, Any]] = {}

    @property
    def token(self) -> str:
        return self.settings.telegram_bot_token

    def connect(self, bot_token: str | None = None) -> dict:
        token = str(bot_token or "").strip() or self.token
        if not token:
            raise TelegramError("Укажите токен бота от @BotFather или задайте LDWARDEN_TELEGRAM_BOT_TOKEN", 400)
        self._cleanup()
        me = self._api("getMe", {}, token=token)
        bot = me.get("result") or {}
        username = str(bot.get("username") or "")
        if not username:
            raise TelegramError("Telegram не вернул username бота", 502)
        state = secrets.token_urlsafe(18)
        self._states[state] = {
            "created_at": time.time(),
            "offset": None,
            "chats": {},
            "bot_username": username,
            "token": token,
        }
        if len(self._states) > self.MAX_STATES:
            oldest = min(self._states, key=lambda key: self._states[key]["created_at"])
            self._states.pop(oldest, None)
        return {
            "state": state,
            "bot_username": username,
            "connect_url": f"https://t.me/{username}?start={state}",
            "expires_in": self.TTL_SECONDS,
            "instructions": (
                "Откройте connect_url, нажмите Start и затем запросите "
                "GET /api/telegram/chats?state=..."
            ),
        }

    def poll(self, state: str) -> dict:
        entry = self._state(state)
        payload: dict[str, Any] = {"timeout": 0, "allowed_updates": ["message"]}
        if entry["offset"] is not None:
            payload["offset"] = entry["offset"]
        data = self._api("getUpdates", payload, token=entry.get("token"))
        updates = data.get("result") or []
        if not isinstance(updates, list):
            updates = []
        max_id = int(entry["offset"] or 0) - 1
        found: dict[str, dict] = {}
        for update in updates:
            try:
                max_id = max(max_id, int(update.get("update_id") or 0))
            except (TypeError, ValueError):
                continue
            message = update.get("message") or update.get("edited_message") or {}
            text = str(message.get("text") or "")
            if not text.startswith("/start"):
                continue
            if state not in text:
                continue
            chat = message.get("chat") or {}
            chat_id = chat.get("id")
            if chat_id is None:
                continue
            key = str(chat_id)
            found[key] = {
                "chat_id": chat_id,
                "type": chat.get("type") or "",
                "title": (
                    chat.get("title")
                    or chat.get("username")
                    or " ".join(
                        part for part in (chat.get("first_name"), chat.get("last_name")) if part
                    )
                    or key
                ),
                "username": chat.get("username") or "",
            }
        if updates:
            entry["offset"] = max_id + 1
        entry["chats"].update(found)
        return {
            "state": state,
            "items": list(entry["chats"].values()),
            "waiting": not bool(entry["chats"]),
            "bot_username": entry["bot_username"],
        }

    def link(
        self,
        state: str,
        chat_id: str | int | None = None,
        workflow_id: str | None = None,
        node_id: str | None = None,
    ) -> dict:
        entry = self._state(state)
        chats = entry["chats"]
        selected: dict | None = None
        if chat_id is not None:
            selected = chats.get(str(chat_id))
            if selected is None:
                raise TelegramError("Чат не найден. Сначала нажмите Start по ссылке connect_url", 400)
        elif len(chats) == 1:
            selected = next(iter(chats.values()))
        elif not chats:
            raise TelegramError("Пока нет подключённых чатов. Нажмите Start по ссылке connect_url", 400)
        else:
            raise TelegramError("Подключено несколько чатов: укажите chat_id", 400)
        TelegramLinkRow.delete().execute()
        row = TelegramLinkRow.create(
            chat_id=str(selected["chat_id"]),
            chat_title=str(selected.get("title") or ""),
            chat_type=str(selected.get("type") or ""),
            username=str(selected.get("username") or ""),
        )
        result: dict[str, Any] = {"link": row.to_dict(), "workflow": None}
        if workflow_id:
            result["workflow"] = self._attach_to_workflow(
                workflow_id, node_id, str(selected["chat_id"])
            )
        return result

    def status(self) -> dict:
        configured = bool(self.token)
        bot: dict | None = None
        online = False
        error = ""
        if configured:
            try:
                me = self._api("getMe", {})
                bot = me.get("result") or {}
                online = True
            except TelegramError as exc:
                error = str(exc)
        linked = TelegramLinkRow.select().order_by(TelegramLinkRow.linked_at.desc()).first()
        return {
            "configured": configured,
            "online": online,
            "bot": bot,
            "linked_chat": linked.to_dict() if linked else None,
            "error": error,
        }

    def unlink(self) -> dict:
        deleted = TelegramLinkRow.delete().execute()
        return {"deleted": int(deleted)}

    def _attach_to_workflow(self, workflow_id: str, node_id: str | None, chat_id: str) -> dict:
        row = WorkflowRow.get_or_none(WorkflowRow.id == workflow_id)
        if row is None:
            raise TelegramError("Workflow не найден", 404)
        if row.is_template or row.published:
            raise TelegramError("Это шаблон: сделайте копию и подключите чат к копии", 409)
        graph = j_loads(row.graph, {"nodes": [], "edges": []})
        target = None
        for node in graph.get("nodes", []):
            if node.get("type") not in {"notify.telegram", "notify.send"}:
                continue
            if node_id and node.get("id") != node_id:
                continue
            target = node
            break
        if target is None:
            raise TelegramError("В workflow нет ноды Telegram", 400)
        data = target.setdefault("data", {})
        params = data.get("params") if isinstance(data.get("params"), dict) else {}
        if target.get("type") == "notify.send":
            params["channel"] = "telegram"
        params["chat_id"] = chat_id
        data["params"] = params
        row.graph = j_dumps(graph)
        row.version = int(row.version or 1) + 1
        row.updated_at = utcnow()
        row.save()
        return row.to_dict()

    def _state(self, state: str) -> dict:
        entry = self._states.get(state)
        if entry is None:
            raise TelegramError("Сессия подключения не найдена. Начните заново", 404)
        if time.time() - entry["created_at"] > self.TTL_SECONDS:
            self._states.pop(state, None)
            raise TelegramError("Сессия подключения истекла. Начните заново", 410)
        return entry

    def _cleanup(self) -> None:
        now = time.time()
        expired = [
            state
            for state, entry in self._states.items()
            if now - entry["created_at"] > self.TTL_SECONDS
        ]
        for state in expired:
            self._states.pop(state, None)

    def _api(self, method: str, payload: dict, token: str | None = None) -> dict:
        active = str(token or "").strip() or self.token
        if not active:
            raise TelegramError("Укажите токен бота от @BotFather или задайте LDWARDEN_TELEGRAM_BOT_TOKEN", 400)
        url = f"https://api.telegram.org/bot{active}/{method}"
        try:
            with httpx.Client(timeout=20) as client:
                response = client.post(url, json=payload)
            data = response.json()
        except Exception as exc:
            raise TelegramError(f"Ошибка Telegram API: {self._safe_error(exc, active)}", 502) from exc
        if not isinstance(data, dict) or not data.get("ok"):
            description = str((data or {}).get("description") or "Telegram API error")
            lower = description.lower()
            if "webhook" in lower or "conflict" in lower:
                raise TelegramError(
                    "У бота установлен webhook, getUpdates недоступен. Удалите webhook или используйте его",
                    409,
                )
            if response.status_code == 401 or "unauthorized" in lower:
                raise TelegramError("Неверный bot_token", 401)
            raise TelegramError(f"Telegram API: {description}", 502)
        return data

    def _safe_error(self, exc: Exception, token: str | None = None) -> str:
        text = str(exc)
        for secret in filter(None, [token, self.token]):
            text = text.replace(secret, "***")
        text = re.sub(r"//[^/@\s]+@", "//***@", text)
        return text[:500]
