from __future__ import annotations

from datetime import datetime, timezone

from app.core.models import HandleSpec, NodeResult, ParamSpec
from app.core.registry import register_node
from app.nodes.base import BaseNode


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@register_node
class ManualTrigger(BaseNode):
    type = "trigger.manual"
    category = "trigger"
    title = "Ручной запуск"
    description = "Запускает сценарий по кнопке из интерфейса или API."
    icon = "▶️"
    color = "#22c55e"
    inputs: list[HandleSpec] = []
    outputs = [HandleSpec("out", "Запуск")]
    params = [
        ParamSpec(
            "note",
            "string",
            "Комментарий",
            "Необязательная заметка к ручному запуску",
            default="",
            placeholder="Например, проверка перед мержем",
        )
    ]
    tags = ["trigger", "manual"]

    def execute(self, ctx, params: dict) -> NodeResult:
        ctx.emit("trigger.fired", "Ручной запуск", node_id=ctx.node_id)
        return NodeResult(
            outputs={"triggered_at": _now(), "type": "manual", "note": params.get("note", "")},
            active_handles=["out"],
            message="Сценарий запущен вручную",
        )


@register_node
class ScheduleTrigger(BaseNode):
    type = "trigger.schedule"
    category = "trigger"
    title = "Расписание"
    description = "Запускает сценарий по cron-расписанию (5 полей: минуты, часы, день, месяц, день недели)."
    icon = "⏰"
    color = "#0ea5e9"
    inputs: list[HandleSpec] = []
    outputs = [HandleSpec("out", "Запуск")]
    params = [
        ParamSpec(
            "cron",
            "string",
            "Cron-выражение",
            "5 полей: минута час день_месяца месяц день_недели. Например, 0 14 * * *",
            default="0 9 * * 1-5",
            required=True,
            placeholder="0 14 * * *",
        ),
        ParamSpec(
            "timezone",
            "string",
            "Часовой пояс",
            "IANA-таймзона для расчёта расписания",
            default="UTC",
            options=["UTC", "Europe/Moscow", "Europe/Berlin", "Asia/Almaty"],
        ),
    ]
    tags = ["trigger", "schedule", "cron"]

    def execute(self, ctx, params: dict) -> NodeResult:
        ctx.emit(
            "trigger.fired",
            f"Запуск по расписанию {params.get('cron')} ({params.get('timezone')})",
            node_id=ctx.node_id,
        )
        return NodeResult(
            outputs={
                "triggered_at": _now(),
                "type": "schedule",
                "cron": params.get("cron"),
                "timezone": params.get("timezone"),
            },
            active_handles=["out"],
            message=f"Расписание: {params.get('cron')}",
        )


@register_node
class WebhookTrigger(BaseNode):
    type = "trigger.webhook"
    category = "trigger"
    title = "Webhook / CI"
    description = "Запускает сценарий внешним HTTP-запросом: CI/CD, GitHub Actions, GitLab CI или другой сервис."
    icon = "🔗"
    color = "#8b5cf6"
    inputs: list[HandleSpec] = []
    outputs = [HandleSpec("out", "Запуск")]
    params = [
        ParamSpec(
            "secret",
            "secret",
            "Секрет подписи",
            "Если задан, API проверяет HMAC-SHA256 в заголовке X-LDWarden-Signature",
            default="",
            secret=True,
        ),
        ParamSpec(
            "description",
            "text",
            "Описание",
            "Для какой цели вызывается этот сценарий",
            default="",
        ),
    ]
    tags = ["trigger", "webhook", "ci"]

    def execute(self, ctx, params: dict) -> NodeResult:
        payload = ctx.trigger_payload or {}
        ctx.emit(
            "trigger.fired",
            "Запуск через webhook/CI",
            node_id=ctx.node_id,
            payload={"keys": sorted(payload.keys())[:20]},
        )
        return NodeResult(
            outputs={
                "triggered_at": _now(),
                "type": "webhook",
                "payload_keys": sorted(payload.keys())[:20],
            },
            active_handles=["out"],
            message="Сценарий запущен через webhook",
        )
