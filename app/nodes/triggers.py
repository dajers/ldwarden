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
    description = "Запускает сценарий один раз в выбранную дату/время или регулярно по дню недели и времени."
    icon = "⏰"
    color = "#0ea5e9"
    inputs: list[HandleSpec] = []
    outputs = [HandleSpec("out", "Запуск")]
    params = [
        ParamSpec(
            "enabled",
            "boolean",
            "Включено",
            "Выключенное расписание не запускается",
            default=True,
        ),
        ParamSpec(
            "mode",
            "select",
            "Режим",
            "Один раз в конкретную дату или регулярно по дням",
            default="weekly",
            options=["weekly", "once"],
        ),
        ParamSpec(
            "run_date",
            "date",
            "Дата",
            "Для режима «Один раз»: YYYY-MM-DD",
            default="",
            depends_on={"mode": "once"},
        ),
        ParamSpec(
            "run_time",
            "time",
            "Время",
            "Локальное время запуска, HH:MM",
            default="09:00",
        ),
        ParamSpec(
            "weekday",
            "select",
            "День недели",
            "По умолчанию каждый день; выберите день, если нужно иначе",
            default="*",
            options=["*", "1", "2", "3", "4", "5", "6", "7"],
            depends_on={"mode": "weekly"},
        ),
        ParamSpec(
            "timezone",
            "string",
            "Часовой пояс",
            "IANA-таймзона для расчёта расписания",
            default="Europe/Moscow",
            options=["UTC", "Europe/Moscow", "Europe/Berlin", "Asia/Almaty", "Asia/Yekaterinburg"],
        ),
        ParamSpec(
            "cron",
            "string",
            "Cron (устаревшее)",
            "Оставлено для старых сценариев: 5 полей cron",
            default="",
            placeholder="0 14 * * *",
        ),
    ]
    tags = ["trigger", "schedule", "daily", "weekly"]

    def execute(self, ctx, params: dict) -> NodeResult:
        mode = params.get("mode") or "weekly"
        when = params.get("run_time") or "09:00"
        if mode == "once":
            when = f"{params.get('run_date') or '—'} {when}"
        else:
            weekday = params.get("weekday") or "*"
            when = f"{'каждый день' if weekday == '*' else 'день ' + str(weekday)} {when}"
        ctx.emit(
            "trigger.fired",
            f"Запуск по расписанию: {when} ({params.get('timezone')})",
            node_id=ctx.node_id,
        )
        return NodeResult(
            outputs={
                "triggered_at": _now(),
                "type": "schedule",
                "mode": mode,
                "run_date": params.get("run_date"),
                "run_time": params.get("run_time"),
                "weekday": params.get("weekday"),
                "cron": params.get("cron"),
                "timezone": params.get("timezone"),
            },
            active_handles=["out"],
            message=f"Расписание: {when}",
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
