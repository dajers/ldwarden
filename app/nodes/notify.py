from __future__ import annotations

from app.core.models import HandleSpec, NodeResult, ParamSpec, severity_counts
from app.db import TelegramLinkRow
from app.core.registry import register_node
from app.nodes.base import BaseNode, NodeError
from app.services.notifications import NotificationService


@register_node
class NotifyNode(BaseNode):
    type = "notify.send"
    category = "notification"
    title = "Уведомление"
    description = (
        "Отправляет итоговый отчёт в один канал на выбор: HTTP webhook, Telegram или SMTP. "
        "Для демо поддерживается local://inbox."
    )
    icon = "📣"
    color = "#eab308"
    outputs = [HandleSpec("out", "Отправлено")]
    params = [
        ParamSpec(
            "channel",
            "select",
            "Канал",
            "Один канал на выбор",
            default="webhook",
            required=True,
            options=[
                {"value": "webhook", "label": "HTTP webhook"},
                {"value": "telegram", "label": "Telegram"},
                {"value": "smtp", "label": "SMTP (email)"},
            ],
        ),
        ParamSpec(
            "url",
            "string",
            "URL webhook",
            "http(s)://... или local://inbox для демонстрации",
            default="local://inbox",
            depends_on={"channel": "webhook"},
        ),
        ParamSpec(
            "method",
            "select",
            "HTTP-метод",
            "",
            default="POST",
            options=["POST", "PUT"],
            depends_on={"channel": "webhook"},
        ),
        ParamSpec(
            "secret",
            "secret",
            "Секрет HMAC",
            "Если задан, добавляется заголовок X-LDWarden-Signature",
            default="",
            secret=True,
            depends_on={"channel": "webhook"},
        ),
        ParamSpec(
            "headers",
            "keyvalue",
            "Доп. заголовки",
            "Объект ключ-значение",
            default={},
            depends_on={"channel": "webhook"},
        ),
        ParamSpec(
            "bot_token",
            "secret",
            "Токен бота",
            "Telegram Bot API token",
            default="",
            secret=True,
            depends_on={"channel": "telegram"},
        ),
        ParamSpec(
            "chat_id",
            "string",
            "Chat ID или @канал",
            "Числовой ID личного чата/группы или @username публичного канала, куда добавлен бот",
            default="",
            depends_on={"channel": "telegram"},
        ),
        ParamSpec("host", "string", "SMTP хост", "", default="", depends_on={"channel": "smtp"}),
        ParamSpec("port", "number", "SMTP порт", "", default=587, depends_on={"channel": "smtp"}),
        ParamSpec("username", "string", "SMTP логин", "", default="", depends_on={"channel": "smtp"}),
        ParamSpec(
            "password",
            "secret",
            "SMTP пароль",
            "",
            default="",
            secret=True,
            depends_on={"channel": "smtp"},
        ),
        ParamSpec("use_tls", "boolean", "STARTTLS", "", default=True, depends_on={"channel": "smtp"}),
        ParamSpec("use_ssl", "boolean", "SMTPS", "", default=False, depends_on={"channel": "smtp"}),
        ParamSpec("from_addr", "string", "От кого", "", default="", depends_on={"channel": "smtp"}),
        ParamSpec("to_addr", "string", "Кому", "", default="", depends_on={"channel": "smtp"}),
        ParamSpec("subject", "string", "Тема", "Тема письма/сообщения", default="LDWarden: отчёт о проверке"),
        ParamSpec("attach_report", "boolean", "Приложить отчёт", "Markdown-отчёт целиком", default=True),
        ParamSpec(
            "message_template",
            "text",
            "Шаблон сообщения",
            "Необязательно. Доступны {workflow}, {status}, {summary}, {critical}, {high}",
            default="",
        ),
        ParamSpec(
            "dry_run",
            "boolean",
            "Dry-run",
            "Не отправлять наружу, только записать в журнал",
            default=False,
        ),
        ParamSpec(
            "fail_on_error",
            "boolean",
            "Ошибка доставки валит run",
            "Для CI, где уведомление обязательно",
            default=False,
        ),
    ]
    tags = ["notification", "webhook", "telegram", "smtp"]
    docs = (
        "Токены и пароли шифруются в БД и маскируются в API. Для демонстрации webhook "
        "используйте local://inbox — сообщение появится в GET /api/dev/inbox."
    )

    def execute(self, ctx, params: dict) -> NodeResult:
        counts = severity_counts(ctx.findings)
        workflow_name = (ctx.workflow or {}).get("name") or "LDWarden"
        subject = params.get("subject") or "LDWarden: отчёт о проверке"
        subject = subject.replace("{workflow}", workflow_name)
        body = self._build_body(ctx, params, counts, workflow_name)
        channel = params.get("channel", "webhook")
        if channel == "telegram":
            if not params.get("bot_token") and ctx.settings.telegram_bot_token:
                params["bot_token"] = ctx.settings.telegram_bot_token
                ctx.secret_values.append(params["bot_token"])
            if not params.get("chat_id"):
                try:
                    linked = TelegramLinkRow.select().order_by(TelegramLinkRow.linked_at.desc()).first()
                    if linked:
                        params["chat_id"] = linked.chat_id
                except Exception:
                    pass
            if not params.get("chat_id") and ctx.settings.telegram_chat_id:
                params["chat_id"] = ctx.settings.telegram_chat_id
        service = NotificationService(ctx.settings)
        result = service.send(
            channel,
            params,
            body=body,
            subject=subject,
            run_id=ctx.run_id,
        )
        ctx.vars["notification"] = result.to_dict()
        level = "error" if result.status == "error" else ("warning" if result.status == "skipped" else "info")
        ctx.emit(
            "notification.sent" if result.status == "sent" else "notification.skipped",
            f"Уведомление ({channel}): {result.status} — {result.message}",
            node_id=ctx.node_id,
            level=level,
            payload=result.to_dict(),
        )
        if result.status == "error" and params.get("fail_on_error"):
            raise NodeError(f"Не удалось отправить уведомление: {result.message}")
        return NodeResult(
            outputs=result.to_dict(),
            message=result.message or f"Канал {channel}: {result.status}",
            preview=result.to_dict(),
        )

    def _build_body(self, ctx, params: dict, counts: dict, workflow_name: str) -> str:
        template = (params.get("message_template") or "").strip()
        if template:
            return (
                template.replace("{workflow}", workflow_name)
                .replace("{status}", ctx.status)
                .replace("{summary}", (ctx.ai_analysis or {}).get("summary", ""))
                .replace("{critical}", str(counts["CRITICAL"]))
                .replace("{high}", str(counts["HIGH"]))
                .replace("{total}", str(counts["total"]))
            )
        if params.get("attach_report", True) and ctx.reports.get("md"):
            header = (
                f"**{workflow_name}** · статус: `{ctx.display_status()}`\n\n"
                f"CRITICAL: {counts['CRITICAL']}, HIGH: {counts['HIGH']}, "
                f"MEDIUM: {counts['MEDIUM']}, LOW: {counts['LOW']}, всего: {counts['total']}\n\n"
            )
            return header + ctx.reports["md"]
        ai_summary = (ctx.ai_analysis or {}).get("summary", "")
        return (
            f"{workflow_name}: статус {ctx.display_status()}. "
            f"Находок: {counts['total']} (CRITICAL {counts['CRITICAL']}, HIGH {counts['HIGH']}). "
            + ai_summary
        )
