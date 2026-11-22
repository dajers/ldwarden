from __future__ import annotations

import re

from app.core.graph import normalize_graph, validate_graph


def _has(text: str, *words: str) -> bool:
    lowered = text.lower()
    return any(word in lowered for word in words)


def _schedule_cron(prompt: str) -> str:
    match = re.search(r"\b([01]?\d|2[0-3]):([0-5]\d)\b", prompt)
    if match:
        return f"{int(match.group(2))} {int(match.group(1))} * * *"
    if _has(prompt, "каждую неделю", "еженедельно", "weekly"):
        return "0 9 * * 1"
    if _has(prompt, "каждый час", "hourly"):
        return "0 * * * *"
    return "0 14 * * *"


def heuristic_workflow(prompt: str, source_hint: str = "") -> dict:
    prompt = (prompt or "").strip()
    warnings: list[str] = []
    if not prompt:
        prompt = "Проверь код на секреты и уязвимые зависимости и отправь отчёт"

    if _has(prompt, "ci", "pipeline", "pull request", "merge request", "коммит", "webhook", "вебхук"):
        trigger_type = "trigger.webhook"
        trigger_params = {"secret": ""}
    elif _has(prompt, "кажд", "ежеднев", "день", "расписан", "cron", "weekly", "еженедел"):
        trigger_type = "trigger.schedule"
        trigger_params = {"cron": _schedule_cron(prompt), "timezone": "UTC"}
    else:
        trigger_type = "trigger.manual"
        trigger_params = {}

    want_secrets = _has(prompt, "секрет", "парол", "ключ", "токен", "token", "secret", "credential")
    want_sca = _has(prompt, "зависим", "библиотек", "sca", "cve", "dependenc", "пакет")
    want_sast = _has(
        prompt,
        "sast",
        "инъекц",
        "статическ",
        "код",
        "kotlin",
        "spring",
        "sql",
        "cors",
        "tls",
        "авторизац",
        "уязвим",
        "idor",
    )
    if not (want_secrets or want_sca or want_sast):
        want_secrets = want_sca = want_sast = True

    want_ai = not _has(prompt, "без ai", "без ии", "no ai", "без нейросет")
    want_gate = _has(prompt, "ci", "pipeline", "gate", "блокир", "критич", "fail")

    if _has(prompt, "telegram", "телеграм"):
        notify_params = {"channel": "telegram", "dry_run": False}
    elif _has(prompt, "webhook", "вебхук", "http"):
        notify_params = {"channel": "webhook", "url": "local://inbox", "dry_run": False}
    else:
        notify_params = {"channel": "webhook", "url": "local://inbox", "dry_run": False}

    nodes: list[dict] = []
    edges: list[dict] = []

    def add(node_id: str, node_type: str, x: int, y: int, label: str, params: dict | None = None):
        nodes.append(
            {
                "id": node_id,
                "type": node_type,
                "position": {"x": x, "y": y},
                "data": {"label": label, "params": params or {}},
            }
        )

    def connect(source: str, target: str, handle: str = "out"):
        edges.append(
            {
                "id": f"e-{source}-{handle}-{target}",
                "source": source,
                "target": target,
                "sourceHandle": handle,
                "targetHandle": "in",
            }
        )

    add("trigger", trigger_type, 40, 200, "Запуск", trigger_params)
    add("source", "source.target", 320, 200, "Источник кода", {"path": source_hint})
    connect("trigger", "source")

    scanners: list[tuple[str, str, str]] = []
    if want_secrets:
        scanners.append(("secrets", "scan.secrets", "Поиск секретов"))
    if want_sca:
        scanners.append(("sca", "scan.sca", "Уязвимые зависимости"))
    if want_sast:
        scanners.append(("sast", "scan.sast", "SAST Kotlin/Spring"))

    previous = "source"
    x = 600
    for node_id, node_type, label in scanners:
        add(node_id, node_type, x, 200, label, {})
        connect(previous, node_id)
        previous = node_id
        x += 260

    if want_ai:
        add("ai", "ai.analyze", x, 200, "AI-объяснение", {"provider": "auto"})
        connect(previous, "ai")
        previous = "ai"
        x += 260

    if want_gate:
        add(
            "gate",
            "control.severity_gate",
            x,
            200,
            "Порог критичности",
            {"threshold": "HIGH", "blocking": True},
        )
        connect(previous, "gate")
        previous = "gate"
        x += 260

    add("report", "report.build", x, 200, "Отчёт", {"formats": ["md", "json", "sarif"]})
    if want_gate:
        connect("gate", "report", "pass")
        connect("gate", "report", "fail")
    else:
        connect(previous, "report")
    x += 260

    add("notify", "notify.send", x, 200, "Уведомление", notify_params)
    connect("report", "notify")

    graph = normalize_graph({"nodes": nodes, "edges": edges})
    report = validate_graph(graph)
    if not report["valid"]:
        warnings.extend(report["errors"])
    description = "Автоматически собранный сценарий: " + ", ".join(
        label for _id, _type, label in scanners
    )
    if want_ai:
        description += ", AI-объяснение"
    if want_gate:
        description += ", порог критичности"
    description += ", отчёт и уведомление."
    return {
        "name": (prompt[:80] or "Сгенерированный workflow"),
        "description": description,
        "graph": report["graph"],
        "provider": "heuristic",
        "validation": report,
        "warnings": warnings,
    }


# ---------- intent + deterministic composer ----------

INTENT_CHECKS = ("secrets", "sca", "sast")
INTENT_TRIGGERS = ("manual", "schedule", "webhook")
INTENT_NOTIFY = ("none", "email", "telegram", "webhook")
INTENT_RISKS = ("none", "LOW", "MEDIUM", "HIGH", "CRITICAL")
WEEKDAY_WORDS = {
    "понедельник": "1",
    "вторник": "2",
    "среду": "3",
    "среда": "3",
    "четверг": "4",
    "пятниц": "5",
    "суббот": "6",
    "воскрес": "7",
}


def _time_from_text(prompt: str) -> str:
    match = re.search(r"\b([01]?\d|2[0-3]):([0-5]\d)\b", prompt or "")
    return f"{int(match.group(1)):02d}:{match.group(2)}" if match else "09:00"


def _date_from_text(prompt: str) -> str:
    match = re.search(r"\b(20\d{2}-\d{2}-\d{2})\b", prompt or "")
    return match.group(1) if match else ""


def _weekday_from_text(prompt: str) -> str:
    lowered = (prompt or "").lower()
    if _has(lowered, "каждый день", "ежеднев", "daily"):
        return "*"
    for word, value in WEEKDAY_WORDS.items():
        if word in lowered:
            return value
    return "*"


def heuristic_intent(prompt: str) -> dict:
    text = (prompt or "").strip()
    lowered = text.lower()
    if _has(lowered, "ci", "pipeline", "pull request", "merge request", "коммит", "webhook", "вебхук"):
        trigger = "webhook"
    elif _has(lowered, "кажд", "ежеднев", "день", "расписан", "cron", "weekly", "еженедел", "понедельник", "вторник", "среду", "четверг", "пятниц", "суббот", "воскрес"):
        trigger = "schedule"
    else:
        trigger = "manual"

    checks = []
    if _has(lowered, "секрет", "парол", "ключ", "токен", "token", "secret", "credential"):
        checks.append("secrets")
    if _has(lowered, "зависим", "библиотек", "sca", "cve", "dependenc", "пакет"):
        checks.append("sca")
    if _has(lowered, "sast", "инъекц", "статическ", "код", "kotlin", "spring", "sql", "cors", "tls", "авторизац", "уязвим", "idor"):
        checks.append("sast")
    if not checks:
        checks = list(INTENT_CHECKS)

    has_ci = _has(lowered, "ci", "pipeline", "gate", "блокир", "fail", "pull request", "merge request")
    gate = "HIGH" if has_ci else "none"
    for risk in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        if risk.lower() in lowered:
            gate = risk
            break

    if _has(lowered, "почт", "email", "e-mail", "smtp"):
        notify = "email"
    elif _has(lowered, "telegram", "телеграм"):
        notify = "telegram"
    elif _has(lowered, "без уведом", "no notify", "без оповещ"):
        notify = "none"
    else:
        notify = "webhook"

    mode = "weekly"
    weekday = _weekday_from_text(text)
    run_time = _time_from_text(text)
    run_date = _date_from_text(text)
    if trigger == "schedule" and run_date:
        mode = "once"

    return {
        "name": (text[:80] or "Сгенерированный сценарий"),
        "description": "Сценарий собран по текстовому описанию.",
        "trigger": trigger,
        "schedule_mode": mode,
        "schedule_date": run_date,
        "schedule_time": run_time,
        "schedule_weekday": weekday,
        "checks": checks,
        "ai": not _has(lowered, "без ai", "без ии", "no ai", "без нейросет"),
        "gate": gate,
        "notify": notify,
        "report_formats": ["md", "json", "sarif"],
    }


def _node(node_id: str, node_type: str, x: int, y: int, label: str, params: dict | None = None) -> dict:
    return {
        "id": node_id,
        "type": node_type,
        "position": {"x": x, "y": y},
        "data": {"label": label, "params": params or {}},
    }


def _edge(source: str, target: str, handle: str = "out") -> dict:
    return {
        "id": f"e-{source}-{handle}-{target}",
        "source": source,
        "target": target,
        "sourceHandle": handle,
        "targetHandle": "in",
    }


def compose_workflow(intent: dict, source_hint: str = "") -> dict:
    trigger = str(intent.get("trigger") or "manual").lower()
    if trigger not in INTENT_TRIGGERS:
        trigger = "manual"
    checks = [str(item) for item in (intent.get("checks") or []) if str(item) in INTENT_CHECKS]
    checks = list(dict.fromkeys(checks)) or list(INTENT_CHECKS)
    notify = str(intent.get("notify") or "none").lower()
    if notify not in INTENT_NOTIFY:
        notify = "webhook"
    gate = str(intent.get("gate") or "none").upper()
    if gate not in INTENT_RISKS:
        gate = "none"
    formats = [str(item) for item in (intent.get("report_formats") or ["md", "json", "sarif"]) if str(item) in {"md", "json", "sarif"}] or ["md", "json", "sarif"]

    nodes: list[dict] = []
    edges: list[dict] = []
    trigger_params: dict = {}
    if trigger == "webhook":
        trigger_params = {"secret": "", "description": "Запуск из CI/вебхука"}
    elif trigger == "schedule":
        mode = str(intent.get("schedule_mode") or "weekly").lower()
        mode = mode if mode in {"once", "weekly"} else "weekly"
        weekday = str(intent.get("schedule_weekday") or "*")
        run_time = str(intent.get("schedule_time") or "09:00")
        run_date = str(intent.get("schedule_date") or "")
        if mode == "once" and not run_date:
            mode = "weekly"
        trigger_params = {
            "mode": mode,
            "run_date": run_date if mode == "once" else "",
            "run_time": run_time,
            "weekday": weekday if mode == "weekly" else "*",
            "timezone": "Europe/Moscow",
            "cron": "",
        }
    nodes.append(_node("trigger", f"trigger.{trigger}", 40, 240, "Запуск", trigger_params))
    nodes.append(_node("source", "source.target", 320, 240, "Источник кода", {"path": source_hint or ""}))
    edges.append(_edge("trigger", "source"))

    x = 620
    previous = "source"
    labels = {
        "secrets": ("scan.secrets", "Поиск секретов"),
        "sca": ("scan.sca", "Уязвимые зависимости"),
        "sast": ("scan.sast", "Статический анализ"),
    }
    for check in checks:
        node_type, label = labels[check]
        node_id = check
        nodes.append(_node(node_id, node_type, x, 240, label, {}))
        edges.append(_edge(previous, node_id))
        previous = node_id
        x += 260

    if intent.get("ai", True):
        nodes.append(_node("ai", "ai.analyze", x, 240, "AI-объяснение", {
            "provider": "auto", "max_findings": 2, "threads": 4, "timeout": 180
        }))
        edges.append(_edge(previous, "ai"))
        previous = "ai"
        x += 260

    if gate != "none":
        nodes.append(_node("gate", "control.severity_gate", x, 240, "Порог критичности", {
            "threshold": gate, "blocking": True, "categories": ["SECRET", "SAST", "SCA"]
        }))
        edges.append(_edge(previous, "gate"))
        previous = "gate"
        x += 260

    nodes.append(_node("report", "report.build", x, 240, "Отчёт", {
        "formats": formats, "include_ai": bool(intent.get("ai", True))
    }))
    if gate != "none":
        edges.append(_edge("gate", "report", "pass"))
        edges.append(_edge("gate", "report", "fail"))
    else:
        edges.append(_edge(previous, "report"))
    x += 260

    if notify != "none":
        notify_params = {
            "subject": "LDWarden: отчёт о проверке",
            "attach_report": True,
            "dry_run": True,
            "fail_on_error": False,
        }
        if notify == "telegram":
            nodes.append(_node("notify", "notify.telegram", x, 240, "Telegram", {
                **notify_params, "bot_token": "", "chat_id": ""
            }))
        else:
            # Email-нода удалена из текущего набора; для email используем webhook
            # с dry-run, чтобы сценарий оставался валидным и запускаемым.
            nodes.append(_node("notify", "notify.webhook", x, 240, "HTTP webhook", {
                **notify_params, "url": "local://inbox", "method": "POST", "secret": ""
            }))
        edges.append(_edge("report", "notify"))

    graph = normalize_graph({"nodes": nodes, "edges": edges})
    report = validate_graph(graph)
    warnings = []
    if intent.get("notify") == "email":
        warnings.append("Email-нода удалена из текущего набора; для уведомления использован HTTP webhook (dry-run).")
    return {
        "name": str(intent.get("name") or "Сгенерированный сценарий")[:160],
        "description": str(intent.get("description") or "")[:4000],
        "graph": report["graph"],
        "validation": report,
        "warnings": warnings,
    }


def merge_intent_with_prompt(intent: dict, prompt: str) -> dict:
    result = dict(intent or {})
    hint = heuristic_intent(prompt)
    if str(result.get("trigger") or "").lower() == "schedule":
        if hint.get("trigger") == "schedule":
            if _has(prompt.lower(), "каждый день", "ежеднев", "daily"):
                result["schedule_weekday"] = "*"
            elif hint.get("schedule_weekday") not in (None, ""):
                result["schedule_weekday"] = hint["schedule_weekday"]
            if _has(prompt.lower(), "каждый день", "ежеднев", "daily"):
                result["schedule_mode"] = "weekly"
            if _date_from_text(prompt):
                result["schedule_mode"] = "once"
                result["schedule_date"] = _date_from_text(prompt)
            if re.search(r"\b([01]?\d|2[0-3]):([0-5]\d)\b", prompt or ""):
                result["schedule_time"] = _time_from_text(prompt)
    return result
