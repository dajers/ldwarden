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
    elif _has(prompt, "почт", "email", "smtp", "письм"):
        notify_params = {"channel": "smtp", "dry_run": False}
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
