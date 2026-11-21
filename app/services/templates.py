from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

from app.core.graph import normalize_graph, validate_graph
from app.db import WorkflowRow, j_loads, utcnow


def _node(node_id: str, node_type: str, x: int, y: int, label: str, params: dict | None = None) -> dict:
    return {
        "id": node_id,
        "type": node_type,
        "position": {"x": x, "y": y},
        "data": {"label": label, "params": params or {}},
    }


def _edge(source: str, target: str, source_handle: str = "out") -> dict:
    return {
        "id": f"e-{source}-{source_handle}-{target}",
        "source": source,
        "target": target,
        "sourceHandle": source_handle,
        "targetHandle": "in",
    }


def _full_audit_graph() -> dict:
    return normalize_graph(
        {
            "nodes": [
                _node("trigger", "trigger.manual", 40, 220, "Ручной запуск"),
                _node("source", "source.target", 320, 220, "Источник кода"),
                _node("secrets", "scan.secrets", 620, 80, "Секреты"),
                _node("sca", "scan.sca", 620, 280, "Уязвимые зависимости"),
                _node("sast", "scan.sast", 620, 480, "SAST Kotlin/Spring"),
                _node("ai", "ai.analyze", 940, 280, "AI-объяснение", {"provider": "auto"}),
                _node("report", "report.build", 1240, 280, "Отчёт"),
                _node(
                    "notify",
                    "notify.webhook",
                    1540,
                    280,
                    "Уведомление",
                    {"url": "local://inbox", "attach_report": True},
                ),
            ],
            "edges": [
                _edge("trigger", "source"),
                _edge("source", "secrets"),
                _edge("source", "sca"),
                _edge("source", "sast"),
                _edge("secrets", "ai"),
                _edge("sca", "ai"),
                _edge("sast", "ai"),
                _edge("ai", "report"),
                _edge("report", "notify"),
            ],
        }
    )


def _secrets_only_graph() -> dict:
    return normalize_graph(
        {
            "nodes": [
                _node("trigger", "trigger.manual", 40, 200, "Ручной запуск"),
                _node("source", "source.target", 320, 200, "Источник кода"),
                _node("secrets", "scan.secrets", 620, 200, "Секреты"),
                _node("ai", "ai.analyze", 920, 200, "AI-объяснение"),
                _node("report", "report.build", 1220, 200, "Отчёт"),
                _node(
                    "notify",
                    "notify.webhook",
                    1520,
                    200,
                    "Уведомление",
                    {"url": "local://inbox", "attach_report": True},
                ),
            ],
            "edges": [
                _edge("trigger", "source"),
                _edge("source", "secrets"),
                _edge("secrets", "ai"),
                _edge("ai", "report"),
                _edge("report", "notify"),
            ],
        }
    )


def _ci_gate_graph() -> dict:
    return normalize_graph(
        {
            "nodes": [
                _node(
                    "trigger",
                    "trigger.webhook",
                    40,
                    260,
                    "Webhook / CI",
                    {"secret": "", "description": "Запуск из GitHub Actions или GitLab CI"},
                ),
                _node("source", "source.target", 320, 260, "Источник кода"),
                _node("secrets", "scan.secrets", 620, 100, "Секреты"),
                _node("sca", "scan.sca", 620, 300, "SCA"),
                _node("sast", "scan.sast", 620, 500, "SAST"),
                _node("ai", "ai.analyze", 940, 300, "AI-объяснение"),
                _node(
                    "gate",
                    "control.severity_gate",
                    1240,
                    300,
                    "CI-порог",
                    {"threshold": "HIGH", "blocking": True},
                ),
                _node("report", "report.build", 1540, 300, "Отчёт"),
                _node(
                    "notify",
                    "notify.webhook",
                    1840,
                    300,
                    "HTTP webhook",
                    {"url": "local://inbox", "attach_report": True},
                ),
            ],
            "edges": [
                _edge("trigger", "source"),
                _edge("source", "secrets"),
                _edge("source", "sca"),
                _edge("source", "sast"),
                _edge("secrets", "ai"),
                _edge("sca", "ai"),
                _edge("sast", "ai"),
                _edge("ai", "gate"),
                _edge("gate", "report", "pass"),
                _edge("gate", "report", "fail"),
                _edge("report", "notify"),
            ],
        }
    )


def _daily_graph() -> dict:
    return normalize_graph(
        {
            "nodes": [
                _node(
                    "trigger",
                    "trigger.schedule",
                    40,
                    240,
                    "Каждый день в 14:00",
                    {"mode": "weekly", "weekday": "*", "run_time": "14:00", "timezone": "UTC"},
                ),
                _node("source", "source.target", 320, 240, "Источник кода"),
                _node("secrets", "scan.secrets", 620, 80, "Секреты"),
                _node("sca", "scan.sca", 620, 280, "SCA"),
                _node("sast", "scan.sast", 620, 480, "SAST"),
                _node("ai", "ai.analyze", 940, 280, "AI-объяснение"),
                _node("report", "report.build", 1240, 280, "Отчёт"),
                _node(
                    "notify",
                    "notify.webhook",
                    1540,
                    280,
                    "Уведомление",
                    {"url": "local://inbox", "attach_report": True},
                ),
            ],
            "edges": [
                _edge("trigger", "source"),
                _edge("source", "secrets"),
                _edge("source", "sca"),
                _edge("source", "sast"),
                _edge("secrets", "ai"),
                _edge("sca", "ai"),
                _edge("sast", "ai"),
                _edge("ai", "report"),
                _edge("report", "notify"),
            ],
        }
    )


def _quick_smoke_graph() -> dict:
    return normalize_graph(
        {
            "nodes": [
                _node("trigger", "trigger.manual", 40, 240, "Ручной запуск"),
                _node("source", "source.target", 320, 240, "Источник кода"),
                _node("secrets", "scan.secrets", 620, 80, "Секреты"),
                _node("sca", "scan.sca", 620, 280, "SCA"),
                _node("sast", "scan.sast", 620, 480, "SAST"),
                _node(
                    "gate",
                    "control.severity_gate",
                    940,
                    280,
                    "Порог",
                    {"threshold": "HIGH", "blocking": True},
                ),
                _node(
                    "report",
                    "report.build",
                    1240,
                    280,
                    "Отчёт",
                    {"formats": ["md", "json", "sarif"]},
                ),
                _node(
                    "notify",
                    "notify.webhook",
                    1540,
                    280,
                    "Уведомление",
                    {"url": "local://inbox", "attach_report": True},
                ),
            ],
            "edges": [
                _edge("trigger", "source"),
                _edge("source", "secrets"),
                _edge("source", "sca"),
                _edge("source", "sast"),
                _edge("secrets", "gate"),
                _edge("sca", "gate"),
                _edge("sast", "gate"),
                _edge("gate", "report", "pass"),
                _edge("gate", "report", "fail"),
                _edge("report", "notify"),
            ],
        }
    )


BUILTIN_TEMPLATES: list[dict] = [
    {
        "id": "tpl-full-audit",
        "name": "Полный аудит перед мержем",
        "description": (
            "Три собственных анализатора (секреты, SCA, SAST) в независимых ветках, AI-объяснение, "
            "Markdown/JSON/SARIF и уведомление в демо-ящик."
        ),
        "tags": ["full", "audit", "ai"],
        "graph": _full_audit_graph,
    },
    {
        "id": "tpl-secrets-only",
        "name": "Только секреты",
        "description": "Быстрый поиск паролей, API-ключей, токенов и приватных ключей с AI-рекомендациями и демо-уведомлением.",
        "tags": ["secrets", "fast"],
        "graph": _secrets_only_graph,
    },
    {
        "id": "tpl-ci-gate",
        "name": "CI/CD: PR gate",
        "description": (
            "Запуск по webhook из пайплайна, все сканеры, порог HIGH, блокировка сборки "
            "при критических находках и уведомление через HTTP webhook."
        ),
        "tags": ["ci", "gate", "webhook"],
        "graph": _ci_gate_graph,
    },
    {
        "id": "tpl-daily-audit",
        "name": "Ежедневный аудит в 14:00",
        "description": "Запуск по расписанию каждый день в 14:00 UTC, полный отчёт и уведомление в демо-ящик.",
        "tags": ["schedule", "daily"],
        "graph": _daily_graph,
    },
    {
        "id": "tpl-quick-smoke",
        "name": "Быстрый smoke (без AI)",
        "description": "Сканеры + порог HIGH + отчёт без обращения к LLM: для pre-commit и CI.",
        "tags": ["fast", "ci", "no-ai"],
        "graph": _quick_smoke_graph,
    },
]


def seed_builtin_templates(settings) -> None:
    for template in BUILTIN_TEMPLATES:
        if WorkflowRow.get_or_none(WorkflowRow.id == template["id"]):
            continue
        graph = template["graph"]()
        report = validate_graph(graph)
        if not report["valid"]:
            import logging

            logging.getLogger(__name__).error(
                "Встроенный шаблон %s невалиден: %s", template["id"], report["errors"]
            )
            continue
        WorkflowRow.create(
            id=template["id"],
            name=template["name"],
            description=template["description"],
            graph=json.dumps(report["graph"], ensure_ascii=False),
            is_template=True,
            published=True,
            published_at=utcnow(),
            version=1,
            owner="ldwarden",
        )


def list_templates() -> list[dict]:
    rows = (
        WorkflowRow.select()
        .where((WorkflowRow.is_template == True) & (WorkflowRow.published == True))
        .order_by(WorkflowRow.name)
    )
    result = []
    for row in rows:
        data = row.to_dict()
        data["node_count"] = len(data.get("graph", {}).get("nodes", []))
        result.append(data)
    return result


def clone_template(template_id: str, name: str | None = None) -> dict:
    source = WorkflowRow.get_or_none(WorkflowRow.id == template_id)
    if source is None:
        raise LookupError("Шаблон не найден")
    new_id = "wf-" + uuid.uuid4().hex[:12]
    base_name = name or f"Копия: {source.name}"
    row = WorkflowRow.create(
        id=new_id,
        name=base_name[:160],
        description=source.description,
        graph=source.graph,
        is_template=False,
        published=False,
        version=1,
        owner="local",
    )
    return row.to_dict()


def publish_workflow(workflow_id: str) -> dict:
    row = WorkflowRow.get_or_none(WorkflowRow.id == workflow_id)
    if row is None:
        raise LookupError("Workflow не найден")
    graph = j_loads(row.graph, {"nodes": [], "edges": []})
    report = validate_graph(graph)
    if not report["valid"]:
        raise ValueError("Нельзя опубликовать невалидный workflow: " + "; ".join(report["errors"]))
    row.is_template = True
    row.published = True
    row.published_at = datetime.now(timezone.utc).replace(tzinfo=None)
    row.graph = json.dumps(report["graph"], ensure_ascii=False)
    row.save()
    return row.to_dict()


def unpublish_workflow(workflow_id: str) -> dict:
    row = WorkflowRow.get_or_none(WorkflowRow.id == workflow_id)
    if row is None:
        raise LookupError("Workflow не найден")
    row.is_template = False
    row.published = False
    row.published_at = None
    row.save()
    return row.to_dict()
