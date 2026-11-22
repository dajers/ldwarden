from __future__ import annotations

import json

SYSTEM_PROMPT = """Ты — senior application security engineer, который помогает небольшой команде разработчиков.
Твоя задача — объяснить результаты уже выполненных собственных анализаторов простым русским языком.
Жёсткие правила:
1. Используй ТОЛЬКО переданные находки. Не придумывай новые файлы, строки, уязвимости, CVE и GHSA.
2. Не меняй вердикт анализаторов: находка существует, если она есть во входных данных.
3. Ссылайся на finding_id из входа. Не ссылайся на идентификаторы, которых нет во входе.
4. Пиши по-русски, кратко и практично: что не так, к чему это приведёт, как исправить.
5. Верни только валидный JSON без markdown-обёрток, ровно по схеме из запроса.
"""


def build_analysis_request(findings: list[dict], meta: dict | None = None) -> str:
    meta = meta or {}
    payload = {
        "task": "aggregate_security_findings",
        "language": "ru",
        "instructions": {
            "summary": "2 предложения: общая картина и самые опасные проблемы.",
            "overall_risk": "CRITICAL | HIGH | MEDIUM | LOW на основе severity.",
            "findings": "Кратко: finding_id и explanation (1–2 предложения). Remediation можно не повторять.",
            "grounding": "Не добавляй файлы, строки, CVE и GHSA, которых нет во входных данных.",
        },
        "allowed_finding_ids": [item.get("id") for item in findings],
        "allowed_advisories": sorted(
            {
                advisory
                for item in findings
                for advisory in (item.get("advisory_ids") or [item.get("advisory_id")])
                if advisory
            }
        ),
        "findings": findings,
        "context": meta,
        "response_schema": {
            "summary": "string",
            "overall_risk": "CRITICAL|HIGH|MEDIUM|LOW",
            "findings": [
                {
                    "finding_id": "string (из allowed_finding_ids)",
                    "explanation": "string",
                }
            ],
        },
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)


def build_repair_request(previous: str, error: str) -> str:
    return json.dumps(
        {
            "task": "repair_json",
            "error": error,
            "previous_response": previous[:8000],
            "instruction": (
                "Верни только валидный JSON по исходной схеме. "
                "Не добавляй markdown, комментарии и пояснения вне JSON."
            ),
        },
        ensure_ascii=False,
    )


def build_workflow_request(prompt: str, node_catalog: list[dict], source_hint: str = "") -> str:
    allowed = [
        {
            "type": spec["type"],
            "category": spec["category"],
            "title": spec["title"],
            "params": [
                {"name": param["name"], "type": param["type"], "default": param["default"]}
                for param in spec["params"]
            ],
            "inputs": [handle["id"] for handle in spec["inputs"]],
            "outputs": [handle["id"] for handle in spec["outputs"]],
        }
        for spec in node_catalog
    ]
    payload = {
        "task": "generate_security_workflow",
        "language": "ru",
        "user_request": prompt,
        "source_hint": source_hint,
        "rules": [
            "Используй только типы нод из allowed_nodes.",
            "Ровно один триггер (trigger.manual, trigger.schedule или trigger.webhook).",
            "Сканеры: scan.secrets, scan.sca, scan.sast; их можно соединять последовательно или параллельно.",
            "После сканеров добавь ai.analyze, затем report.build и notify.send.",
            "sourceHandle должен быть из outputs ноды-источника, targetHandle — из inputs ноды-цели.",
            "Не придумывай параметры, которых нет в описании ноды.",
            "Располагай ноды слева направо: x = 80 + 280 * колонка, y = 80 + 180 * ряд.",
        ],
        "allowed_nodes": allowed,
        "response_schema": {
            "name": "string",
            "description": "string",
            "nodes": [{"id": "string", "type": "string", "label": "string", "params": {}}],
            "edges": [{"source": "string", "target": "string", "sourceHandle": "string", "targetHandle": "string"}],
        },
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)


def build_workflow_intent_request(prompt: str, source_hint: str = "") -> str:
    payload = {
        "task": "extract_workflow_intent",
        "language": "ru",
        "rules": [
            "Верни только JSON-объект без markdown.",
            "Не придумывай новые типы проверок.",
            "checks: только secrets, sca, sast.",
            "trigger: manual, schedule или webhook.",
            "Если нужен CI — trigger=webhook и gate HIGH (если не указан другой порог).",
            "Если запуск по времени — trigger=schedule; schedule_mode=weekly или once; время HH:MM.",
            "Если указан день недели — schedule_weekday: * или 1..7 (понедельник=1).",
            "Если указана конкретная дата — schedule_mode=once и schedule_date YYYY-MM-DD.",
            "notify: none, email, telegram или webhook.",
        ],
        "response_schema": {
            "name": "string",
            "description": "string",
            "trigger": "manual|schedule|webhook",
            "schedule_mode": "weekly|once",
            "schedule_date": "YYYY-MM-DD или пусто",
            "schedule_time": "HH:MM",
            "schedule_weekday": "*|1|2|3|4|5|6|7",
            "checks": ["secrets", "sca", "sast"],
            "ai": "boolean",
            "gate": "none|LOW|MEDIUM|HIGH|CRITICAL",
            "notify": "none|email|telegram|webhook",
            "report_formats": ["md", "json", "sarif"],
        },
        "user_request": prompt,
        "source_hint": source_hint,
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)


def build_workflow_ast_request(prompt: str, source_hint: str = "") -> str:
    payload = {
        "task": "generate_security_workflow_ast",
        "language": "ru",
        "rules": [
            "Верни только валидный JSON без markdown.",
            "Не создавай nodes, edges, id и координаты — только steps.",
            "steps — упорядоченный массив. Порядок шагов = порядок выполнения.",
            "Разрешённые type: source.target, scan.secrets, scan.sca, scan.sast, ai.analyze, control.severity_gate, report.build, notify.webhook, notify.telegram.",
            "Для условия используй type=condition с полями field, operator, value, then, else; then/else — массивы шагов.",
            "Допустимые field: findings.total, findings.CRITICAL, findings.HIGH, findings.MEDIUM, findings.LOW, findings.by_category.SECRET, findings.by_category.SAST, findings.by_category.SCA, gate.passed, ai.overall_risk.",
            "Допустимые operator: eq, ne, gt, gte, lt, lte, contains, truthy, empty.",
            "Максимум 24 шага и вложенность 4.",
            "Для CI используй trigger.type=webhook и gate/condition по CRITICAL или HIGH.",
            "Для расписания используй trigger.type=schedule, time HH:MM, weekday * или 1..7, mode weekly|once, date YYYY-MM-DD для once.",
            "Если нужен отчёт, добавь report.build. Если нужно уведомление, добавь notify.webhook или notify.telegram.",
        ],
        "examples": [
            {
                "name": "Ежедневный аудит",
                "trigger": {"type": "schedule", "mode": "weekly", "weekday": "*", "time": "09:00", "timezone": "Europe/Moscow"},
                "steps": [
                    {"type": "source.target", "params": {}},
                    {"type": "scan.secrets", "params": {}},
                    {"type": "scan.sca", "params": {}},
                    {"type": "report.build", "params": {"formats": ["md", "json", "sarif"]}},
                    {"type": "notify.webhook", "params": {"url": "local://inbox"}}
                ]
            },
            {
                "name": "CI gate",
                "trigger": {"type": "webhook"},
                "steps": [
                    {"type": "source.target", "params": {}},
                    {"type": "scan.secrets", "params": {}},
                    {"type": "scan.sast", "params": {}},
                    {
                        "type": "condition",
                        "field": "findings.CRITICAL",
                        "operator": "gte",
                        "value": "1",
                        "then": [
                            {"type": "report.build", "params": {"formats": ["md", "json", "sarif"]}},
                            {"type": "notify.telegram", "params": {}}
                        ],
                        "else": [
                            {"type": "notify.webhook", "params": {"url": "local://inbox"}}
                        ]
                    }
                ]
            },
            {
                "name": "Только статический анализ",
                "trigger": {"type": "manual"},
                "steps": [
                    {"type": "source.target", "params": {}},
                    {"type": "scan.sast", "params": {}},
                    {"type": "report.build", "params": {"formats": ["md", "json"]}}
                ]
            }
        ],
        "user_request": prompt,
        "source_hint": source_hint,
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)
