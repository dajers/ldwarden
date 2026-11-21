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
