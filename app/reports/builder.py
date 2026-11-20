from __future__ import annotations

import json
from datetime import datetime, timezone

from app.core.models import Finding, count_by, severity_counts, sort_findings

SEVERITY_LABEL = {
    "CRITICAL": "Критическая",
    "HIGH": "Высокая",
    "MEDIUM": "Средняя",
    "LOW": "Низкая",
}
CATEGORY_LABEL = {"SECRET": "Секреты", "SAST": "SAST", "SCA": "SCA"}


def build_all(
    findings: list[Finding],
    run_info: dict,
    ai: dict | None = None,
    gate: dict | None = None,
    source: dict | None = None,
    formats: list[str] | None = None,
) -> dict[str, str]:
    formats = formats or ["md", "json", "sarif"]
    ordered = sort_findings(findings)
    result: dict[str, str] = {}
    if "md" in formats:
        result["md"] = build_markdown(ordered, run_info, ai, gate, source)
    if "json" in formats:
        result["json"] = json.dumps(
            {"findings": [finding.to_submission() for finding in ordered]},
            ensure_ascii=False,
            indent=2,
        )
    if "sarif" in formats:
        result["sarif"] = json.dumps(
            build_sarif(ordered, run_info), ensure_ascii=False, indent=2
        )
    return result


def build_markdown(
    findings: list[Finding],
    run_info: dict,
    ai: dict | None = None,
    gate: dict | None = None,
    source: dict | None = None,
) -> str:
    counts = severity_counts(findings)
    categories = count_by(findings, "category")
    lines: list[str] = []
    lines.append("# Отчёт о проверке безопасности")
    lines.append("")
    lines.append(f"**Workflow:** {run_info.get('workflow_name') or '—'}  ")
    lines.append(f"**Запуск:** `{run_info.get('id', '—')}`  ")
    lines.append(f"**Источник:** {source.get('label') if source else (run_info.get('source_label') or '—')}  ")
    lines.append(f"**Триггер:** {run_info.get('trigger', 'manual')}  ")
    lines.append(f"**Статус:** {run_info.get('status', '—')}  ")
    if run_info.get("started_at"):
        lines.append(f"**Начат:** {run_info['started_at']}  ")
    if run_info.get("duration_ms") is not None:
        lines.append(f"**Длительность:** {run_info['duration_ms'] / 1000:.2f} с  ")
    lines.append("")
    lines.append("## Сводка")
    lines.append("")
    lines.append("| Критичность | Находок |")
    lines.append("| --- | ---: |")
    for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        lines.append(f"| {SEVERITY_LABEL[level]} ({level}) | {counts[level]} |")
    lines.append(f"| **Всего** | **{counts['total']}** |")
    lines.append("")
    if categories:
        lines.append("По категориям: " + ", ".join(f"{CATEGORY_LABEL.get(k, k)} — {v}" for k, v in categories.items()))
        lines.append("")
    if gate:
        lines.append(
            f"**CI-порог:** {'пройден' if gate.get('passed') else 'не пройден'} "
            f"(порог {gate.get('threshold')}, максимум {gate.get('max_severity') or '—'})"
        )
        lines.append("")
    if ai:
        lines.append("## AI-анализ")
        lines.append("")
        lines.append(f"**Провайдер:** {ai.get('provider', '—')} {ai.get('model', '')}".strip())
        lines.append("")
        lines.append(ai.get("summary", ""))
        lines.append("")
        if ai.get("next_steps"):
            lines.append("**Что делать дальше:**")
            lines.append("")
            for step in ai["next_steps"]:
                lines.append(f"- {step}")
            lines.append("")
        validation = ai.get("validation") or {}
        if validation:
            lines.append(
                "Проверка ответа: "
                f"схема — {'ok' if validation.get('schema_ok') else 'fallback'}, "
                f"привязка к находкам — {'ok' if validation.get('grounded') else 'есть расхождения'}, "
                f"покрыто {validation.get('coverage', {}).get('explained', 0)}"
                f"/{validation.get('coverage', {}).get('total', 0)}."
            )
            if validation.get("invented_advisories"):
                lines.append(
                    "Удалены неподтверждённые идентификаторы: "
                    + ", ".join(validation["invented_advisories"])
                )
            lines.append("")
    lines.append("## Находки")
    lines.append("")
    if not findings:
        lines.append("Находок нет: анализаторы не выявили проблем.")
        lines.append("")
        return "\n".join(lines)
    ai_by_id = {item.get("finding_id"): item for item in (ai or {}).get("findings", [])}
    for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        group = [finding for finding in findings if finding.severity == level]
        if not group:
            continue
        lines.append(f"### {SEVERITY_LABEL[level]} ({level}) — {len(group)}")
        lines.append("")
        for index, finding in enumerate(group, 1):
            lines.extend(_finding_markdown(index, finding, ai_by_id.get(finding.fingerprint)))
    return "\n".join(lines).rstrip() + "\n"


def _finding_markdown(index: int, finding: Finding, ai_item: dict | None) -> list[str]:
    location = f"{finding.path}:{finding.line}"
    if finding.end_line and finding.end_line > finding.line:
        location += f"–{finding.end_line}"
    lines = [
        f"#### {index}. `{finding.class_name}` — {location}",
        "",
        f"- **Категория:** {finding.category}",
        f"- **Правило:** `{finding.rule_id or finding.class_name}`",
    ]
    if finding.category == "SCA":
        lines.append(
            f"- **Зависимость:** `{finding.group}:{finding.artifact}:{finding.version}`"
        )
        lines.append(f"- **Advisory:** `{finding.advisory_id}`")
        if finding.extra.get("fixed_versions"):
            lines.append(
                "- **Исправленные версии:** "
                + ", ".join(str(v) for v in finding.extra["fixed_versions"])
            )
    if finding.cwe:
        lines.append(f"- **CWE:** {finding.cwe}")
    if finding.evidence:
        lines.append(f"- **Фрагмент:** `{finding.evidence}`")
    lines.append("")
    if finding.description or finding.message:
        lines.append(finding.description or finding.message)
        lines.append("")
    if finding.remediation:
        lines.append(f"**Рекомендация:** {finding.remediation}")
        lines.append("")
    if ai_item:
        lines.append("**AI-объяснение:** " + (ai_item.get("explanation") or ""))
        lines.append("")
        if ai_item.get("remediation") and ai_item.get("remediation") != finding.remediation:
            lines.append("**AI-рекомендация:** " + ai_item["remediation"])
            lines.append("")
    return lines


def build_sarif(findings: list[Finding], run_info: dict) -> dict:
    rules: dict[str, dict] = {}
    results = []
    level_map = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note"}
    for finding in findings:
        rule_key = finding.rule_id or finding.class_name
        if rule_key not in rules:
            rules[rule_key] = {
                "id": rule_key,
                "name": finding.class_name,
                "shortDescription": {"text": finding.message or finding.class_name},
                "defaultConfiguration": {"level": level_map.get(finding.severity, "warning")},
                "properties": {"category": finding.category, "severity": finding.severity},
            }
        region = {"startLine": finding.line}
        if finding.end_line and finding.end_line > finding.line:
            region["endLine"] = finding.end_line
        results.append(
            {
                "ruleId": rule_key,
                "level": level_map.get(finding.severity, "warning"),
                "message": {"text": finding.description or finding.message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": finding.path},
                            "region": region,
                        }
                    }
                ],
                "properties": {
                    "category": finding.category,
                    "severity": finding.severity,
                    "cwe": finding.cwe,
                    "advisoryId": finding.advisory_id,
                    "fingerprint": finding.fingerprint,
                },
            }
        )
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "LDWarden",
                        "informationUri": "https://github.com/ldwarden",
                        "version": "1.0.0",
                        "rules": list(rules.values()),
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "startTimeUtc": run_info.get("started_at") or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    }
                ],
                "results": results,
            }
        ],
    }
