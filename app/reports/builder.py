from __future__ import annotations

import json
from datetime import datetime, timezone
from html import escape as _html_escape

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
    if "html" in formats:
        result["html"] = build_html(ordered, run_info, ai, gate, source)
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


def _h(value) -> str:
    return _html_escape(str(value if value is not None else ""), quote=True)


def _when(value) -> str:
    if not value:
        return "—"
    try:
        moment = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return moment.astimezone(timezone.utc).strftime("%d.%m.%Y %H:%M UTC")
    except ValueError:
        return str(value)


def build_html(
    findings: list[Finding],
    run_info: dict,
    ai: dict | None = None,
    gate: dict | None = None,
    source: dict | None = None,
) -> str:
    """Self-contained HTML-отчёт: без внешних файлов, готов к печати и отправке."""
    ordered = sort_findings(findings)
    counts = severity_counts(ordered)
    categories = count_by(ordered, "category")
    ai_items: dict[str, dict] = {}
    if isinstance(ai, dict):
        for item in ai.get("findings") or []:
            key = item.get("finding_id")
            if key:
                ai_items[str(key)] = item

    severity_class = {
        "CRITICAL": "sev-critical",
        "HIGH": "sev-high",
        "MEDIUM": "sev-medium",
        "LOW": "sev-low",
    }

    def chips() -> str:
        parts = []
        for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            parts.append(
                f'<div class="stat {severity_class[level]}">'
                f'<span class="stat__num">{counts.get(level, 0)}</span>'
                f'<span class="stat__label">{SEVERITY_LABEL[level]}</span></div>'
            )
        return "".join(parts)

    parts: list[str] = []
    parts.append("<!doctype html>")
    parts.append('<html lang="ru"><head><meta charset="utf-8">')
    parts.append('<meta name="viewport" content="width=device-width, initial-scale=1">')
    parts.append(f"<title>LDWarden — отчёт {_h(run_info.get('workflow_name') or '')}</title>")
    parts.append(
        """<style>
:root { --ink:#221a1d; --muted:#7a6a70; --line:#ecd9df; --surface:#fff; --bg:#faf4f6; --rose:#c2597b; }
* { box-sizing: border-box; }
body { margin:0; padding:32px 20px; background:var(--bg); color:var(--ink);
  font: 14px/1.55 -apple-system, "Segoe UI", Roboto, Arial, sans-serif; }
.wrap { max-width: 960px; margin: 0 auto; }
.brand { display:flex; align-items:baseline; gap:10px; margin-bottom:6px; }
.brand b { font-size: 20px; letter-spacing:-.02em; }
.brand span { color: var(--muted); font-size: 12px; }
h1 { font-size: 24px; margin: 6px 0 18px; letter-spacing:-.02em; }
h2 { font-size: 16px; margin: 28px 0 12px; }
h3 { font-size: 14px; margin: 0 0 4px; }
h4 { font-size: 12px; margin: 14px 0 4px; color: var(--muted); text-transform: uppercase; letter-spacing:.04em; }
.meta { display:grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap:10px 18px;
  padding: 14px 16px; background: var(--surface); border:1px solid var(--line); border-radius: 12px; }
.meta div { font-size: 12px; color: var(--muted); }
.meta b { display:block; font-size: 13px; color: var(--ink); font-weight:600; margin-top:2px; }
.stats { display:grid; grid-template-columns: repeat(5, 1fr); gap:10px; margin:14px 0; }
.stat { background: var(--surface); border:1px solid var(--line); border-radius: 12px; padding: 10px 12px; }
.stat__num { display:block; font-size: 22px; font-weight: 700; }
.stat__label { font-size: 11px; color: var(--muted); }
.stat--total .stat__num { color: var(--rose); }
.sev-critical { border-left: 4px solid #b91c1c; }
.sev-high { border-left: 4px solid #dc2626; }
.sev-medium { border-left: 4px solid #d97706; }
.sev-low { border-left: 4px solid #2563eb; }
.cats { color: var(--muted); font-size: 12px; margin: 6px 0 0; }
.ai { background: var(--surface); border:1px solid var(--line); border-radius: 12px; padding: 14px 16px; }
.ai__model { color: var(--muted); font-size: 11px; }
.ai ul { margin: 8px 0 0 18px; padding: 0; }
.finding { background: var(--surface); border:1px solid var(--line); border-radius: 12px;
  padding: 14px 16px; margin-bottom: 12px; break-inside: avoid; }
.finding__top { display:flex; flex-wrap:wrap; align-items:center; gap:8px; margin-bottom:6px; }
.chip { font-size: 10px; text-transform: uppercase; letter-spacing:.05em; padding: 2px 8px;
  border-radius: 999px; background: var(--bg); border:1px solid var(--line); color: var(--muted); }
.chip--cat { color: var(--rose); border-color: #e7c3ce; }
.sev-label { font-size: 11px; font-weight: 600; }
.path { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 11.5px; color: var(--muted); }
pre { margin: 8px 0 0; padding: 10px 12px; background: #fbf7f8; border:1px solid var(--line);
  border-radius: 8px; overflow-x: auto; font-size: 11.5px; line-height: 1.45; }
.empty { color: var(--muted); font-style: italic; }
footer { margin-top: 28px; color: var(--muted); font-size: 11px; text-align: center; }
@media print { body { background:#fff; padding:0; } .wrap { max-width:none; } .finding, .ai { break-inside: avoid; } }
</style></head><body><div class="wrap">"""
    )

    parts.append('<div class="brand"><b>LDWarden</b><span>конструктор проверок безопасности</span></div>')
    parts.append("<h1>Отчёт о проверке безопасности</h1>")
    parts.append('<div class="meta">')
    meta_rows = [
        ("Workflow", run_info.get("workflow_name") or "—"),
        ("Запуск", run_info.get("id") or "—"),
        ("Источник", (source or {}).get("label") or run_info.get("source_label") or "—"),
        ("Триггер", run_info.get("trigger") or "manual"),
        ("Статус", run_info.get("status") or "—"),
        ("Дата", _when(run_info.get("started_at") or run_info.get("finished_at"))),
    ]
    if run_info.get("duration_ms"):
        meta_rows.append(("Длительность", f'{int(run_info["duration_ms"]) / 1000:.1f} с'))
    for label, value in meta_rows:
        parts.append(f"<div>{_h(label)}<b>{_h(value)}</b></div>")
    parts.append("</div>")

    parts.append('<div class="stats"><div class="stat stat--total"><span class="stat__num">'
                 + str(counts["total"]) + '</span><span class="stat__label">Всего</span></div>')
    parts.append(chips())
    parts.append("</div>")
    if categories:
        cats = ", ".join(f"{_h(name)} — {count}" for name, count in categories.items())
        parts.append(f'<p class="cats">Категории: {cats}</p>')

    if isinstance(ai, dict) and (ai.get("summary") or ai.get("next_steps")):
        parts.append('<section class="ai"><h2 style="margin-top:0">AI-сводка</h2>')
        if ai.get("summary"):
            parts.append(f"<p>{_h(ai['summary'])}</p>")
        if ai.get("next_steps"):
            parts.append("<ul>" + "".join(f"<li>{_h(step)}</li>" for step in ai["next_steps"]) + "</ul>")
        model = " · ".join(part for part in [ai.get("provider"), ai.get("model")] if part)
        if model:
            parts.append(f'<p class="ai__model">Модель: {_h(model)}</p>')
        parts.append("</section>")

    if gate:
        status = "пройден" if gate.get("passed", True) else "заблокирован"
        parts.append(f'<p class="cats">Порог критичности: {_h(gate.get("threshold") or "")} · гейт {_h(status)}</p>')

    parts.append("<h2>Находки</h2>")
    if not ordered:
        parts.append('<p class="empty">Находок нет — проверка чистая.</p>')
    for finding in ordered:
        sev = str(finding.severity)
        item = ai_items.get(str(finding.fingerprint)) or {}
        parts.append(f'<article class="finding {severity_class.get(sev, "sev-medium")}">')
        parts.append('<div class="finding__top">')
        parts.append(f'<span class="chip chip--cat">{_h(finding.category)}</span>')
        parts.append(f'<span class="chip">{_h(finding.class_name)}</span>')
        parts.append(f'<span class="sev-label">{_h(SEVERITY_LABEL.get(sev, sev))}</span>')
        parts.append("</div>")
        title = finding.message or finding.description or finding.class_name
        parts.append(f"<h3>{_h(title)}</h3>")
        location = f"{finding.path}:{finding.line}"
        if finding.end_line:
            location += f"–{finding.end_line}"
        parts.append(f'<div class="path">{_h(location)}</div>')
        if (
            finding.description
            and finding.description != title
            and not title.startswith(finding.description)
        ):
            parts.append(f"<p>{_h(finding.description)}</p>")
        if finding.evidence:
            parts.append(f"<pre>{_h(finding.evidence)}</pre>")
        if item.get("explanation"):
            parts.append("<h4>Почему это важно</h4>")
            parts.append(f"<p>{_h(item['explanation'])}</p>")
        remediation = item.get("remediation") or finding.remediation
        if remediation:
            parts.append("<h4>Как исправить</h4>")
            parts.append(f"<p>{_h(remediation)}</p>")
        if finding.extra and finding.extra.get("fixed_versions"):
            parts.append(f'<p class="cats">Исправлено в: {_h(", ".join(finding.extra["fixed_versions"]))}</p>')
        parts.append("</article>")

    parts.append(
        f'<footer>Сформировано LDWarden · {_h(datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"))}'
        "</footer></div></body></html>"
    )
    return "".join(parts)
