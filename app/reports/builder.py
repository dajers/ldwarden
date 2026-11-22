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
    theme: str = "sakura",
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
        result["html"] = build_html(ordered, run_info, ai, gate, source, theme=theme)
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


REPORT_THEMES: dict[str, dict] = {
    "sakura": {
        "bg": "#f7f4f5", "surface": "#ffffff", "surface2": "#fbf8f9",
        "ink": "#241d21", "muted": "#6f6168", "line": "#e5dade",
        "accent": "#b94a6b", "accent_soft": "#f8e9ee",
        "code_bg": "#f6f2f4", "code_ink": "#2b2227",
        "ok": "#2f7d55", "warn": "#a66a1f", "bad": "#b34444", "crit": "#8f1d3a",
        "scheme": "light",
    },
    "github": {
        "bg": "#f6f8fa", "surface": "#ffffff", "surface2": "#f6f8fa",
        "ink": "#1f2328", "muted": "#59636e", "line": "#d8dee4",
        "accent": "#0969da", "accent_soft": "#ddf4ff",
        "code_bg": "#f6f8fa", "code_ink": "#1f2328",
        "ok": "#1a7f37", "warn": "#9a6700", "bad": "#cf222e", "crit": "#a40e26",
        "scheme": "light",
    },
    "github-dark": {
        "bg": "#0d1117", "surface": "#161b22", "surface2": "#0d1117",
        "ink": "#e6edf3", "muted": "#8b949e", "line": "#30363d",
        "accent": "#58a6ff", "accent_soft": "#11294a",
        "code_bg": "#0d1117", "code_ink": "#e6edf3",
        "ok": "#3fb950", "warn": "#d29922", "bad": "#f85149", "crit": "#ff7b72",
        "scheme": "dark",
    },
    "warden": {
        "bg": "#070d18", "surface": "#0e1a2d", "surface2": "#0a1423",
        "ink": "#e9eff9", "muted": "#8ea3c4", "line": "#1d2f4f",
        "accent": "#60a5fa", "accent_soft": "#14294a",
        "code_bg": "#050b14", "code_ink": "#dbe7fb",
        "ok": "#34d399", "warn": "#fbbf24", "bad": "#f87171", "crit": "#fb7185",
        "scheme": "dark",
    },
    "mono": {
        "bg": "#08090a", "surface": "#121315", "surface2": "#0c0d0e",
        "ink": "#f1f1f1", "muted": "#a0a0a6", "line": "#2a2b2f",
        "accent": "#d8d8dc", "accent_soft": "#1b1c1f",
        "code_bg": "#000000", "code_ink": "#f5f5f5",
        "ok": "#3fb950", "warn": "#d29922", "bad": "#f85149", "crit": "#ff7b72",
        "scheme": "dark",
    },
}
REPORT_SEVERITIES = {"CRITICAL": "Критический", "HIGH": "Высокий", "MEDIUM": "Средний", "LOW": "Низкий"}
REPORT_STATUSES = {"success": "Завершён", "failed": "Ошибка", "cancelled": "Отменён", "running": "Выполняется"}


def _report_css(palette: dict) -> str:
    css = r"""
:root {
  --bg: __BG__; --surface: __SURFACE__; --surface-2: __SURFACE2__;
  --ink: __INK__; --muted: __MUTED__; --line: __LINE__;
  --accent: __ACCENT__; --accent-soft: __ACCENT_SOFT__;
  --code-bg: __CODE_BG__; --code-ink: __CODE_INK__;
  --ok: __OK__; --warn: __WARN__; --bad: __BAD__; --crit: __CRIT__;
  color-scheme: __SCHEME__;
}
* { box-sizing: border-box; }
html { background: var(--bg); }
body {
  margin: 0; padding: 48px 28px 56px; background: var(--bg); color: var(--ink);
  font: 13.5px/1.6 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif;
  -webkit-font-smoothing: antialiased;
}
.wrap { max-width: 1020px; margin: 0 auto; }
a { color: var(--accent); text-decoration: none; }
code, pre, .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
.cover { border-bottom: 2px solid var(--accent); padding-bottom: 26px; margin-bottom: 30px; }
.topline { display: flex; align-items: center; justify-content: space-between; gap: 16px; }
.brand { display: flex; align-items: center; gap: 9px; font-weight: 700; letter-spacing: -.01em; }
.brand svg { width: 24px; height: 24px; color: var(--accent); }
.brand span { font-size: 15px; }
.confidential { font-size: 9.5px; letter-spacing: .14em; text-transform: uppercase; color: var(--muted); border: 1px solid var(--line); padding: 4px 8px; border-radius: 4px; }
.eyebrow { margin: 32px 0 8px; font-size: 10px; letter-spacing: .16em; text-transform: uppercase; color: var(--accent); font-weight: 700; }
h1 { margin: 0; font-family: "Iowan Old Style", "Palatino Linotype", Georgia, serif; font-size: 36px; line-height: 1.08; font-weight: 600; letter-spacing: -.02em; }
.subtitle { margin: 10px 0 0; font-size: 15px; color: var(--muted); }
.badges { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 18px; }
.badge { display: inline-flex; align-items: center; gap: 6px; padding: 4px 9px; border-radius: 4px; border: 1px solid var(--line); background: var(--surface); font-size: 10px; font-weight: 700; letter-spacing: .04em; text-transform: uppercase; }
.badge--critical { color: var(--crit); border-color: var(--crit); }
.badge--high { color: var(--bad); border-color: var(--bad); }
.badge--medium { color: var(--warn); border-color: var(--warn); }
.badge--low { color: var(--accent); border-color: var(--accent); }
.badge--status { color: var(--ok); border-color: var(--ok); }
.badge--failed { color: var(--bad); border-color: var(--bad); }
.badge--cancelled { color: var(--warn); border-color: var(--warn); }
.cover-meta { display: grid; grid-template-columns: repeat(4, 1fr); gap: 0; margin-top: 26px; border-top: 1px solid var(--line); border-bottom: 1px solid var(--line); }
.cover-meta div { padding: 12px 14px 12px 0; }
.cover-meta span { display: block; font-size: 9.5px; letter-spacing: .08em; text-transform: uppercase; color: var(--muted); }
.cover-meta b { display: block; margin-top: 3px; font-size: 12.5px; font-weight: 600; color: var(--ink); overflow-wrap: anywhere; }
.section { margin: 34px 0; }
.section-head { display: flex; align-items: baseline; gap: 12px; margin-bottom: 14px; }
.section-head .num { font-size: 10px; font-weight: 700; letter-spacing: .12em; color: var(--accent); }
.section-head h2 { margin: 0; font-family: "Iowan Old Style", "Palatino Linotype", Georgia, serif; font-size: 22px; font-weight: 600; letter-spacing: -.01em; }
.lead { font-size: 14px; margin: 0 0 16px; color: var(--ink); }
.summary-grid { display: grid; grid-template-columns: 0.9fr 1.5fr; gap: 14px; align-items: stretch; }
.risk-card { border: 1px solid var(--line); border-left: 4px solid var(--crit); background: var(--surface); padding: 16px 18px; border-radius: 6px; }
.risk-card span { display: block; font-size: 9.5px; letter-spacing: .1em; text-transform: uppercase; color: var(--muted); }
.risk-card strong { display: block; margin: 5px 0 6px; font-family: "Iowan Old Style", "Palatino Linotype", Georgia, serif; font-size: 25px; font-weight: 600; color: var(--crit); }
.risk-card p { margin: 0; color: var(--muted); font-size: 11.5px; }
.risk-card.risk--high { border-left-color: var(--bad); } .risk-card.risk--high strong { color: var(--bad); }
.risk-card.risk--medium { border-left-color: var(--warn); } .risk-card.risk--medium strong { color: var(--warn); }
.risk-card.risk--low { border-left-color: var(--accent); } .risk-card.risk--low strong { color: var(--accent); }
.risk-card.risk--none { border-left-color: var(--ok); } .risk-card.risk--none strong { color: var(--ok); }
.metrics { display: grid; grid-template-columns: repeat(5, 1fr); gap: 8px; }
.metric { background: var(--surface); border: 1px solid var(--line); border-radius: 6px; padding: 12px 12px 10px; }
.metric span { display: block; font-size: 9px; letter-spacing: .06em; text-transform: uppercase; color: var(--muted); }
.metric b { display: block; margin-top: 4px; font-size: 23px; line-height: 1.1; font-weight: 650; }
.metric--critical b { color: var(--crit); } .metric--high b { color: var(--bad); }
.metric--medium b { color: var(--warn); } .metric--low b { color: var(--accent); }
.cats { color: var(--muted); font-size: 11.5px; margin: 10px 0 0; }
.ai-callout { background: var(--surface); border: 1px solid var(--line); border-left: 3px solid var(--accent); border-radius: 6px; padding: 16px 18px; margin-top: 14px; }
.ai-callout h3 { margin: 0 0 6px; font-size: 13px; }
.ai-callout p { margin: 0; font-size: 12.5px; }
.ai-callout ul { margin: 10px 0 0 18px; padding: 0; }
.ai-callout li { margin: 3px 0; }
.ai-model { margin-top: 10px; font-size: 10.5px; color: var(--muted); }
.toc { display: flex; flex-wrap: wrap; gap: 6px 18px; padding: 12px 0; border-top: 1px solid var(--line); border-bottom: 1px solid var(--line); font-size: 10.5px; letter-spacing: .06em; text-transform: uppercase; }
.toc a { color: var(--muted); }
.method-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 18px; }
.method-grid h3 { margin: 0 0 5px; font-size: 12px; }
.method-grid p { margin: 0; font-size: 11.5px; color: var(--muted); }
.note { margin: 14px 0 0; padding: 11px 13px; background: var(--surface-2); border: 1px solid var(--line); border-radius: 5px; font-size: 11px; color: var(--muted); }
.table-wrap { overflow-x: auto; border: 1px solid var(--line); border-radius: 6px; }
table { width: 100%; border-collapse: collapse; background: var(--surface); }
thead th { text-align: left; font-size: 9.5px; letter-spacing: .08em; text-transform: uppercase; color: var(--muted); font-weight: 700; padding: 10px 12px; border-bottom: 1px solid var(--line); white-space: nowrap; }
tbody td { padding: 10px 12px; border-bottom: 1px solid var(--line); font-size: 11.5px; vertical-align: top; }
tbody tr:last-child td { border-bottom: 0; }
tbody tr:nth-child(even) td { background: var(--surface-2); }
td .loc { color: var(--muted); font-size: 10.5px; white-space: nowrap; }
.findings-title { margin: 22px 0 10px; font-size: 13px; letter-spacing: .08em; text-transform: uppercase; color: var(--muted); }
.finding { background: var(--surface); border: 1px solid var(--line); border-radius: 6px; padding: 16px 18px; margin-bottom: 12px; break-inside: avoid; }
.finding-head { display: flex; flex-wrap: wrap; align-items: center; gap: 9px; margin-bottom: 5px; }
.finding-num { font-size: 11px; font-weight: 700; color: var(--muted); letter-spacing: .06em; }
.finding h3 { margin: 2px 0 4px; font-size: 15px; font-weight: 600; }
.finding .location { margin: 0 0 8px; color: var(--muted); font-size: 10.5px; overflow-wrap: anywhere; }
.finding p { margin: 0 0 8px; font-size: 12px; }
pre { margin: 8px 0 10px; padding: 10px 12px; background: var(--code-bg); color: var(--code-ink); border: 1px solid var(--line); border-radius: 4px; overflow-x: auto; font-size: 10.5px; line-height: 1.45; }
.finding-cols { display: grid; grid-template-columns: 1fr 1fr; gap: 18px; margin-top: 10px; }
.finding-cols h4 { margin: 0 0 4px; font-size: 9.5px; letter-spacing: .08em; text-transform: uppercase; color: var(--accent); }
.finding-cols p { margin: 0; font-size: 11.5px; color: var(--ink); }
.empty { padding: 22px; border: 1px dashed var(--line); border-radius: 6px; color: var(--muted); text-align: center; }
.limitations { font-size: 11.5px; color: var(--muted); }
.limitations ul { margin: 8px 0 0 18px; padding: 0; }
footer { margin-top: 34px; padding-top: 14px; border-top: 1px solid var(--line); color: var(--muted); font-size: 10px; display: flex; justify-content: space-between; gap: 16px; }
@media (max-width: 760px) {
  body { padding: 28px 16px; } .cover-meta { grid-template-columns: 1fr 1fr; }
  .summary-grid, .method-grid, .finding-cols { grid-template-columns: 1fr; }
  .metrics { grid-template-columns: repeat(2, 1fr); }
}
@media print {
  :root { --bg:#fff; --surface:#fff; --surface-2:#f7f7f7; --ink:#111; --muted:#555; --line:#d5d5d5; --accent:#333; --accent-soft:#f1f1f1; --code-bg:#f7f7f7; --code-ink:#111; --ok:#1a7f37; --warn:#8a5a00; --bad:#b42318; --crit:#7a1222; color-scheme: light; }
  body { padding: 0; font-size: 10.5px; }
  .wrap { max-width: none; }
  .cover { page-break-after: always; }
  .toc { display: none; }
  .finding, .metric, .risk-card, .ai-callout { break-inside: avoid; }
}
"""
    for key, value in palette.items():
        css = css.replace(f"__{key.upper()}__", str(value))
    return css


def build_html(
    findings: list[Finding],
    run_info: dict,
    ai: dict | None = None,
    gate: dict | None = None,
    source: dict | None = None,
    theme: str = "sakura",
) -> str:
    """Самодостаточный HTML-отчёт в стиле выбранной темы."""
    palette = REPORT_THEMES.get(str(theme or "sakura").lower(), REPORT_THEMES["sakura"])
    ordered = sort_findings(findings)
    counts = severity_counts(ordered)
    categories = count_by(ordered, "category")
    ai_items: dict[str, dict] = {}
    if isinstance(ai, dict):
        for item in ai.get("findings") or []:
            key = item.get("finding_id")
            if key:
                ai_items[str(key)] = item

    risk_key = next((level for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW") if counts.get(level, 0)), "NONE")
    risk_label = REPORT_SEVERITIES.get(risk_key, "Чисто")
    risk_class = risk_key.lower()
    status = str(run_info.get("status") or "")
    status_label = REPORT_STATUSES.get(status, status or "—")
    status_class = "badge--status" if status == "success" else ("badge--failed" if status == "failed" else "badge--cancelled" if status == "cancelled" else "badge--status")
    location_source = (source or {}).get("label") or run_info.get("source_label") or "—"
    generated_at = datetime.now(timezone.utc).strftime("%d.%m.%Y %H:%M UTC")
    model = " · ".join(part for part in [ai.get("provider"), ai.get("model")] if part) if isinstance(ai, dict) else ""
    gate_passed = bool(gate.get("passed", True)) if isinstance(gate, dict) else None

    def badge(level: str) -> str:
        return f'<span class="badge badge--{level.lower()}">{_h(REPORT_SEVERITIES.get(level, level))}</span>'

    def html_escape(value) -> str:
        return _h(value)

    parts: list[str] = []
    parts.append("<!doctype html>")
    parts.append(f'<html lang="ru" data-report-theme="{html_escape(theme)}"><head><meta charset="utf-8">')
    parts.append('<meta name="viewport" content="width=device-width, initial-scale=1">')
    parts.append('<meta name="color-scheme" content="light dark">')
    parts.append(f"<title>LDWarden — отчёт о проверке безопасности · {html_escape(run_info.get('workflow_name') or '')}</title>")
    parts.append("<style>" + _report_css(palette) + "</style></head><body><div class=\"wrap\">")

    # cover
    parts.append('<header class="cover">')
    parts.append('<div class="topline"><div class="brand">'
                 '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round">'
                 '<path d="M12 3.5 19 6v5.5c0 4.2-2.9 7.5-7 9-4.1-1.5-7-4.8-7-9V6Z"/><path d="M9 12l2 2 4-4"/></svg>'
                 '<span>LDWarden</span></div><span class="confidential">Конфиденциально</span></div>')
    parts.append('<p class="eyebrow">Security assessment · static analysis</p>')
    parts.append("<h1>Отчёт о проверке<br>безопасности кода</h1>")
    parts.append(f'<p class="subtitle">{html_escape(run_info.get("workflow_name") or "Проверка безопасности")} · {html_escape(location_source)}</p>')
    parts.append('<div class="badges">')
    parts.append(f'<span class="badge badge--{risk_class if risk_key != "NONE" else "critical"}">{html_escape(risk_label)}</span>')
    parts.append(f'<span class="badge {status_class}">{html_escape(status_label)}</span>')
    if gate is not None:
        parts.append(f'<span class="badge {"badge--status" if gate_passed else "badge--failed"}">Порог: {"пройден" if gate_passed else "заблокирован"}</span>')
    parts.append("</div>")
    parts.append('<div class="cover-meta">')
    meta_rows = [
        ("Запуск", run_info.get("id") or "—"),
        ("Дата", _when(run_info.get("started_at") or run_info.get("finished_at"))),
        ("Триггер", run_info.get("trigger") or "manual"),
        ("Источник", location_source),
        ("Находок", str(counts.get("total", 0))),
        ("Длительность", f'{int(run_info["duration_ms"]) / 1000:.1f} с' if run_info.get("duration_ms") else "—"),
    ]
    for label, value in meta_rows:
        parts.append(f"<div><span>{html_escape(label)}</span><b>{html_escape(value)}</b></div>")
    parts.append("</div></header>")

    # summary
    parts.append('<section class="section" id="summary">')
    parts.append('<div class="section-head"><span class="num">01</span><h2>Резюме</h2></div>')
    parts.append('<div class="summary-grid">')
    risk_text = {
        "CRITICAL": "Обнаружены критичные проблемы, требующие немедленного исправления.",
        "HIGH": "Есть серьёзные риски; исправление рекомендуется до релиза.",
        "MEDIUM": "Найдены умеренные риски; запланируйте исправления.",
        "LOW": "Обнаружены незначительные замечания.",
        "NONE": "Проблем не обнаружено.",
    }.get(risk_key, "Требуется проверка результатов.")
    parts.append(f'<div class="risk-card risk--{risk_class}"><span>Уровень риска</span><strong>{html_escape(risk_label)}</strong><p>{html_escape(risk_text)}</p></div>')
    parts.append('<div class="metrics">')
    metric_rows = [
        ("Всего", counts.get("total", 0), ""),
        ("CRITICAL", counts.get("CRITICAL", 0), "critical"),
        ("HIGH", counts.get("HIGH", 0), "high"),
        ("MEDIUM", counts.get("MEDIUM", 0), "medium"),
        ("LOW", counts.get("LOW", 0), "low"),
    ]
    for label, value, tone in metric_rows:
        parts.append(f'<div class="metric metric--{tone}"><span>{html_escape(label)}</span><b>{value}</b></div>')
    parts.append("</div></div>")
    if categories:
        cats = " · ".join(f"{html_escape(name)} {count}" for name, count in categories.items())
        parts.append(f'<p class="cats">Категории: {cats}</p>')
    summary_sentence = (
        f"Проверено: {html_escape(location_source)}. "
        f"Обнаружено {counts.get('total', 0)} находок: "
        f"критических — {counts.get('CRITICAL', 0)}, высоких — {counts.get('HIGH', 0)}, "
        f"средних — {counts.get('MEDIUM', 0)}, низких — {counts.get('LOW', 0)}."
    )
    parts.append(f'<p class="lead">{summary_sentence}</p>')
    if isinstance(ai, dict) and ai.get("summary"):
        parts.append('<div class="ai-callout"><h3>AI-сводка</h3>')
        parts.append(f"<p>{html_escape(ai['summary'])}</p>")
        if ai.get("next_steps"):
            parts.append("<ul>" + "".join(f"<li>{html_escape(step)}</li>" for step in ai["next_steps"]) + "</ul>")
        if model:
            parts.append(f'<p class="ai-model">Модель: {html_escape(model)}</p>')
        parts.append("</div>")
    parts.append("</section>")

    # toc
    parts.append('<nav class="toc"><a href="#summary">01 Резюме</a><a href="#method">02 Методика</a><a href="#findings">03 Находки</a><a href="#ai">04 AI-рекомендации</a><a href="#limitations">05 Ограничения</a></nav>')

    # methodology
    parts.append('<section class="section" id="method">')
    parts.append('<div class="section-head"><span class="num">02</span><h2>Методика</h2></div>')
    parts.append('<div class="method-grid">')
    parts.append('<div><h3>SECRET</h3><p>Собственные regex-правила, фильтрация плейсхолдеров и полная маскировка значений. Пароли, API-ключи, токены, fallback-секреты и приватные ключи.</p></div>')
    parts.append('<div><h3>SCA</h3><p>Разбор build.gradle.kts, разрешение версий через свойства и lockfile, сверка с Maven-справочником по диапазонам; координаты и advisoryId.</p></div>')
    parts.append('<div><h3>SAST</h3><p>Паттерны Kotlin/Spring: SQL-инъекции, проверка TLS, credentialed CORS, авторизация маршрутов и объектов. Класс, строки и критичность.</p></div>')
    parts.append("</div>")
    parts.append(f'<p class="note">Область анализа: {html_escape(location_source)}. Статический анализ, приложение не запускалось. '
                 f'AI: {html_escape(model or "не использовалась")}; ответ проверяется по JSON-схеме и grounding.</p>')
    parts.append("</section>")

    # findings
    parts.append('<section class="section" id="findings">')
    parts.append(f'<div class="section-head"><span class="num">03</span><h2>Находки</h2></div>')
    if not ordered:
        parts.append('<div class="empty">Находок нет — проверка чистая.</div>')
    else:
        parts.append('<div class="table-wrap"><table><thead><tr><th>#</th><th>Критичность</th><th>Категория</th><th>Находка</th><th>Расположение</th></tr></thead><tbody>')
        for index, finding in enumerate(ordered, 1):
            title = finding.message or finding.description or finding.class_name
            loc = f"{finding.path}:{finding.line}" + (f"–{finding.end_line}" if finding.end_line else "")
            parts.append(
                f"<tr><td><a href=\"#f{index}\">{index:02d}</a></td>"
                f"<td>{badge(str(finding.severity))}</td>"
                f"<td>{html_escape(finding.category)}</td>"
                f"<td>{html_escape(title)}</td>"
                f"<td class=\"loc\">{html_escape(loc)}</td></tr>"
            )
        parts.append("</tbody></table></div>")
        parts.append('<h3 class="findings-title">Подробности</h3>')
        for index, finding in enumerate(ordered, 1):
            sev = str(finding.severity)
            item = ai_items.get(str(finding.fingerprint)) or {}
            title = finding.message or finding.description or finding.class_name
            loc = f"{finding.path}:{finding.line}" + (f"–{finding.end_line}" if finding.end_line else "")
            parts.append(f'<article class="finding" id="f{index}">')
            parts.append('<div class="finding-head">')
            parts.append(f'<span class="finding-num">№ {index:02d}</span>')
            parts.append(badge(sev))
            parts.append(f'<span class="badge">{html_escape(finding.category)}</span>')
            if finding.rule_id:
                parts.append(f'<span class="badge">{html_escape(finding.rule_id)}</span>')
            parts.append("</div>")
            parts.append(f"<h3>{html_escape(title)}</h3>")
            parts.append(f'<p class="location mono">{html_escape(loc)}</p>')
            if finding.description and finding.description != title and not title.startswith(finding.description):
                parts.append(f"<p>{html_escape(finding.description)}</p>")
            if finding.evidence:
                parts.append(f"<pre>{html_escape(finding.evidence)}</pre>")
            cols: list[str] = []
            if item.get("explanation"):
                cols.append(f'<div><h4>Почему это важно</h4><p>{html_escape(item["explanation"])}</p></div>')
            remediation = item.get("remediation") or finding.remediation
            if remediation:
                cols.append(f'<div><h4>Как исправить</h4><p>{html_escape(remediation)}</p></div>')
            if cols:
                parts.append('<div class="finding-cols">' + "".join(cols) + "</div>")
            fixed = (finding.extra or {}).get("fixed_versions")
            if fixed:
                parts.append(f'<p class="cats">Исправлено в: {html_escape(", ".join(fixed))}</p>')
            parts.append("</article>")
    parts.append("</section>")

    # ai
    parts.append('<section class="section" id="ai">')
    parts.append('<div class="section-head"><span class="num">04</span><h2>AI-рекомендации</h2></div>')
    if isinstance(ai, dict) and (ai.get("summary") or ai.get("next_steps")):
        parts.append('<div class="ai-callout">')
        if ai.get("summary"):
            parts.append(f"<p>{html_escape(ai['summary'])}</p>")
        if ai.get("next_steps"):
            parts.append("<ul>" + "".join(f"<li>{html_escape(step)}</li>" for step in ai["next_steps"]) + "</ul>")
        if model:
            parts.append(f'<p class="ai-model">Модель: {html_escape(model)} · ответ проверен по схеме и grounding</p>')
        parts.append("</div>")
    else:
        parts.append('<p class="empty">AI-анализ не выполнялся — использованы детерминированные рекомендации анализаторов.</p>')
    parts.append("</section>")

    # limitations
    parts.append('<section class="section" id="limitations">')
    parts.append('<div class="section-head"><span class="num">05</span><h2>Ограничения</h2></div>')
    parts.append('<div class="limitations"><ul>'
                 '<li>Статический анализ не заменяет запуск приложения и ручную проверку специалистом.</li>'
                 '<li>Правила ориентированы на Kotlin / Spring Boot / Gradle Kotlin DSL.</li>'
                 '<li>Результаты AI требуют проверки: модель может ошибаться, grounding отсекает только выдуманные ссылки и CVE.</li>'
                 '<li>Секреты в отчёте маскируются; исходные значения доступны только в защищённом хранилище.</li>'
                 '</ul></div>')
    parts.append("</section>")

    parts.append(f'<footer><span>LDWarden · сформировано {html_escape(generated_at)}</span><span>Конфиденциально · требует проверки специалистом</span></footer>')
    parts.append("</div></body></html>")
    return "".join(parts)
