from __future__ import annotations

from app.core.models import HandleSpec, NodeResult, ParamSpec, severity_counts
from app.core.registry import register_node
from app.nodes.base import BaseNode
from app.reports.builder import build_all


@register_node
class ReportBuildNode(BaseNode):
    type = "report.build"
    category = "report"
    title = "Отчёт"
    description = "Собирает JSON по формату организаторов, читаемый Markdown и SARIF из одного набора находок."
    icon = "📄"
    color = "#64748b"
    outputs = [HandleSpec("out", "Отчёт")]
    params = [
        ParamSpec(
            "formats",
            "multiselect",
            "Форматы",
            "Какие отчёты сформировать",
            default=["md", "json", "sarif"],
            options=[
                {"value": "md", "label": "Markdown"},
                {"value": "json", "label": "JSON (submission)"},
                {"value": "sarif", "label": "SARIF"},
            ],
        ),
        ParamSpec("include_ai", "boolean", "Включить AI-объяснения", "", default=True),
    ]
    tags = ["report", "markdown", "json", "sarif"]

    def execute(self, ctx, params: dict) -> NodeResult:
        formats = params.get("formats") or ["md", "json", "sarif"]
        run_info = ctx.run_info()
        reports = build_all(
            ctx.findings,
            run_info,
            ai=ctx.ai_analysis if params.get("include_ai", True) else None,
            gate=ctx.gate,
            source=ctx.source.to_dict() if ctx.source else None,
            formats=formats,
        )
        ctx.reports.update(reports)
        counts = severity_counts(ctx.findings)
        sizes = {name: len(value) for name, value in reports.items()}
        ctx.emit(
            "report.built",
            "Отчёт собран: " + ", ".join(f"{name} ({size} б)" for name, size in sizes.items()),
            node_id=ctx.node_id,
            payload={"formats": list(reports.keys()), "sizes": sizes, "counts": counts},
        )
        return NodeResult(
            outputs={
                "formats": list(reports.keys()),
                "sizes": sizes,
                "findings": counts["total"],
            },
            message="Отчёт собран",
            preview={"formats": list(reports.keys()), "sizes": sizes},
        )
