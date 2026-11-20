from __future__ import annotations

from typing import TYPE_CHECKING, Any

from app.core.models import HandleSpec, NodeResult
from app.core.registry import register_node

if TYPE_CHECKING:
    from app.core.engine import RunContext


class NodeError(RuntimeError):
    """A node failed in a way that should mark the run as failed."""


class NodeSkipped(RuntimeError):
    """A node intentionally did not perform work."""


class BaseNode:
    type: str = "base"
    category: str = "other"
    title: str = "Нода"
    description: str = ""
    icon: str = ""
    color: str = "#64748b"
    inputs: list[HandleSpec] | None = None
    outputs: list[HandleSpec] | None = None
    params: list[Any] = []
    tags: list[str] = []
    docs: str = ""
    examples: list[dict] = []
    version: str = "1.0"

    def execute(self, ctx: "RunContext", params: dict) -> NodeResult:
        raise NotImplementedError

    def validate_output(self, result: NodeResult) -> NodeResult:
        if not isinstance(result, NodeResult):
            raise NodeError(f"Нода {self.type} вернула некорректный результат")
        if not result.active_handles:
            result.active_handles = ["out"]
        return result


    @staticmethod
    def findings_summary(findings, limit: int = 10) -> dict:
        by_severity: dict[str, int] = {}
        by_class: dict[str, int] = {}
        for finding in findings:
            by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1
            by_class[finding.class_name] = by_class.get(finding.class_name, 0) + 1
        top = [
            {
                "id": finding.fingerprint,
                "category": finding.category,
                "class": finding.class_name,
                "severity": finding.severity,
                "path": finding.path,
                "line": finding.line,
                "end_line": finding.end_line,
                "message": finding.message,
                "advisory_id": finding.advisory_id,
            }
            for finding in findings[:limit]
        ]
        return {
            "count": len(findings),
            "by_severity": dict(sorted(by_severity.items(), key=lambda item: -item[1])),
            "by_class": dict(sorted(by_class.items(), key=lambda item: -item[1])),
            "top": top,
        }


def node(cls):
    """Register a node class and return it (alias for readability)."""
    return register_node(cls)
