from __future__ import annotations

from dataclasses import dataclass, field

from app.core.models import Finding
from app.core.source import SourceTree


@dataclass
class AnalysisResult:
    findings: list[Finding] = field(default_factory=list)
    stats: dict = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "findings": [f.to_dict() for f in self.findings],
            "stats": self.stats,
            "warnings": self.warnings,
        }


class BaseAnalyzer:
    name = "base"
    title = "Базовый анализатор"

    def analyze(self, tree: SourceTree) -> AnalysisResult:
        raise NotImplementedError

    def _result(
        self,
        findings: list[Finding],
        scanned: int,
        warnings: list[str] | None = None,
        **extra,
    ) -> AnalysisResult:
        stats = {
            "analyzer": self.name,
            "files_scanned": scanned,
            "findings": len(findings),
            **extra,
        }
        if warnings:
            stats["warnings"] = list(warnings)
        return AnalysisResult(findings=findings, stats=stats, warnings=list(warnings or []))
