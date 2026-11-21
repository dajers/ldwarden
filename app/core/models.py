from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

SEVERITY_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
SEVERITY_ALIASES = {
    "INFO": "LOW",
    "INFORMATIONAL": "LOW",
    "NOTE": "LOW",
    "WARNING": "MEDIUM",
    "WARN": "MEDIUM",
    "MODERATE": "MEDIUM",
    "ERROR": "HIGH",
    "MAJOR": "HIGH",
    "CRIT": "CRITICAL",
    "BLOCKER": "CRITICAL",
}
CATEGORIES = ["SECRET", "SAST", "SCA", "CUSTOM"]


def normalize_severity(value: str | None, default: str = "MEDIUM") -> str:
    if not value:
        return default
    text = str(value).strip().upper()
    if text in SEVERITY_ORDER:
        return text
    return SEVERITY_ALIASES.get(text, default)


def severity_rank(value: str | None) -> int:
    return SEVERITY_ORDER.get(normalize_severity(value), 0)


def max_severity(findings: list["Finding"]) -> str | None:
    if not findings:
        return None
    return max((normalize_severity(f.severity) for f in findings), key=severity_rank)


def severity_counts(findings: list["Finding"]) -> dict[str, int]:
    counts = {level: 0 for level in SEVERITIES}
    for finding in findings:
        counts[normalize_severity(finding.severity)] += 1
    counts["total"] = len(findings)
    return counts


def normalize_rel_path(value: str | Path, root: str | Path | None = None) -> str:
    """Return a safe project-relative POSIX path.

    Absolute paths are made relative to ``root`` when possible; anything that
    still escapes the project (``..``) is reduced to its basename.
    """
    text = str(value).replace("\\", "/").strip()
    if root is not None:
        try:
            text = str(Path(text).resolve().relative_to(Path(root).resolve())).replace("\\", "/")
        except (ValueError, OSError):
            pass
    if text.startswith("/"):
        text = text.lstrip("/")
    parts: list[str] = []
    for part in PurePosixPath(text).parts:
        if part in ("", "."):
            continue
        if part == "..":
            parts = []
            continue
        parts.append(part)
    return "/".join(parts) or "unknown"


@dataclass
class Finding:
    category: str
    class_name: str
    path: str
    line: int = 1
    end_line: int | None = None
    severity: str = "MEDIUM"
    message: str = ""
    description: str = ""
    remediation: str = ""
    cwe: str | None = None
    rule_id: str = ""
    evidence: str = ""
    confidence: float = 0.8
    detector: str = ""
    source_node: str = ""
    group: str | None = None
    artifact: str | None = None
    version: str | None = None
    advisory_id: str | None = None
    advisory_ids: list[str] = field(default_factory=list)
    alternate_locations: list[dict] = field(default_factory=list)
    extra: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.category = str(self.category).upper()
        if self.category not in CATEGORIES:
            self.category = "SAST"
        self.severity = normalize_severity(self.severity)
        self.path = normalize_rel_path(self.path)
        try:
            self.line = max(1, int(self.line or 1))
        except (TypeError, ValueError):
            self.line = 1
        if self.end_line is not None:
            try:
                self.end_line = max(self.line, int(self.end_line))
            except (TypeError, ValueError):
                self.end_line = None
            if self.end_line is not None and self.end_line - self.line > 14:
                self.end_line = self.line + 14
        self.advisory_ids = list(dict.fromkeys(self.advisory_ids or []))
        if self.advisory_id and self.advisory_id not in self.advisory_ids:
            self.advisory_ids.insert(0, self.advisory_id)

    @property
    def fingerprint(self) -> str:
        raw = "|".join(
            [
                self.category,
                self.class_name,
                self.path,
                str(self.line),
                self.advisory_id or "",
                self.rule_id or "",
            ]
        )
        return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:20]

    @property
    def severity_rank(self) -> int:
        return severity_rank(self.severity)

    def to_submission(self) -> dict:
        """Serialise exactly as the organisers' submission format requires."""
        data: dict[str, Any] = {
            "category": self.category,
            "path": self.path,
            "severity": self.severity,
        }
        if self.description:
            data["description"] = self.description
        elif self.message:
            data["description"] = self.message
        if self.remediation:
            data["remediation"] = self.remediation
        if self.category in ("SECRET", "SAST"):
            data["class"] = self.class_name
            data["line"] = self.line
            if self.end_line and self.end_line > self.line:
                data["endLine"] = self.end_line
        else:
            data["group"] = self.group or ""
            data["artifact"] = self.artifact or ""
            data["version"] = self.version or ""
            data["advisoryId"] = self.advisory_id or (self.advisory_ids[0] if self.advisory_ids else "")
        return data

    def to_dict(self) -> dict:
        return {
            "id": self.fingerprint,
            "fingerprint": self.fingerprint,
            "category": self.category,
            "class": self.class_name,
            "rule_id": self.rule_id,
            "severity": self.severity,
            "path": self.path,
            "line": self.line,
            "end_line": self.end_line,
            "message": self.message,
            "description": self.description,
            "remediation": self.remediation,
            "cwe": self.cwe,
            "evidence": self.evidence,
            "confidence": round(float(self.confidence), 2),
            "detector": self.detector,
            "source_node": self.source_node,
            "group": self.group,
            "artifact": self.artifact,
            "version": self.version,
            "advisory_id": self.advisory_id,
            "advisory_ids": self.advisory_ids,
            "alternate_locations": self.alternate_locations,
            "extra": self.extra,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Finding":
        return cls(
            category=data.get("category", "SAST"),
            class_name=data.get("class", data.get("class_name", "unknown")),
            path=data.get("path", "unknown"),
            line=data.get("line", 1),
            end_line=data.get("end_line", data.get("endLine")),
            severity=data.get("severity", "MEDIUM"),
            message=data.get("message", ""),
            description=data.get("description", ""),
            remediation=data.get("remediation", ""),
            cwe=data.get("cwe"),
            rule_id=data.get("rule_id", ""),
            evidence=data.get("evidence", ""),
            confidence=data.get("confidence", 0.8),
            detector=data.get("detector", ""),
            source_node=data.get("source_node", ""),
            group=data.get("group"),
            artifact=data.get("artifact"),
            version=data.get("version"),
            advisory_id=data.get("advisory_id"),
            advisory_ids=data.get("advisory_ids", []),
            alternate_locations=data.get("alternate_locations", []),
            extra=data.get("extra", {}),
        )


def dedupe_findings(findings: list[Finding]) -> list[Finding]:
    """Merge duplicates produced by overlapping detectors."""
    merged: dict[str, Finding] = {}
    for finding in findings:
        key = finding.fingerprint
        if key not in merged:
            merged[key] = finding
            continue
        existing = merged[key]
        if severity_rank(finding.severity) > severity_rank(existing.severity):
            existing.severity = finding.severity
        if len(finding.description) > len(existing.description):
            existing.description = finding.description
        if len(finding.evidence) > len(existing.evidence):
            existing.evidence = finding.evidence
        existing.alternate_locations.extend(
            loc for loc in finding.alternate_locations if loc not in existing.alternate_locations
        )
        existing.advisory_ids = list(dict.fromkeys(existing.advisory_ids + finding.advisory_ids))
        existing.extra = {**finding.extra, **existing.extra}
    return list(merged.values())


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda f: (-severity_rank(f.severity), f.category, f.path, f.line, f.class_name),
    )


def filter_min_severity(findings: list[Finding], minimum: str | None) -> list[Finding]:
    threshold = severity_rank(minimum) if minimum else 0
    return [f for f in findings if severity_rank(f.severity) >= threshold]


def count_by(findings: list[Finding], attribute: str) -> dict[str, int]:
    result: dict[str, int] = {}
    for finding in findings:
        key = str(getattr(finding, attribute, "") or "")
        result[key] = result.get(key, 0) + 1
    return dict(sorted(result.items(), key=lambda item: (-item[1], item[0])))


@dataclass
class HandleSpec:
    id: str
    label: str = ""
    description: str = ""
    position: str = "right"
    kind: str = "source"

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "label": self.label or self.id,
            "description": self.description,
            "position": self.position,
            "kind": self.kind,
        }


@dataclass
class ParamSpec:
    name: str
    type: str = "string"
    label: str = ""
    description: str = ""
    default: Any = None
    required: bool = False
    options: list[Any] = field(default_factory=list)
    secret: bool = False
    placeholder: str = ""
    multiline: bool = False
    min: float | None = None
    max: float | None = None
    depends_on: dict | None = None

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "type": self.type,
            "label": self.label or self.name,
            "description": self.description,
            "default": self.default,
            "required": self.required,
            "options": self.options,
            "secret": self.secret or self.type == "secret",
            "placeholder": self.placeholder,
            "multiline": self.multiline,
            "min": self.min,
            "max": self.max,
            "depends_on": self.depends_on,
        }


@dataclass
class NodeSpec:
    type: str
    category: str
    title: str
    description: str
    icon: str = ""
    color: str = "#64748b"
    inputs: list[HandleSpec] = field(default_factory=lambda: [HandleSpec("in", "Вход", position="left", kind="target")])
    outputs: list[HandleSpec] = field(default_factory=lambda: [HandleSpec("out", "Выход")])
    params: list[ParamSpec] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    docs: str = ""
    examples: list[dict] = field(default_factory=list)
    version: str = "1.0"

    def to_dict(self) -> dict:
        return {
            "type": self.type,
            "category": self.category,
            "title": self.title,
            "description": self.description,
            "icon": self.icon,
            "color": self.color,
            "inputs": [h.to_dict() for h in self.inputs],
            "outputs": [h.to_dict() for h in self.outputs],
            "params": [p.to_dict() for p in self.params],
            "tags": self.tags,
            "docs": self.docs,
            "examples": self.examples,
            "version": self.version,
            "ui": {
                "min_width": 220,
                "handles": {
                    "inputs": [h.to_dict() for h in self.inputs],
                    "outputs": [h.to_dict() for h in self.outputs],
                },
            },
        }


@dataclass
class NodeResult:
    status: str = "success"
    outputs: dict = field(default_factory=dict)
    active_handles: list[str] = field(default_factory=lambda: ["out"])
    message: str = ""
    preview: dict = field(default_factory=dict)
    findings_count: int = 0
    error: str | None = None


@dataclass
class ResolvedSource:
    id: str
    root: Path
    label: str
    kind: str
    files: int = 0
    skipped: int = 0
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "root": str(self.root),
            "label": self.label,
            "kind": self.kind,
            "files": self.files,
            "skipped": self.skipped,
            "warnings": self.warnings,
        }


_FILENAME_SAFE = re.compile(r"[^A-Za-z0-9_.-]+")


def safe_slug(value: str, fallback: str = "workflow") -> str:
    text = _FILENAME_SAFE.sub("-", (value or "").strip()).strip("-.")
    return (text or fallback)[:80]
