from __future__ import annotations

ANALYSIS_SCHEMA = {
    "type": "object",
    "required": ["summary", "findings"],
    "additionalProperties": False,
    "properties": {
        "summary": {"type": "string", "minLength": 1},
        "overall_risk": {"type": "string", "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW"]},
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["finding_id", "explanation"],
                "additionalProperties": False,
                "properties": {
                    "finding_id": {"type": "string", "minLength": 1},
                    "explanation": {"type": "string", "minLength": 1},
                    "remediation": {"type": "string"},
                    "severity_assessment": {"type": "string"},
                    "confidence": {"type": "number", "minimum": 0, "maximum": 1},
                },
            },
        },
        "next_steps": {"type": "array", "items": {"type": "string"}},
    },
}

PLANNER_SCHEMA = {
    "type": "object",
    "required": ["name", "nodes", "edges"],
    "additionalProperties": False,
    "properties": {
        "name": {"type": "string"},
        "description": {"type": "string"},
        "nodes": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["id", "type"],
                "additionalProperties": True,
                "properties": {
                    "id": {"type": "string"},
                    "type": {"type": "string"},
                    "label": {"type": "string"},
                    "params": {"type": "object"},
                },
            },
        },
        "edges": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["source", "target"],
                "additionalProperties": True,
                "properties": {
                    "source": {"type": "string"},
                    "target": {"type": "string"},
                    "sourceHandle": {"type": "string"},
                    "targetHandle": {"type": "string"},
                },
            },
        },
    },
}
