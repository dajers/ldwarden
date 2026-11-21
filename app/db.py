from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from typing import Any

from peewee import (
    AutoField,
    BooleanField,
    CharField,
    DateTimeField,
    IntegerField,
    Model,
    SqliteDatabase,
    TextField,
)

from app.config import Settings


db = SqliteDatabase(None, pragmas={"journal_mode": "wal", "foreign_keys": 1, "busy_timeout": 5000})
_db_lock = threading.Lock()
_initialized = False


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def j_dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), default=str)


def j_loads(value: str | None, default: Any = None) -> Any:
    if not value:
        return default
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return default


class BaseModel(Model):
    class Meta:
        database = db


class WorkflowRow(BaseModel):
    id = CharField(primary_key=True)
    name = CharField()
    description = TextField(default="")
    graph = TextField(default="{}")
    is_template = BooleanField(default=False)
    published = BooleanField(default=False)
    published_at = DateTimeField(null=True)
    version = IntegerField(default=1)
    owner = CharField(default="local")
    created_at = DateTimeField(default=utcnow)
    updated_at = DateTimeField(default=utcnow)

    def to_dict(self, include_graph: bool = True) -> dict:
        data = {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "is_template": bool(self.is_template),
            "published": bool(self.published),
            "published_at": iso(self.published_at),
            "version": self.version,
            "owner": self.owner,
            "created_at": iso(self.created_at),
            "updated_at": iso(self.updated_at),
        }
        if include_graph:
            data["graph"] = j_loads(self.graph, {"nodes": [], "edges": []})
        return data


class RunRow(BaseModel):
    id = CharField(primary_key=True)
    workflow_id = CharField(null=True)
    workflow_name = CharField(default="")
    status = CharField(default="queued")
    trigger = CharField(default="manual")
    target = TextField(default="")
    source_label = CharField(default="")
    started_at = DateTimeField(null=True)
    finished_at = DateTimeField(null=True)
    duration_ms = IntegerField(null=True)
    error = TextField(default="")
    summary = TextField(default="{}")
    ai = TextField(default="")
    gate = TextField(default="")
    report_md = TextField(default="")
    report_json = TextField(default="")
    report_sarif = TextField(default="")
    ci_mode = BooleanField(default=False)
    created_at = DateTimeField(default=utcnow)

    def to_dict(self, include_reports: bool = False) -> dict:
        data = {
            "id": self.id,
            "workflow_id": self.workflow_id,
            "workflow_name": self.workflow_name,
            "status": self.status,
            "trigger": self.trigger,
            "target": self.target,
            "source_label": self.source_label,
            "started_at": iso(self.started_at),
            "finished_at": iso(self.finished_at),
            "duration_ms": self.duration_ms,
            "error": self.error,
            "summary": j_loads(self.summary, {}),
            "gate": j_loads(self.gate, None),
            "ai": j_loads(self.ai, None),
            "ci_mode": bool(self.ci_mode),
            "created_at": iso(self.created_at),
            "reports": {
                "markdown": bool(self.report_md),
                "json": bool(self.report_json),
                "sarif": bool(self.report_sarif),
            },
        }
        if include_reports:
            data["report_markdown"] = self.report_md
            data["report_json"] = j_loads(self.report_json, {})
            data["report_sarif"] = j_loads(self.report_sarif, {})
        return data


class RunEventRow(BaseModel):
    id = AutoField()
    run_id = CharField(index=True)
    seq = IntegerField()
    ts = DateTimeField(default=utcnow)
    type = CharField()
    level = CharField(default="info")
    node_id = CharField(null=True)
    message = TextField(default="")
    payload = TextField(default="{}")

    class Meta:
        indexes = ((("run_id", "seq"), True),)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "run_id": self.run_id,
            "seq": self.seq,
            "ts": iso(self.ts),
            "type": self.type,
            "level": self.level,
            "node_id": self.node_id,
            "message": self.message,
            "payload": j_loads(self.payload, {}),
        }


class FindingRow(BaseModel):
    id = AutoField()
    run_id = CharField(index=True)
    node_id = CharField(null=True)
    fingerprint = CharField(index=True)
    category = CharField()
    class_code = CharField(column_name="class")
    rule_id = CharField(default="")
    severity = CharField(default="MEDIUM")
    path = CharField()
    line = IntegerField(default=1)
    end_line = IntegerField(null=True)
    message = TextField(default="")
    description = TextField(default="")
    remediation = TextField(default="")
    cwe = CharField(null=True)
    evidence = TextField(default="")
    confidence = CharField(default="0.8")
    detector = CharField(default="")
    extra = TextField(default="{}")
    created_at = DateTimeField(default=utcnow)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "run_id": self.run_id,
            "node_id": self.node_id,
            "fingerprint": self.fingerprint,
            "category": self.category,
            "class": self.class_code,
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
            "confidence": float(self.confidence or 0.8),
            "detector": self.detector,
            "extra": j_loads(self.extra, {}),
        }


class TelegramLinkRow(BaseModel):
    id = AutoField()
    chat_id = CharField()
    chat_title = CharField(default="")
    chat_type = CharField(default="")
    username = CharField(default="")
    linked_at = DateTimeField(default=utcnow)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "chat_id": self.chat_id,
            "chat_title": self.chat_title,
            "chat_type": self.chat_type,
            "username": self.username,
            "linked_at": iso(self.linked_at),
        }


class ScheduleStateRow(BaseModel):
    id = AutoField()
    workflow_id = CharField()
    node_id = CharField()
    last_fired_at = DateTimeField(null=True)

    class Meta:
        indexes = ((("workflow_id", "node_id"), True),)


class CustomNodeRow(BaseModel):
    id = CharField(primary_key=True)
    name = CharField()
    kind = CharField(default="http")
    version = IntegerField(default=1)
    spec = TextField(default="{}")
    runtime = TextField(default="{}")
    created_at = DateTimeField(default=utcnow)
    updated_at = DateTimeField(default=utcnow)


class AppSettingRow(BaseModel):
    key = CharField(primary_key=True)
    value = TextField(default="")
    updated_at = DateTimeField(default=utcnow)


class InboxMessageRow(BaseModel):
    id = AutoField()
    run_id = CharField(null=True)
    channel = CharField(default="webhook")
    target = CharField(default="")
    subject = CharField(default="")
    body = TextField(default="")
    headers = TextField(default="{}")
    status = CharField(default="received")
    created_at = DateTimeField(default=utcnow)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "run_id": self.run_id,
            "channel": self.channel,
            "target": self.target,
            "subject": self.subject,
            "body": self.body,
            "headers": j_loads(self.headers, {}),
            "status": self.status,
            "created_at": iso(self.created_at),
        }


MODELS = [
    WorkflowRow,
    RunRow,
    RunEventRow,
    FindingRow,
    TelegramLinkRow,
    ScheduleStateRow,
    InboxMessageRow,
    CustomNodeRow,
    AppSettingRow,
]


def init_db(settings: Settings, reset: bool = False) -> None:
    """Initialise the database, create tables and seed built-in templates."""
    global _initialized
    with _db_lock:
        settings.ensure_dirs()
        if db.is_closed():
            db.init(str(settings.db_path))
            db.connect(reuse_if_open=True)
        elif db.database != str(settings.db_path):
            db.close()
            db.init(str(settings.db_path))
            db.connect(reuse_if_open=True)
        if reset:
            db.drop_tables(MODELS, safe=True)
        db.create_tables(MODELS, safe=True)
        _initialized = True
        if settings.seed_templates:
            _seed_templates(settings)


def close_db() -> None:
    global _initialized
    with _db_lock:
        if not db.is_closed():
            db.close()
        _initialized = False


def _seed_templates(settings: Settings) -> None:

    import app.nodes
    from app.services.templates import seed_builtin_templates

    try:
        seed_builtin_templates(settings)
    except Exception:
        import logging

        logging.getLogger(__name__).exception("Не удалось загрузить встроенные шаблоны")


def reset_db(settings: Settings) -> None:
    init_db(settings, reset=True)
