from __future__ import annotations

import json
import time
from datetime import datetime

from flask import Blueprint, Response, jsonify, request

from app.api.common import ApiError, engine, get_bool
from app.db import FindingRow, RunEventRow, RunRow, j_loads

bp = Blueprint("runs", __name__)

TERMINAL_STATUSES = {"success", "failed", "cancelled"}


def _run_or_404(run_id: str) -> RunRow:
    run = RunRow.get_or_none(RunRow.id == run_id)
    if run is None:
        raise ApiError("Запуск не найден", 404, "not_found")
    return run


@bp.get("/runs")
def list_runs():
    query = RunRow.select()
    workflow_id = request.args.get("workflow_id")
    if workflow_id:
        query = query.where(RunRow.workflow_id == workflow_id)
    status = request.args.get("status")
    if status:
        query = query.where(RunRow.status == status)
    limit = min(int(request.args.get("limit", 50)), 500)
    offset = max(int(request.args.get("offset", 0)), 0)
    rows = list(query.order_by(RunRow.created_at.desc()).limit(limit).offset(offset))
    return jsonify({"items": [row.to_dict() for row in rows], "count": len(rows)})


@bp.get("/runs/<run_id>")
def get_run(run_id: str):
    run = _run_or_404(run_id)
    include_reports = get_bool(request.args.get("reports"), False)
    data = run.to_dict(include_reports=include_reports)
    data["findings_count"] = (data.get("summary") or {}).get("findings", {}).get("total", 0)
    return jsonify(data)


@bp.get("/runs/<run_id>/status")
def run_status(run_id: str):
    run = _run_or_404(run_id)
    summary = j_loads(run.summary, {})
    gate = j_loads(run.gate, None)
    findings = summary.get("findings", {})
    return jsonify(
        {
            "id": run.id,
            "status": run.status,
            "exit_code": 0 if run.status == "success" else (2 if run.status == "cancelled" else 1),
            "gate": gate,
            "counts": findings.get("by_severity"),
            "max_severity": findings.get("max_severity"),
            "started_at": run.to_dict().get("started_at"),
            "finished_at": run.to_dict().get("finished_at"),
            "duration_ms": run.duration_ms,
            "error": run.error,
        }
    )


@bp.post("/runs/<run_id>/cancel")
def cancel_run(run_id: str):
    _run_or_404(run_id)
    cancelled = engine().cancel(run_id)
    return jsonify({"run_id": run_id, "cancelled": cancelled})


@bp.get("/runs/<run_id>/nodes")
def run_nodes(run_id: str):
    run = _run_or_404(run_id)
    summary = j_loads(run.summary, {})
    return jsonify({"items": summary.get("nodes", {}), "status": run.status})


@bp.get("/runs/<run_id>/events")
def run_events(run_id: str):
    run = _run_or_404(run_id)
    after = max(int(request.args.get("after", 0)), 0)
    limit = min(int(request.args.get("limit", 500)), 2000)
    rows = list(
        RunEventRow.select()
        .where((RunEventRow.run_id == run_id) & (RunEventRow.seq > after))
        .order_by(RunEventRow.seq)
        .limit(limit)
    )
    items = [row.to_dict() for row in rows]
    next_cursor = items[-1]["seq"] if items else after
    return jsonify(
        {
            "items": items,
            "next_cursor": next_cursor,
            "run_status": run.status,
            "finished": run.status in TERMINAL_STATUSES,
        }
    )


@bp.get("/runs/<run_id>/stream")
def stream_events(run_id: str):
    _run_or_404(run_id)
    after = max(int(request.args.get("after", 0)), 0)

    def generate():
        cursor = after
        started = time.monotonic()
        last_ping = time.monotonic()
        while True:
            if time.monotonic() - started > 600:
                break
            rows = list(
                RunEventRow.select()
                .where((RunEventRow.run_id == run_id) & (RunEventRow.seq > cursor))
                .order_by(RunEventRow.seq)
                .limit(200)
            )
            for row in rows:
                cursor = row.seq
                payload = {
                    "seq": row.seq,
                    "ts": row.to_dict().get("ts"),
                    "type": row.type,
                    "level": row.level,
                    "node_id": row.node_id,
                    "message": row.message,
                    "payload": j_loads(row.payload, {}),
                }
                yield f"id: {row.seq}\nevent: {row.type}\ndata: {json.dumps(payload, ensure_ascii=False)}\n\n"
            run = RunRow.get_or_none(RunRow.id == run_id)
            if run is None:
                break
            if run.status in TERMINAL_STATUSES and not rows:
                break
            if time.monotonic() - last_ping > 15:
                yield ": ping\n\n"
                last_ping = time.monotonic()
            time.sleep(0.35)

    return Response(
        generate(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


@bp.get("/runs/<run_id>/findings")
def run_findings(run_id: str):
    _run_or_404(run_id)
    query = FindingRow.select().where(FindingRow.run_id == run_id)
    category = request.args.get("category")
    if category:
        query = query.where(FindingRow.category == category.upper())
    severity = request.args.get("severity")
    if severity:
        query = query.where(FindingRow.severity == severity.upper())
    class_code = request.args.get("class")
    if class_code:
        query = query.where(FindingRow.class_code == class_code)
    path = request.args.get("path")
    if path:
        query = query.where(FindingRow.path.contains(path))
    limit = min(int(request.args.get("limit", 500)), 2000)
    offset = max(int(request.args.get("offset", 0)), 0)
    rows = list(
        query.order_by(FindingRow.line, FindingRow.path).limit(limit).offset(offset)
    )
    return jsonify({"items": [row.to_dict() for row in rows], "count": len(rows)})


@bp.get("/runs/<run_id>/report")
def run_report(run_id: str):
    run = _run_or_404(run_id)
    fmt = (request.args.get("format") or "md").lower()
    if fmt in {"markdown", "md"}:
        content, mime, ext = run.report_md, "text/markdown; charset=utf-8", "md"
    elif fmt == "json":
        content, mime, ext = run.report_json, "application/json; charset=utf-8", "json"
    elif fmt == "sarif":
        content, mime, ext = run.report_sarif, "application/json; charset=utf-8", "sarif"
    else:
        raise ApiError("format должен быть md, json или sarif", 400, "invalid_format")
    if not content:
        raise ApiError("Отчёт ещё не сформирован", 404, "report_not_ready")
    headers = {"Content-Type": mime}
    if get_bool(request.args.get("download"), False):
        headers["Content-Disposition"] = f'attachment; filename="ldwarden-{run_id}.{ext}"'
    return Response(content, headers=headers)


@bp.get("/runs/<run_id>/ai")
def run_ai(run_id: str):
    run = _run_or_404(run_id)
    data = j_loads(run.ai, None)
    if not data:
        raise ApiError("AI-анализ для этого запуска отсутствует", 404, "not_found")
    return jsonify(data)


@bp.get("/runs/<run_id>/log")
def run_log(run_id: str):
    """Plain-text execution log for a copy-paste into an incident ticket."""
    _run_or_404(run_id)
    rows = (
        RunEventRow.select()
        .where(RunEventRow.run_id == run_id)
        .order_by(RunEventRow.seq)
    )
    lines = []
    for row in rows:
        ts = row.to_dict().get("ts") or ""
        node = f"[{row.node_id}] " if row.node_id else ""
        lines.append(f"{ts} {row.level.upper():7s} {node}{row.type}: {row.message}")
    return Response("\n".join(lines), mimetype="text/plain; charset=utf-8")
