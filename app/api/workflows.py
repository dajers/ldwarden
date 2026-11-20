from __future__ import annotations

import json
import uuid

from flask import Blueprint, jsonify, request

from app.api.common import (
    ApiError,
    encrypt_workflow_secrets,
    engine,
    get_bool,
    json_body,
    parse_graph,
    serialize_workflow,
    settings,
    validate_graph_payload,
    validate_target,
    workflow_or_404,
)
from app.db import WorkflowRow, j_loads, utcnow
from app.services.templates import publish_workflow, unpublish_workflow

bp = Blueprint("workflows", __name__)


@bp.get("/workflows")
def list_workflows():
    include_templates = get_bool(request.args.get("include_templates"), False)
    templates_only = get_bool(request.args.get("templates_only"), False)
    limit = min(int(request.args.get("limit", 100)), 500)
    offset = max(int(request.args.get("offset", 0)), 0)
    query = WorkflowRow.select()
    if templates_only:
        query = query.where(WorkflowRow.published == True)
    elif not include_templates:
        query = query.where(WorkflowRow.published == False)
    rows = list(query.order_by(WorkflowRow.updated_at.desc()).limit(limit).offset(offset))
    return jsonify({"items": [serialize_workflow(row) for row in rows], "count": len(rows)})


@bp.post("/workflows")
def create_workflow():
    data = json_body()
    name = str(data.get("name") or "").strip()
    if not name:
        raise ApiError("Укажите название workflow", 400, "invalid_name")
    if len(name) > 160:
        raise ApiError("Название слишком длинное (максимум 160)", 400, "invalid_name")
    graph = parse_graph(data.get("graph") or {"nodes": [], "edges": []})
    graph = encrypt_workflow_secrets(graph)
    row = WorkflowRow.create(
        id="wf-" + uuid.uuid4().hex[:12],
        name=name,
        description=str(data.get("description") or "")[:4000],
        graph=json.dumps(graph, ensure_ascii=False),
        is_template=False,
        published=False,
        version=1,
        owner=str(data.get("owner") or "local")[:80],
    )
    return jsonify(serialize_workflow(row)), 201


@bp.get("/workflows/<workflow_id>")
def get_workflow(workflow_id: str):
    row = workflow_or_404(workflow_id)
    return jsonify(serialize_workflow(row))


@bp.put("/workflows/<workflow_id>")
def update_workflow(workflow_id: str):
    row = workflow_or_404(workflow_id)
    data = json_body()
    old_graph = j_loads(row.graph, {"nodes": [], "edges": []})
    if "name" in data:
        name = str(data.get("name") or "").strip()
        if not name:
            raise ApiError("Название не может быть пустым", 400, "invalid_name")
        row.name = name[:160]
    if "description" in data:
        row.description = str(data.get("description") or "")[:4000]
    if "graph" in data:
        graph = parse_graph(data.get("graph") or {"nodes": [], "edges": []})
        graph = encrypt_workflow_secrets(graph, old_graph=old_graph)
        row.graph = json.dumps(graph, ensure_ascii=False)
        row.version = int(row.version or 1) + 1
    row.updated_at = utcnow()
    row.save()
    return jsonify(serialize_workflow(row))


@bp.delete("/workflows/<workflow_id>")
def delete_workflow(workflow_id: str):
    row = workflow_or_404(workflow_id)
    if row.is_template and row.id.startswith("tpl-"):
        raise ApiError(
            "Встроенный шаблон нельзя удалить; снимите публикацию или сделайте копию",
            409,
            "builtin_template",
        )
    row.delete_instance()
    return jsonify({"deleted": workflow_id})


@bp.post("/workflows/validate")
def validate_draft():
    data = json_body()
    report = validate_graph_payload(data.get("graph") or {"nodes": [], "edges": []})
    graph = report.pop("graph", None)
    if graph is not None:
        report["stats"]["node_ids"] = [node["id"] for node in graph["nodes"]]
    return jsonify(report)


@bp.post("/workflows/<workflow_id>/validate")
def validate_workflow(workflow_id: str):
    row = workflow_or_404(workflow_id)
    graph = j_loads(row.graph, {"nodes": [], "edges": []})
    report = validate_graph_payload(graph)
    report.pop("graph", None)
    return jsonify(report)


@bp.post("/workflows/<workflow_id>/duplicate")
def duplicate_workflow(workflow_id: str):
    row = workflow_or_404(workflow_id)
    data = json_body(required=False)
    new_name = str(data.get("name") or f"Копия: {row.name}")[:160]
    copy_row = WorkflowRow.create(
        id="wf-" + uuid.uuid4().hex[:12],
        name=new_name,
        description=row.description,
        graph=row.graph,
        is_template=False,
        published=False,
        version=1,
        owner="local",
    )
    return jsonify(serialize_workflow(copy_row)), 201


@bp.post("/workflows/<workflow_id>/publish")
def publish(workflow_id: str):
    row = publish_workflow(workflow_id)
    return jsonify(serialize_workflow(row))


@bp.delete("/workflows/<workflow_id>/publish")
def unpublish(workflow_id: str):
    row = unpublish_workflow(workflow_id)
    return jsonify(serialize_workflow(row))


@bp.get("/workflows/<workflow_id>/export")
def export_workflow(workflow_id: str):
    row = workflow_or_404(workflow_id)
    data = serialize_workflow(row)
    data["exported_at"] = utcnow().isoformat() + "Z"
    return (
        json.dumps(data, ensure_ascii=False, indent=2),
        200,
        {
            "Content-Type": "application/json; charset=utf-8",
            "Content-Disposition": f'attachment; filename="{row.id}.json"',
        },
    )


@bp.post("/workflows/<workflow_id>/runs")
def run_workflow(workflow_id: str):
    row = workflow_or_404(workflow_id)
    data = json_body(required=False)
    target = validate_target(data.get("target"))
    wait = bool(data.get("wait", False))
    trigger = str(data.get("trigger") or "manual")
    ci_mode = bool(data.get("ci_mode", False))
    run_params = data.get("params") if isinstance(data.get("params"), dict) else {}
    run = engine().start_run(
        row.to_dict(),
        trigger=trigger,
        target=target,
        wait=wait,
        ci_mode=ci_mode,
        run_params=run_params,
    )
    status = 200 if wait else 202
    return jsonify(run), status
