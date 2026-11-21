from __future__ import annotations

import json

from flask import Blueprint, jsonify, request

from app.api.common import (
    ApiError,
    json_body,
    library_service,
    mask_graph,
    parse_graph,
    workflow_or_404,
)
from app.db import j_loads
from app.services.library import LibraryError

bp = Blueprint("library", __name__)


@bp.get("/library/status")
def library_status():
    return jsonify(library_service().status())


@bp.get("/library")
def library_index():
    service = library_service()
    try:
        force = str(request.args.get("refresh") or "").lower() in {"1", "true", "yes"}
        data = service.list_presets(force=force)
    except LibraryError as exc:
        raise ApiError(str(exc), 502, "library_error") from exc
    for item in data.get("items", []):
        item["graph"] = mask_graph(item["graph"])
    return jsonify(data)


@bp.post("/library/publish")
def library_publish():
    data = json_body()
    workflow_id = str(data.get("workflow_id") or "").strip()
    if workflow_id:
        row = workflow_or_404(workflow_id)
        graph = j_loads(row.graph, {"nodes": [], "edges": []})
        name = str(data.get("name") or row.name)
        description = str(data.get("description") or row.description or "")
        author = str(data.get("author") or row.owner or "local")
    else:
        payload = data.get("graph")
        if not isinstance(payload, dict):
            raise ApiError("Передайте workflow_id или graph", 400, "missing_workflow")
        graph = parse_graph(payload)
        name = str(data.get("name") or "LDWarden preset")
        description = str(data.get("description") or "")
        author = str(data.get("author") or "local")
    raw_tags = data.get("tags") or []
    if isinstance(raw_tags, str):
        raw_tags = raw_tags.split(",")
    tags = [str(tag).strip() for tag in raw_tags if str(tag).strip()] if isinstance(raw_tags, list) else []
    try:
        result = library_service().publish(
            mask_graph(graph),
            name=name,
            description=description,
            tags=tags,
            author=author,
        )
    except LibraryError as exc:
        raise ApiError(str(exc), 502, "library_error") from exc
    return jsonify(result), 201
