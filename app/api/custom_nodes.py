from __future__ import annotations

import json

from flask import Blueprint, Response, jsonify

from app.api.common import ApiError, json_body, settings
from app.services import custom_nodes as service

bp = Blueprint("custom_nodes", __name__)


def _node_or_404(node_id: str) -> dict:
    definition = service.get_definition(node_id)
    if definition is None:
        raise ApiError("Нода не найдена", 404, "not_found")
    return definition


@bp.get("/custom-nodes")
def custom_nodes_list():
    return jsonify({"items": service.list_definitions()})


@bp.post("/custom-nodes")
def custom_nodes_create():
    try:
        definition = service.create_definition(json_body())
    except service.CustomNodeError as exc:
        raise ApiError(str(exc), 400, "invalid_node") from exc
    return jsonify(definition), 201


@bp.get("/custom-nodes/<node_id>")
def custom_nodes_get(node_id: str):
    return jsonify(_node_or_404(node_id))


@bp.put("/custom-nodes/<node_id>")
def custom_nodes_update(node_id: str):
    _node_or_404(node_id)
    try:
        definition = service.update_definition(node_id, json_body())
    except service.CustomNodeError as exc:
        raise ApiError(str(exc), 400, "invalid_node") from exc
    return jsonify(definition)


@bp.delete("/custom-nodes/<node_id>")
def custom_nodes_delete(node_id: str):
    _node_or_404(node_id)
    service.delete_definition(node_id)
    return jsonify({"deleted": True})


@bp.post("/custom-nodes/<node_id>/test")
def custom_nodes_test(node_id: str):
    _node_or_404(node_id)
    data = json_body(required=False)
    params = data.get("params") if isinstance(data.get("params"), dict) else data
    result = service.test_definition(node_id, params, settings())
    return jsonify(result), (200 if result.get("ok") else 400)


@bp.get("/custom-nodes/<node_id>/export")
def custom_nodes_export(node_id: str):
    definition = service.export_definition(node_id)
    payload = json.dumps(definition, ensure_ascii=False, indent=2)
    return Response(
        payload,
        headers={
            "Content-Type": "application/json; charset=utf-8",
            "Content-Disposition": f'attachment; filename="{node_id}.node.json"',
        },
    )


@bp.post("/custom-nodes/import")
def custom_nodes_import():
    try:
        definition = service.import_definition(json_body())
    except service.CustomNodeError as exc:
        raise ApiError(str(exc), 400, "invalid_node") from exc
    return jsonify(definition), 201


@bp.get("/settings/network")
def network_get():
    return jsonify(service.get_network_rules())


@bp.put("/settings/network")
def network_put():
    try:
        rules = service.save_network_rules(json_body())
    except service.CustomNodeError as exc:
        raise ApiError(str(exc), 400, "invalid_network") from exc
    return jsonify(rules)
