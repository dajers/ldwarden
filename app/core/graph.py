from __future__ import annotations

import copy
import re
from collections import deque
from typing import Any

from app.core.models import NodeSpec
from app.core.registry import NODE_SPECS, get_spec, validate_params

CRON_RE = re.compile(r"^\s*(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s*$")


def node_params(node: dict, spec: NodeSpec | None = None) -> dict:
    data = node.get("data") or {}
    if isinstance(data.get("params"), dict):
        return dict(data["params"])
    if spec is None:
        spec = get_spec(str(node.get("type") or ""))
    if spec is None:
        return {key: value for key, value in data.items() if key not in {"label", "disabled", "notes"}}
    return {param.name: data[param.name] for param in spec.params if param.name in data}


def normalize_graph(raw: Any) -> dict:
    if not isinstance(raw, dict):
        raise ValueError("Граф workflow должен быть объектом")
    nodes_raw = raw.get("nodes") or []
    edges_raw = raw.get("edges") or []
    if not isinstance(nodes_raw, list) or not isinstance(edges_raw, list):
        raise ValueError("nodes и edges должны быть массивами")

    nodes: list[dict] = []
    seen: set[str] = set()
    for index, item in enumerate(nodes_raw):
        if not isinstance(item, dict):
            raise ValueError(f"Нода #{index + 1} должна быть объектом")
        node_id = str(item.get("id") or "").strip()
        if not node_id:
            raise ValueError(f"У ноды #{index + 1} нет id")
        if node_id in seen:
            raise ValueError(f"Дублирующийся id ноды: {node_id}")
        seen.add(node_id)
        node_type = str(item.get("type") or "").strip()
        data = item.get("data") if isinstance(item.get("data"), dict) else {}
        data = copy.deepcopy(data)
        spec = get_spec(node_type)
        if spec:
            data.setdefault("label", spec.title)
            data["params"] = node_params(item, spec)
        position = item.get("position") if isinstance(item.get("position"), dict) else {}
        node = {
            "id": node_id,
            "type": node_type,
            "position": {
                "x": _number(position.get("x"), (index % 5) * 280),
                "y": _number(position.get("y"), (index // 5) * 180),
            },
            "data": data,
        }
        if item.get("width") is not None:
            node["width"] = item["width"]
        if item.get("height") is not None:
            node["height"] = item["height"]
        nodes.append(node)

    edges: list[dict] = []
    seen_edges: set[tuple] = set()
    for index, item in enumerate(edges_raw):
        if not isinstance(item, dict):
            raise ValueError(f"Связь #{index + 1} должна быть объектом")
        source = str(item.get("source") or "").strip()
        target = str(item.get("target") or "").strip()
        if not source or not target:
            raise ValueError(f"У связи #{index + 1} не указан source или target")
        source_handle = str(item.get("sourceHandle") or item.get("source_handle") or "out")
        target_handle = str(item.get("targetHandle") or item.get("target_handle") or "in")
        key = (source, source_handle, target, target_handle)
        if key in seen_edges:
            continue
        seen_edges.add(key)
        edges.append(
            {
                "id": str(item.get("id") or f"e-{source}-{source_handle}-{target}-{target_handle}"),
                "source": source,
                "sourceHandle": source_handle,
                "target": target,
                "targetHandle": target_handle,
                "type": item.get("type", "smoothstep"),
                "animated": bool(item.get("animated", False)),
                "label": item.get("label", ""),
            }
        )

    graph = {
        "nodes": nodes,
        "edges": edges,
        "viewport": raw.get("viewport") if isinstance(raw.get("viewport"), dict) else {"x": 0, "y": 0, "zoom": 1},
    }
    for key, value in raw.items():
        if key not in graph and key not in {"nodes", "edges"}:
            graph[key] = value
    return graph


def _number(value: Any, default: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return float(default)


def adjacency(graph: dict) -> tuple[dict[str, list[dict]], dict[str, list[dict]]]:
    outgoing: dict[str, list[dict]] = {node["id"]: [] for node in graph["nodes"]}
    incoming: dict[str, list[dict]] = {node["id"]: [] for node in graph["nodes"]}
    for edge in graph["edges"]:
        if edge["source"] in outgoing and edge["target"] in incoming:
            outgoing[edge["source"]].append(edge)
            incoming[edge["target"]].append(edge)
    return outgoing, incoming


def is_trigger(node: dict) -> bool:
    spec = get_spec(str(node.get("type") or ""))
    return bool(spec and spec.category == "trigger")


def find_cycles(graph: dict) -> list[list[str]]:
    """Return one or more cycles using Kahn's algorithm on the node graph."""
    outgoing, incoming = adjacency(graph)
    indegree = {node_id: len(edges) for node_id, edges in incoming.items()}
    queue = deque(sorted(node_id for node_id, degree in indegree.items() if degree == 0))
    visited: list[str] = []
    while queue:
        node_id = queue.popleft()
        visited.append(node_id)
        for edge in outgoing[node_id]:
            indegree[edge["target"]] -= 1
            if indegree[edge["target"]] == 0:
                queue.append(edge["target"])
    if len(visited) == len(indegree):
        return []
    remaining = [node_id for node_id, degree in indegree.items() if degree > 0]
    return [remaining]


def topological_order(graph: dict) -> list[str]:
    outgoing, incoming = adjacency(graph)
    indegree = {node_id: len(edges) for node_id, edges in incoming.items()}
    queue = deque(sorted(node_id for node_id, degree in indegree.items() if degree == 0))
    order: list[str] = []
    while queue:
        node_id = queue.popleft()
        order.append(node_id)
        for edge in outgoing[node_id]:
            indegree[edge["target"]] -= 1
            if indegree[edge["target"]] == 0:
                queue.append(edge["target"])
    if len(order) != len(indegree):
        raise ValueError("Граф содержит цикл")
    return order


def validate_graph(graph: Any) -> dict:
    errors: list[str] = []
    warnings: list[str] = []
    try:
        graph = normalize_graph(graph)
    except ValueError as exc:
        return {"valid": False, "errors": [str(exc)], "warnings": [], "graph": None, "stats": {}}

    nodes = graph["nodes"]
    edges = graph["edges"]
    if not nodes:
        errors.append("В workflow нет ни одной ноды")
    if not edges and len(nodes) > 1:
        warnings.append("Ноды не соединены связями")

    by_id = {node["id"]: node for node in nodes}
    triggers = [node for node in nodes if is_trigger(node)]
    if not triggers:
        errors.append("В workflow нет триггера: добавьте ноду запуска")
    if len(triggers) > 1:
        warnings.append("В workflow несколько триггеров: запуск начнётся с подходящего")
    if len(triggers) > 1 and all(node["type"] == "trigger.manual" for node in triggers):
        warnings.append("Несколько ручных триггеров создадут параллельные ветки")

    outgoing, incoming = adjacency(graph)
    for edge in edges:
        source = edge["source"]
        target = edge["target"]
        if source not in by_id:
            errors.append(f"Связь {edge['id']} ссылается на несуществующую ноду {source}")
            continue
        if target not in by_id:
            errors.append(f"Связь {edge['id']} ссылается на несуществующую ноду {target}")
            continue
        if source == target:
            errors.append(f"Нода {source} соединена сама с собой")
        source_spec = get_spec(str(by_id[source].get("type") or ""))
        target_spec = get_spec(str(by_id[target].get("type") or ""))
        if source_spec and edge["sourceHandle"] not in {handle.id for handle in source_spec.outputs}:
            errors.append(
                f"У ноды {source} нет выходного порта {edge['sourceHandle']} "
                f"(доступны: {', '.join(h.id for h in source_spec.outputs)})"
            )
        if target_spec and edge["targetHandle"] not in {handle.id for handle in target_spec.inputs}:
            errors.append(
                f"У ноды {target} нет входного порта {edge['targetHandle']} "
                f"(доступны: {', '.join(h.id for h in target_spec.inputs)})"
            )

    cycles = find_cycles(graph)
    if cycles:
        errors.append("Workflow содержит цикл: " + ", ".join(cycles[0]))

    for node in nodes:
        node_type = str(node.get("type") or "")
        spec = get_spec(node_type)
        if spec is None:
            errors.append(f"Неизвестный тип ноды: {node_type or '(пусто)'}")
            continue
        try:
            validate_params(spec, node_params(node, spec))
        except ValueError as exc:
            details = getattr(exc, "details", []) or []
            errors.append(f"Нода «{node['id']}» ({spec.title}): {exc}")
            errors.extend(f"  • {detail}" for detail in details)
        if spec.category == "trigger" and incoming.get(node["id"]):
            warnings.append(f"У триггера {node['id']} есть входящие связи — они игнорируются")
        if spec.category != "trigger" and not incoming.get(node["id"]):
            warnings.append(f"Нода {node['id']} ({spec.title}) недостижима: нет входящих связей")
        if node_type == "trigger.schedule":
            params = node_params(node, spec)
            if params.get("cron") and not CRON_RE.match(str(params["cron"])):
                errors.append(f"Нода {node['id']}: cron должен состоять из 5 полей")
        if spec.category == "notification":
            params = node_params(node, spec)
            if params.get("channel") == "webhook" and not params.get("url"):
                errors.append(f"Нода {node['id']}: для webhook нужен URL")
            if params.get("channel") == "telegram" and not (params.get("chat_id") and params.get("bot_token")):
                warnings.append(f"Нода {node['id']}: Telegram не настроен (нет chat_id/bot_token)")
            if params.get("channel") == "smtp" and not (params.get("to") and params.get("host")):
                warnings.append(f"Нода {node['id']}: SMTP не настроен (нет host/to)")

    reachable = set()
    if triggers:
        queue = deque(node["id"] for node in triggers)
        while queue:
            node_id = queue.popleft()
            if node_id in reachable:
                continue
            reachable.add(node_id)
            for edge in outgoing.get(node_id, []):
                queue.append(edge["target"])
    unreachable = sorted(set(by_id) - reachable)
    if triggers and unreachable:
        warnings.append("Недостижимые от триггера ноды: " + ", ".join(unreachable))

    stats = {
        "nodes": len(nodes),
        "edges": len(edges),
        "triggers": len(triggers),
        "by_category": _count_categories(nodes),
        "unreachable": unreachable,
    }
    return {"valid": not errors, "errors": errors, "warnings": warnings, "graph": graph, "stats": stats}


def _count_categories(nodes: list[dict]) -> dict[str, int]:
    result: dict[str, int] = {}
    for node in nodes:
        spec = get_spec(str(node.get("type") or ""))
        category = spec.category if spec else "unknown"
        result[category] = result.get(category, 0) + 1
    return dict(sorted(result.items()))


def graph_summary(graph: dict) -> dict:
    """Compact description stored on a run (no credentials, no large params)."""
    nodes = []
    for node in graph.get("nodes", []):
        spec = get_spec(str(node.get("type") or ""))
        nodes.append(
            {
                "id": node.get("id"),
                "type": node.get("type"),
                "title": spec.title if spec else node.get("type"),
                "category": spec.category if spec else "unknown",
                "disabled": bool((node.get("data") or {}).get("disabled")),
            }
        )
    return {
        "nodes": nodes,
        "edges": [
            {
                "source": edge.get("source"),
                "target": edge.get("target"),
                "sourceHandle": edge.get("sourceHandle", "out"),
            }
            for edge in graph.get("edges", [])
        ],
    }
