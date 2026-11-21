from __future__ import annotations

import copy
import json
from functools import wraps
from pathlib import Path
from typing import Any

from flask import current_app, g, request

from app.config import Settings
from app.core.graph import normalize_graph, validate_graph
from app.core.registry import get_spec
from app.crypto import MASK, SecretBox, mask_value
from app.db import WorkflowRow

MASK_VALUES = {MASK, "••••••", "***", "********", "<unchanged>"}
PUBLIC_PATHS = {"/api/health", "/api/meta", "/api/openapi.json"}


class ApiError(Exception):
    def __init__(self, message: str, status: int = 400, code: str = "bad_request", details: Any = None):
        super().__init__(message)
        self.message = message
        self.status = status
        self.code = code
        self.details = details


def settings() -> Settings:
    return current_app.extensions["ldwarden_settings"]


def engine():
    return current_app.extensions["ldwarden_engine"]


def source_service():
    return current_app.extensions["ldwarden_source_service"]


def telegram_service():
    return current_app.extensions["ldwarden_telegram"]


def library_service():
    return current_app.extensions["ldwarden_library"]


def secret_box() -> SecretBox:
    return current_app.extensions["ldwarden_secret_box"]


def json_body(required: bool = True) -> dict:
    data = request.get_json(silent=True)
    if data is None:
        if required:
            raise ApiError("Ожидался JSON-объект в теле запроса", 400, "invalid_json")
        return {}
    if not isinstance(data, dict):
        raise ApiError("Тело запроса должно быть JSON-объектом", 400, "invalid_json")
    return data


def workflow_or_404(workflow_id: str) -> WorkflowRow:
    row = WorkflowRow.get_or_none(WorkflowRow.id == workflow_id)
    if row is None:
        raise ApiError("Workflow не найден", 404, "not_found")
    return row


def parse_graph(payload: Any) -> dict:
    if not isinstance(payload, dict):
        raise ApiError("graph должен быть объектом с nodes и edges", 400, "invalid_graph")
    try:
        graph = normalize_graph(payload)
    except ValueError as exc:
        raise ApiError(str(exc), 400, "invalid_graph") from exc
    report = validate_graph(graph)
    if not report["valid"]:
        raise ApiError(
            "Workflow не прошёл валидацию",
            400,
            "invalid_graph",
            {"errors": report["errors"], "warnings": report["warnings"]},
        )
    return report["graph"]


def validate_graph_payload(payload: dict) -> dict:
    try:
        graph = normalize_graph(payload)
    except ValueError as exc:
        raise ApiError(str(exc), 400, "invalid_graph") from exc
    return validate_graph(graph)


def _old_params(old_graph: dict | None) -> dict[str, dict]:
    result: dict[str, dict] = {}
    for node in (old_graph or {}).get("nodes", []):
        params = (node.get("data") or {}).get("params")
        if isinstance(params, dict):
            result[node.get("id")] = params
    return result


def encrypt_workflow_secrets(graph: dict, old_graph: dict | None = None) -> dict:
    """Encrypt secret node params, preserving old values on masked updates."""
    box = secret_box()
    old = _old_params(old_graph)
    result = copy.deepcopy(graph)
    for node in result.get("nodes", []):
        spec = get_spec(node.get("type", ""))
        if spec is None:
            continue
        data = node.setdefault("data", {})
        params = data.get("params") if isinstance(data.get("params"), dict) else {}
        old_params = old.get(node.get("id"), {})
        for param in spec.params:
            if not (param.secret or param.type == "secret"):
                continue
            if param.name in params:
                value = params[param.name]
                if isinstance(value, str) and value in MASK_VALUES:
                    if isinstance(old_params.get(param.name), str) and old_params[param.name]:
                        params[param.name] = old_params[param.name]
                    else:
                        params[param.name] = ""
                elif value is None or value == "":
                    params[param.name] = ""
                elif isinstance(value, str) and value.startswith("enc:v1:"):
                    params[param.name] = value
                else:
                    params[param.name] = box.encrypt(str(value))
            elif isinstance(old_params.get(param.name), str) and old_params[param.name]:
                params[param.name] = old_params[param.name]
        data["params"] = params
        data.pop("secret_meta", None)
    return result


def mask_graph(graph: dict) -> dict:
    """Return a copy safe for the browser: no encrypted blobs, no plaintext."""
    box = secret_box()
    result = copy.deepcopy(graph)
    for node in result.get("nodes", []):
        spec = get_spec(node.get("type", ""))
        if spec is None:
            continue
        data = node.get("data") or {}
        params = data.get("params") if isinstance(data.get("params"), dict) else {}
        meta = {}
        for param in spec.params:
            if not (param.secret or param.type == "secret"):
                continue
            value = params.get(param.name)
            if value:
                try:
                    preview = mask_value(box.decrypt(value))
                except Exception:
                    preview = "…"
                meta[param.name] = {"has_value": True, "preview": preview}
                params[param.name] = MASK
            else:
                meta[param.name] = {"has_value": False, "preview": ""}
                params[param.name] = ""
        data["params"] = params
        data["secret_meta"] = meta
        node["data"] = data
    return result


def serialize_workflow(row: WorkflowRow) -> dict:
    data = row.to_dict(include_graph=False)
    graph = row.to_dict(include_graph=True).get("graph", {"nodes": [], "edges": []})
    data["graph"] = mask_graph(graph)
    data["node_count"] = len(graph.get("nodes", []))
    data["edge_count"] = len(graph.get("edges", []))
    return data


def validate_target(target: Any) -> dict | str | None:
    if target is None or target == "":
        return None
    if isinstance(target, str):
        target = {"kind": "path", "path": target}
    if not isinstance(target, dict):
        raise ApiError("target должен быть строкой или объектом", 400, "invalid_target")
    kind = str(target.get("kind") or "path").lower()
    if kind not in {"default", "path", "source", "git"}:
        raise ApiError(f"Неизвестный тип источника: {kind}", 400, "invalid_target")
    settings_ = settings()
    if kind == "path":
        raw = target.get("path") or str(settings_.default_target)
        try:
            settings_.resolve_allowed_path(raw)
        except PermissionError as exc:
            raise ApiError(str(exc), 403, "forbidden_target") from exc
        except OSError as exc:
            raise ApiError(f"Некорректный путь: {exc}", 400, "invalid_target") from exc
    if kind == "source":
        source_id = str(target.get("id") or target.get("source_id") or "")
        try:
            root = settings_.source_dir(source_id)
        except ValueError as exc:
            raise ApiError(str(exc), 400, "invalid_target") from exc
        if not root.exists():
            raise ApiError("Загруженный источник не найден", 404, "not_found")
    if kind == "git":
        from urllib.parse import urlparse

        if not settings_.allowed_git_hosts:
            raise ApiError(
                "Клонирование Git отключено: задайте LDWARDEN_ALLOWED_GIT_HOSTS",
                403,
                "git_disabled",
            )
        url = str(target.get("url") or "")
        parsed = urlparse(url)
        if parsed.scheme != "https" or not parsed.hostname:
            raise ApiError("Разрешены только HTTPS-ссылки на Git-репозитории", 400, "invalid_target")
        if parsed.username or parsed.password:
            raise ApiError("Учётные данные в URL запрещены; задайте LDWARDEN_GIT_TOKEN", 400, "invalid_target")
        if parsed.hostname.lower() not in {host.lower() for host in settings_.allowed_git_hosts}:
            raise ApiError(f"Хост {parsed.hostname} не входит в allow-list", 403, "forbidden_git_host")
    return target


def require_api_token(settings_: Settings, path: str) -> None:
    token = settings_.api_token
    if not token:
        return
    if (
        path in PUBLIC_PATHS
        or path.startswith("/api/hooks/")
        or path.startswith("/api/dev/inbox")
        or path.startswith("/api/ci/")
    ):
        return
    provided = request.headers.get("Authorization", "")
    if provided.lower().startswith("bearer "):
        provided = provided[7:].strip()
    if not provided:
        provided = request.headers.get("X-API-Token", "")
    if not provided or provided != token:
        raise ApiError("Требуется API-токен", 401, "unauthorized")


def check_ci_token(settings_: Settings) -> None:
    expected = settings_.ci_token or settings_.api_token
    if not expected:
        return
    provided = request.headers.get("X-CI-Token", "")
    if not provided:
        auth = request.headers.get("Authorization", "")
        if auth.lower().startswith("bearer "):
            provided = auth[7:].strip()
    if not provided or provided != expected:
        raise ApiError("Требуется CI-токен", 401, "unauthorized")


def with_errors(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except ApiError:
            raise
        except LookupError as exc:
            raise ApiError(str(exc), 404, "not_found") from exc
        except PermissionError as exc:
            raise ApiError(str(exc), 403, "forbidden") from exc
        except ValueError as exc:
            raise ApiError(str(exc), 400, "bad_request") from exc

    return wrapper


def parse_csv(value: str | None) -> list[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def get_bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return value.lower() in {"1", "true", "yes", "on"}


def base_dir() -> Path:
    return settings().base_dir
