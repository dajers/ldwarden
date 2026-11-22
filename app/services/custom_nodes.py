"""Кастомные ноды: HTTP, AI и композитные.

Определения хранятся в БД, регистрируются в общем реестре нод и потому
работают в движке, валидации, экспорте и «Процессах» так же, как встроенные.
"""

from __future__ import annotations

import json
import re
import uuid
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx

from app.core.models import Finding, HandleSpec, NodeResult, NodeSpec, ParamSpec, severity_counts
from app.core.registry import get_spec, register_custom, unregister_custom
from app.db import AppSettingRow, CustomNodeRow, j_dumps, j_loads, utcnow
from app.nodes.base import BaseNode, NodeError

CUSTOM_PREFIX = "custom-"
SCHEMA = "ldwarden.node.v1"
DEFAULT_ICON = "box"
DEFAULT_COLOR = "#8b5cf6"
KINDS = {"http", "ai", "composite"}
PARAM_TYPES = {"string", "text", "number", "select", "boolean", "secret", "json", "keyvalue"}
PORT_KINDS = {"exec", "data"}
HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"}
AI_PROVIDERS = {"auto", "local", "openai", "ollama", "universal"}
SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
CATEGORIES = {"CUSTOM", "SECRET", "SCA", "SAST"}

DEFAULT_NETWORK = {
    "allow_hosts": ["api.github.com", "raw.githubusercontent.com", "127.0.0.1"],
    "timeout": 20,
    "max_bytes": 1_048_576,
    "max_redirects": 3,
    "max_requests_per_run": 20,
}


class CustomNodeError(ValueError):
    pass


def _text(value: Any, limit: int = 0) -> str:
    result = str(value or "").strip()
    return result[:limit] if limit else result


def _bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _port(port: dict, is_input: bool, index: int) -> dict:
    if not isinstance(port, dict):
        raise CustomNodeError("Порт должен быть объектом")
    port_id = _text(port.get("id"), 60) or ("in" if is_input else "out")
    if not re.fullmatch(r"[a-zA-Z0-9_.-]+", port_id):
        raise CustomNodeError(f"Некорректный id порта: {port_id}")
    kind = _text(port.get("kind")) or PORT_KINDS and ("exec" if index == 0 else "data")
    if kind not in PORT_KINDS:
        raise CustomNodeError(f"Неизвестный тип порта: {kind}")
    result = {
        "id": port_id,
        "label": _text(port.get("label"), 80) or port_id,
        "kind": kind,
    }
    inner = port.get("inner")
    if isinstance(inner, dict) and inner.get("node"):
        result["inner"] = {"node": str(inner["node"]), "port": str(inner.get("port") or "in")}
    return result


def _param(raw: dict) -> dict:
    if not isinstance(raw, dict):
        raise CustomNodeError("Параметр должен быть объектом")
    name = _text(raw.get("name"), 60)
    if not re.fullmatch(r"[a-zA-Z_][a-zA-Z0-9_]*", name):
        raise CustomNodeError(f"Некорректное имя параметра: {name or '(пусто)'}")
    ptype = _text(raw.get("type")) or "string"
    if ptype not in PARAM_TYPES:
        raise CustomNodeError(f"Неизвестный тип параметра «{name}»: {ptype}")
    options = raw.get("options") if isinstance(raw.get("options"), list) else []
    default = raw.get("default")
    if ptype == "boolean":
        default = _bool(default)
    elif ptype == "number":
        try:
            default = float(default) if default not in (None, "") else 0
        except (TypeError, ValueError):
            default = 0
    elif ptype == "select":
        default = _text(default) if default not in (None, "") else (str(options[0]) if options else "")
    elif ptype in {"json", "keyvalue"}:
        if not isinstance(default, (dict, list)):
            default = {} if ptype == "keyvalue" else None
    else:
        default = _text(default)
    return {
        "name": name,
        "type": ptype,
        "label": _text(raw.get("label"), 120) or name,
        "description": _text(raw.get("description"), 500),
        "default": default,
        "required": _bool(raw.get("required")),
        "secret": _bool(raw.get("secret")) or ptype == "secret",
        "options": [str(item) for item in options],
        "min": raw.get("min") if isinstance(raw.get("min"), (int, float)) else None,
        "max": raw.get("max") if isinstance(raw.get("max"), (int, float)) else None,
    }


def _findings_config(raw: Any) -> dict:
    if not isinstance(raw, dict):
        return {}
    category = _text(raw.get("category")).upper() or "CUSTOM"
    if category not in CATEGORIES:
        raise CustomNodeError(f"Неизвестная категория находок: {category}")
    default_severity = _text(raw.get("default_severity")).upper() or "MEDIUM"
    if default_severity not in SEVERITIES:
        raise CustomNodeError(f"Неизвестная критичность: {default_severity}")
    field_map = raw.get("map") if isinstance(raw.get("map"), dict) else {}
    return {
        "enabled": _bool(raw.get("enabled", True)),
        "from": _text(raw.get("from"), 200),
        "category": category,
        "default_severity": default_severity,
        "map": {str(key): _text(value, 80) for key, value in field_map.items()},
        "fingerprint": _text(raw.get("fingerprint"), 80),
    }


def normalize_definition(payload: dict, node_id: str | None = None) -> dict:
    if not isinstance(payload, dict):
        raise CustomNodeError("Определение ноды должно быть объектом")
    source = payload
    if isinstance(payload.get("spec"), dict):
        source = {**payload.get("spec"), "runtime": payload.get("runtime") or {}, "kind": payload.get("kind")}
    name = _text(source.get("name"), 120)
    if not name:
        raise CustomNodeError("Укажите название ноды")
    kind = _text(source.get("kind")) or _text((source.get("runtime") or {}).get("kind")) or "http"
    if kind not in KINDS:
        raise CustomNodeError(f"Неизвестный тип ноды: {kind}")
    inputs = [_port(item, True, index) for index, item in enumerate(source.get("inputs") or [{"id": "in", "kind": "exec"}])]
    outputs = [_port(item, False, index) for index, item in enumerate(source.get("outputs") or [{"id": "out", "kind": "exec"}])]
    params = [_param(item) for item in source.get("params") or []]
    names = [item["name"] for item in params]
    if len(names) != len(set(names)):
        raise CustomNodeError("Имена параметров должны быть уникальны")
    runtime = source.get("runtime") if isinstance(source.get("runtime"), dict) else {}
    if kind == "http":
        method = _text(runtime.get("method")).upper() or "GET"
        if method not in HTTP_METHODS:
            raise CustomNodeError(f"Неподдерживаемый HTTP-метод: {method}")
        url = _text(runtime.get("url"), 2000)
        if not url:
            raise CustomNodeError("Укажите URL для HTTP-ноды")
        body = runtime.get("body")
        if body is not None and not isinstance(body, (str, dict, list)):
            raise CustomNodeError("Тело запроса должно быть строкой или JSON-объектом")
        normal_runtime = {
            "method": method,
            "url": url,
            "headers": {str(k): str(v) for k, v in (runtime.get("headers") or {}).items()} if isinstance(runtime.get("headers"), dict) else {},
            "body": body,
            "timeout": max(1, min(120, int(runtime.get("timeout") or 20))),
            "findings": _findings_config(runtime.get("findings")),
        }
    elif kind == "ai":
        prompt = _text(runtime.get("prompt"), 8000)
        if not prompt:
            raise CustomNodeError("Укажите промпт для AI-ноды")
        provider = _text(runtime.get("provider")).lower() or "auto"
        if provider not in AI_PROVIDERS:
            raise CustomNodeError(f"Неизвестный AI-провайдер: {provider}")
        normal_runtime = {
            "provider": provider,
            "system": _text(runtime.get("system"), 4000),
            "prompt": prompt,
            "max_tokens": max(1, min(8192, int(runtime.get("max_tokens") or 512))),
            "temperature": max(0.0, min(2.0, float(runtime.get("temperature") or 0.2))),
            "findings": _findings_config(runtime.get("findings")),
        }
    else:
        graph = runtime.get("graph") if isinstance(runtime.get("graph"), dict) else {}
        nodes = graph.get("nodes") if isinstance(graph.get("nodes"), list) else []
        if not nodes:
            raise CustomNodeError("В композитной ноде нет внутренних нод")
        for inner in nodes:
            if not isinstance(inner, dict):
                raise CustomNodeError("Некорректная внутренняя нода")
            if str(inner.get("type", "")).startswith("trigger."):
                raise CustomNodeError("Внутри композитной ноды нельзя использовать триггеры")
        normal_runtime = {
            "graph": graph,
            "bindings": runtime.get("bindings") if isinstance(runtime.get("bindings"), dict) else {},
        }
        roots, leaves = _composite_boundaries(graph)
        for index, item in enumerate(inputs):
            if not item.get("inner") and roots:
                item["inner"] = {"node": roots[min(index, len(roots) - 1)], "port": "in"}
        for index, item in enumerate(outputs):
            if not item.get("inner") and leaves:
                item["inner"] = {"node": leaves[min(index, len(leaves) - 1)], "port": "out"}
    definition = {
        "id": node_id or _text(source.get("id"), 80) or f"custom-{uuid.uuid4().hex[:10]}",
        "name": name,
        "description": _text(source.get("description"), 1000),
        "icon": _text(source.get("icon"), 40) or DEFAULT_ICON,
        "color": _text(source.get("color"), 20) or DEFAULT_COLOR,
        "kind": kind,
        "version": max(1, int(source.get("version") or 1)),
        "inputs": inputs,
        "outputs": outputs,
        "params": params,
        "runtime": normal_runtime,
    }
    return definition


def build_spec(definition: dict) -> NodeSpec:
    return NodeSpec(
        type=definition["id"],
        category="custom",
        title=definition["name"],
        description=definition.get("description", ""),
        icon=definition.get("icon", DEFAULT_ICON),
        color=definition.get("color", DEFAULT_COLOR),
        inputs=[
            HandleSpec(item["id"], item.get("label", item["id"]), position="left", kind="target")
            for item in definition.get("inputs", [])
        ],
        outputs=[
            HandleSpec(item["id"], item.get("label", item["id"]), kind="source")
            for item in definition.get("outputs", [])
        ],
        params=[
            ParamSpec(
                name=item["name"],
                type=item["type"],
                label=item.get("label", item["name"]),
                description=item.get("description", ""),
                default=item.get("default"),
                required=bool(item.get("required")),
                options=list(item.get("options") or []),
                secret=bool(item.get("secret")),
                min=item.get("min"),
                max=item.get("max"),
            )
            for item in definition.get("params", [])
        ],
        tags=["custom", definition.get("kind", "")],
        version=f"1.{definition.get('version', 1)}",
    )


def _make_class(definition: dict) -> type:
    spec = build_spec(definition)

    def execute(self, ctx, params: dict) -> NodeResult:
        return execute_definition(definition, ctx, params)

    return type(
        "CustomNode_" + re.sub(r"[^a-zA-Z0-9_]", "_", definition["id"]),
        (BaseNode,),
        {
            "type": spec.type,
            "category": "custom",
            "title": spec.title,
            "description": spec.description,
            "icon": spec.icon,
            "color": spec.color,
            "inputs": spec.inputs,
            "outputs": spec.outputs,
            "params": spec.params,
            "tags": ["custom"],
            "execute": execute,
        },
    )


def register_definition(definition: dict) -> None:
    register_custom(definition["id"], build_spec(definition), _make_class(definition))


def load_all() -> None:
    unregister_custom()
    for row in CustomNodeRow.select():
        try:
            register_definition(definition_from_row(row))
        except Exception:
            continue


def definition_from_row(row: CustomNodeRow) -> dict:
    spec = j_loads(row.spec, {}) or {}
    runtime = j_loads(row.runtime, {}) or {}
    return {
        "id": row.id,
        "name": row.name,
        "description": spec.get("description", ""),
        "icon": spec.get("icon", DEFAULT_ICON),
        "color": spec.get("color", DEFAULT_COLOR),
        "kind": row.kind,
        "version": row.version,
        "inputs": spec.get("inputs", []),
        "outputs": spec.get("outputs", []),
        "params": spec.get("params", []),
        "runtime": runtime,
    }


def _save(definition: dict) -> CustomNodeRow:
    spec = {key: definition[key] for key in ("description", "icon", "color", "inputs", "outputs", "params")}
    row = CustomNodeRow.get_or_none(CustomNodeRow.id == definition["id"])
    if row is None:
        row = CustomNodeRow.create(
            id=definition["id"],
            name=definition["name"],
            kind=definition["kind"],
            version=definition["version"],
            spec=j_dumps(spec),
            runtime=j_dumps(definition["runtime"]),
        )
    else:
        row.name = definition["name"]
        row.kind = definition["kind"]
        row.version = definition["version"]
        row.spec = j_dumps(spec)
        row.runtime = j_dumps(definition["runtime"])
        row.updated_at = utcnow()
        row.save()
    return row


def list_definitions() -> list[dict]:
    workflows = []
    return [definition_from_row(row) for row in CustomNodeRow.select().order_by(CustomNodeRow.updated_at.desc())]


def get_definition(node_id: str) -> dict | None:
    row = CustomNodeRow.get_or_none(CustomNodeRow.id == node_id)
    return definition_from_row(row) if row else None


def create_definition(payload: dict) -> dict:
    definition = normalize_definition(payload)
    definition["version"] = 1
    _save(definition)
    register_definition(definition)
    return definition


def update_definition(node_id: str, payload: dict) -> dict:
    current = get_definition(node_id)
    if current is None:
        raise CustomNodeError("Нода не найдена")
    definition = normalize_definition(payload, node_id=node_id)
    definition["version"] = int(current.get("version", 1)) + 1
    _save(definition)
    register_definition(definition)
    return definition


def delete_definition(node_id: str) -> None:
    row = CustomNodeRow.get_or_none(CustomNodeRow.id == node_id)
    if row is None:
        raise CustomNodeError("Нода не найдена")
    row.delete_instance()
    unregister_custom(prefix=node_id)


def import_definition(payload: dict) -> dict:
    definition = normalize_definition(payload)
    existing = get_definition(definition["id"])
    if existing is not None:
        definition["version"] = max(int(existing.get("version", 1)), int(definition.get("version", 1))) + 1
        _save(definition)
        register_definition(definition)
        return definition
    _save(definition)
    register_definition(definition)
    return definition


def export_definition(node_id: str) -> dict:
    definition = get_definition(node_id)
    if definition is None:
        raise CustomNodeError("Нода не найдена")
    return {"schema": SCHEMA, **definition}




def get_network_rules() -> dict:
    row = AppSettingRow.get_or_none(AppSettingRow.key == "network_rules")
    data = j_loads(row.value, {}) if row else {}
    rules = {**DEFAULT_NETWORK, **(data if isinstance(data, dict) else {})}
    hosts = [str(item).strip().lower() for item in rules.get("allow_hosts", []) if str(item).strip()]
    rules["allow_hosts"] = list(dict.fromkeys(hosts))
    return rules


def save_network_rules(payload: dict) -> dict:
    if not isinstance(payload, dict):
        raise CustomNodeError("Ожидался объект сетевых правил")
    hosts = payload.get("allow_hosts")
    if hosts is None:
        hosts = get_network_rules().get("allow_hosts", [])
    if not isinstance(hosts, list):
        raise CustomNodeError("allow_hosts должен быть списком")
    cleaned = []
    for host in hosts:
        value = str(host).strip().lower()
        if not value:
            continue
        if "://" in value or "/" in value:
            raise CustomNodeError(f"Укажите только хост, без схемы и пути: {value}")
        if not re.fullmatch(r"[a-z0-9.*:_-]+", value):
            raise CustomNodeError(f"Некорректный хост: {value}")
        cleaned.append(value)
    rules = {
        "allow_hosts": list(dict.fromkeys(cleaned)),
        "timeout": max(1, min(120, int(payload.get("timeout") or 20))),
        "max_bytes": max(1024, min(20_000_000, int(payload.get("max_bytes") or 1_048_576))),
        "max_redirects": max(0, min(10, int(payload.get("max_redirects") or 3))),
        "max_requests_per_run": max(1, min(100, int(payload.get("max_requests_per_run") or 20))),
    }
    row = AppSettingRow.get_or_none(AppSettingRow.key == "network_rules")
    if row is None:
        AppSettingRow.create(key="network_rules", value=j_dumps(rules))
    else:
        row.value = j_dumps(rules)
        row.updated_at = utcnow()
        row.save()
    return rules


def _host_allowed(url: str, rules: dict) -> None:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise NodeError("Разрешены только http(s)-адреса")
    host = parsed.hostname.lower()
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    for pattern in rules.get("allow_hosts", []):
        pattern = str(pattern).lower()
        if pattern.startswith("*."):
            base = pattern[2:]
            if host == base or host.endswith("." + base):
                return
        elif ":" in pattern:
            pattern_host, _, pattern_port = pattern.rpartition(":")
            if pattern_host and pattern_port.isdigit() and host == pattern_host and port == int(pattern_port):
                return
        elif host == pattern:
            return
    raise NodeError(f"Хост {host} не разрешён. Добавьте его в «Сетевые правила»")


def _render(text: str, ctx, params: dict) -> str:
    counts = severity_counts(ctx.findings)

    def lookup(expr: str) -> Any:
        parts = [part for part in re.split(r"[.\[\]]", expr) if part]
        if not parts:
            return ""
        if parts[0] == "params":
            value = params
            for part in parts[1:]:
                value = value.get(part) if isinstance(value, dict) else None
            return "" if value is None else value
        if parts[0] == "run":
            return getattr(ctx, "run_id", "")
        if parts[0] == "workflow":
            return (ctx.workflow or {}).get("name", "")
        if parts[0] == "source":
            return getattr(getattr(ctx, "source", None), "label", "")
        if parts[0] == "findings":
            key = parts[1] if len(parts) > 1 else "total"
            return counts.get(key, 0) if key != "total" else counts.get("total", 0)
        return ""

    def replace(match: re.Match) -> str:
        value = lookup(match.group(1).strip())
        if isinstance(value, (dict, list)):
            return json.dumps(value, ensure_ascii=False)
        return str(value)

    return re.sub(r"\{\{\s*([^}]+)\s*\}\}", replace, str(text or ""))


def _render_value(value: Any, ctx, params: dict) -> Any:
    if isinstance(value, str):
        return _render(value, ctx, params)
    if isinstance(value, dict):
        return {str(key): _render_value(item, ctx, params) for key, item in value.items()}
    if isinstance(value, list):
        return [_render_value(item, ctx, params) for item in value]
    return value


def _pick(item: Any, path: str) -> Any:
    value = item
    for part in [part for part in str(path or "").split(".") if part]:
        if isinstance(value, dict):
            value = value.get(part)
        elif isinstance(value, list) and part.isdigit():
            value = value[int(part)] if int(part) < len(value) else None
        else:
            return None
    return value


def _mapped_findings(config: dict, response: Any, node_id: str) -> list[Finding]:
    if not config or not config.get("enabled"):
        return []
    items = _pick(response, config.get("from") or "") if config.get("from") else response
    if isinstance(items, dict):
        items = items.get("items") if isinstance(items.get("items"), list) else [items]
    if not isinstance(items, list):
        return []
    mapping = config.get("map") or {}
    findings: list[Finding] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        severity = str(_pick(item, mapping.get("severity", "severity")) or config.get("default_severity") or "MEDIUM")
        title = str(_pick(item, mapping.get("title", "title")) or _pick(item, mapping.get("message", "message")) or "Custom finding")
        path = str(_pick(item, mapping.get("path", "path")) or "")
        line = _pick(item, mapping.get("line", "line")) or 1
        rule = str(_pick(item, mapping.get("rule", "rule")) or "custom-check")
        findings.append(
            Finding(
                category=config.get("category", "CUSTOM"),
                class_name=rule,
                path=path,
                line=line,
                severity=severity,
                message=title,
                rule_id=rule,
                detector="custom",
                source_node=node_id,
                extra={"custom_node": node_id},
            )
        )
    return findings


def _findings_summary(findings: list[Finding]) -> dict:
    counts = severity_counts(findings)
    return {
        "count": len(findings),
        "by_severity": counts,
        "top": [
            {
                "id": finding.fingerprint,
                "severity": finding.severity,
                "category": finding.category,
                "path": finding.path,
                "line": finding.line,
                "message": finding.message,
            }
            for finding in findings[:20]
        ],
    }


def _http_execute(definition: dict, ctx, params: dict) -> NodeResult:
    runtime = definition["runtime"]
    rules = get_network_rules()
    method = runtime.get("method", "GET")
    url = _render(runtime.get("url", ""), ctx, params)
    headers = _render_value(runtime.get("headers") or {}, ctx, params)
    body = runtime.get("body")
    if body is not None:
        body = _render_value(body, ctx, params)
        if not isinstance(body, str):
            body = json.dumps(body, ensure_ascii=False)
        headers.setdefault("Content-Type", "application/json")
    timeout = min(int(runtime.get("timeout") or 20), int(rules.get("timeout") or 20))
    max_bytes = int(rules.get("max_bytes") or 1_048_576)
    max_redirects = int(rules.get("max_redirects") or 3)
    current = url
    content = b""
    status = 0
    response_headers: dict[str, str] = {}
    with httpx.Client(timeout=timeout, follow_redirects=False) as client:
        for _ in range(max_redirects + 1):
            _host_allowed(current, rules)
            with client.stream(method, current, headers=headers, content=body.encode("utf-8") if body else None) as response:
                if response.is_redirect:
                    location = response.headers.get("location")
                    if not location:
                        break
                    current = urljoin(current, location)
                    continue
                status = response.status_code
                response_headers = {key.lower(): value for key, value in response.headers.items()}
                total = 0
                chunks: list[bytes] = []
                for chunk in response.iter_bytes():
                    total += len(chunk)
                    if total > max_bytes:
                        raise NodeError(f"Ответ больше лимита {max_bytes} байт")
                    chunks.append(chunk)
                content = b"".join(chunks)
                break
        else:
            raise NodeError("Слишком много редиректов")
    text = content.decode("utf-8", errors="replace")
    parsed: Any = text
    if "json" in response_headers.get("content-type", ""):
        try:
            parsed = json.loads(text)
        except ValueError:
            parsed = text
    findings = _mapped_findings(runtime.get("findings") or {}, parsed, definition["id"])
    added = ctx.add_findings(findings, node_id=ctx.node_id) if findings else 0
    summary = _findings_summary(findings)
    return NodeResult(
        outputs={
            "status": status,
            "response": parsed,
            "body": text[:4000],
            "headers": response_headers,
            "findings": summary,
            "new_findings": added,
        },
        message=f"HTTP {status} · находок {len(findings)}",
        preview={"status": status, "findings": summary},
        findings_count=len(findings),
    )


def _ai_execute(definition: dict, ctx, params: dict) -> NodeResult:
    from app.ai.providers import build_provider

    runtime = definition["runtime"]
    provider_name = runtime.get("provider") or "auto"
    settings = ctx.settings
    if provider_name == "auto":
        provider_name = settings.effective_llm_provider
    if provider_name not in {"local", "openai", "ollama", "universal", "fake"}:
        raise NodeError("AI-провайдер не настроен — используется fallback")
    provider = build_provider(settings)
    scoped_findings = ctx.findings_for_node(ctx.node_id) if hasattr(ctx, "findings_for_node") else list(ctx.findings)
    counts = severity_counts(scoped_findings)
    context = {
        "findings_total": len(scoped_findings),
        "findings_by_severity": counts,
        "workflow": (ctx.workflow or {}).get("name", ""),
    }
    system = _render(runtime.get("system") or "", ctx, params)
    prompt = _render(runtime.get("prompt") or "", ctx, params)
    messages = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "system", "content": "Контекст запуска: " + json.dumps(context, ensure_ascii=False)})
    messages.append({"role": "user", "content": prompt})
    text = provider.complete(
        messages,
        max_tokens=int(runtime.get("max_tokens") or 512),
        temperature=float(runtime.get("temperature") or 0.2),
    )
    findings = []
    payload = None
    try:
        payload = json.loads(text)
    except ValueError:
        payload = None
    if runtime.get("findings", {}).get("enabled") and payload is not None:
        findings = _mapped_findings(runtime.get("findings"), payload, definition["id"])
        if findings:
            ctx.add_findings(findings, node_id=ctx.node_id)

    summary = text.strip()
    if isinstance(payload, dict) and str(payload.get("summary") or "").strip():
        summary = str(payload["summary"]).strip()
    summary = summary[:8000]
    previous = ctx.ai_analysis or {}
    items = [
        {
            "finding_id": finding.fingerprint,
            "explanation": finding.message,
            "remediation": finding.remediation,
            "severity": finding.severity,
            "source": "custom",
        }
        for finding in findings
    ]
    combined_summary = summary
    if previous.get("summary"):
        combined_summary = f"{previous['summary']}\n\n{summary}"
    ctx.ai_analysis = {
        "provider": provider_name,
        "model": getattr(provider, "model", ""),
        "summary": combined_summary,
        "overall_risk": previous.get("overall_risk") or (counts.get("CRITICAL") and "CRITICAL") or (counts.get("HIGH") and "HIGH") or "MEDIUM",
        "findings": [*(previous.get("findings") or []), *items],
        "next_steps": (payload or {}).get("next_steps", []) if isinstance(payload, dict) else [],
        "validation": {
            "grounded": True,
            "fallback": False,
            "schema_ok": True,
            "coverage": {"explained": len(items), "total": len(scoped_findings), "missing": []},
            "errors": [],
        },
    }
    ctx.emit(
        "ai.completed",
        f"AI: {provider_name} · {len(text)} символов",
        node_id=ctx.node_id,
        payload={"provider": provider_name, "summary": summary[:500]},
    )
    return NodeResult(
        outputs={"text": text, "response": text, "findings": _findings_summary(findings)},
        message=f"AI · {len(text)} символов",
        preview={"provider": provider_name, "text": text[:500]},
        findings_count=len(findings),
    )


def execute_definition(definition: dict, ctx, params: dict) -> NodeResult:
    kind = definition["kind"]
    if kind == "http":
        return _http_execute(definition, ctx, params)
    if kind == "ai":
        return _ai_execute(definition, ctx, params)
    if kind == "composite":
        raise NodeError("Композитная нода должна быть развёрнута перед запуском")
    raise NodeError(f"Неизвестный тип ноды: {kind}")


class _TestContext:
    def __init__(self, settings, workflow=None):
        self.settings = settings
        self.findings = []
        self.run_id = "test"
        self.workflow = workflow or {"name": "Тест кастомной ноды"}
        self.source = None
        self.node_id = "test"
        self.secret_values = []

    def add_findings(self, findings, node_id=None):
        self.findings.extend(findings)
        return len(findings)

    def findings_for_node(self, node_id=None):
        return list(self.findings)

    def emit(self, *args, **kwargs):
        return None


def test_definition(node_id: str, params: dict | None = None, settings=None) -> dict:
    definition = get_definition(node_id)
    if definition is None:
        raise CustomNodeError("Нода не найдена")
    if settings is None:
        raise CustomNodeError("Нет настроек приложения")
    spec = build_spec(definition)
    from app.core.registry import validate_params

    try:
        clean = validate_params(spec, params or {})
        ctx = _TestContext(settings)
        result = execute_definition(definition, ctx, clean)
        return {
            "ok": True,
            "message": result.message,
            "outputs": result.outputs,
            "findings_count": len(ctx.findings),
            "findings": _findings_summary(ctx.findings),
        }
    except Exception as exc:
        return {"ok": False, "message": str(exc), "error": type(exc).__name__}




def _composite_boundaries(graph: dict) -> tuple[list[str], list[str]]:
    nodes = [node for node in (graph.get("nodes") or []) if isinstance(node, dict) and node.get("id")]
    ids = [str(node["id"]) for node in nodes]
    known = set(ids)
    incoming = {node_id: 0 for node_id in ids}
    outgoing = {node_id: 0 for node_id in ids}
    for edge in graph.get("edges") or []:
        source = str(edge.get("source") or "")
        target = str(edge.get("target") or "")
        if source in known and target in known:
            outgoing[source] += 1
            incoming[target] += 1
    roots = [node_id for node_id in ids if incoming[node_id] == 0]
    leaves = [node_id for node_id in ids if outgoing[node_id] == 0]
    return roots or ids, leaves or ids


def _with_composite_boundaries(definition: dict) -> dict:
    result = json.loads(json.dumps(definition))
    runtime = result.get("runtime") or {}
    graph = runtime.get("graph") or {}
    roots, leaves = _composite_boundaries(graph)
    inputs = result.get("inputs") if isinstance(result.get("inputs"), list) else []
    outputs = result.get("outputs") if isinstance(result.get("outputs"), list) else []
    if not inputs and roots:
        inputs = [{"id": "in", "label": "Вход", "kind": "exec"}]
    if not outputs and leaves:
        outputs = [{"id": "out", "label": "Выход", "kind": "exec"}]
    for index, item in enumerate(inputs):
        if not item.get("inner") and roots:
            item["inner"] = {"node": roots[min(index, len(roots) - 1)], "port": "in"}
    for index, item in enumerate(outputs):
        if not item.get("inner") and leaves:
            item["inner"] = {"node": leaves[min(index, len(leaves) - 1)], "port": "out"}
    result["inputs"] = inputs
    result["outputs"] = outputs
    return result


def _composite_definition(node_type: str) -> dict | None:
    if not node_type.startswith(CUSTOM_PREFIX):
        return None
    return get_definition(node_type)


def expand_composite_nodes(graph: dict, depth: int = 0) -> dict:
    if depth > 4:
        raise CustomNodeError("Слишком глубокая вложенность композитных нод")
    nodes = graph.get("nodes") or []
    edges = graph.get("edges") or []
    composite_ids = {}
    for node in nodes:
        spec = get_spec(str(node.get("type")))
        if spec is None or spec.category != "custom":
            continue
        definition = _composite_definition(str(node.get("type")))
        if definition and definition["kind"] == "composite":
            composite_ids[node["id"]] = _with_composite_boundaries(definition)
    if not composite_ids:
        return graph

    replacements = {}
    new_nodes: list[dict] = []
    new_edges: list[dict] = []
    for node in nodes:
        if node["id"] not in composite_ids:
            new_nodes.append(node)
            continue
        definition = composite_ids[node["id"]]
        runtime = definition["runtime"]
        prefix = f"{node['id']}/"
        inner_graph = runtime.get("graph") or {}
        composite_params = (node.get("data") or {}).get("params") or {}
        bindings = runtime.get("bindings") or {}
        copied = {}
        for inner in inner_graph.get("nodes") or []:
            inner_copy = json.loads(json.dumps(inner))
            inner_copy["id"] = prefix + str(inner["id"])
            inner_copy.setdefault("data", {})
            inner_params = inner_copy["data"].setdefault("params", {})
            for param_key, binding in bindings.items():
                if not isinstance(binding, dict) or binding.get("node") != inner["id"]:
                    continue
                if param_key in composite_params:
                    inner_params[binding.get("param") or param_key] = composite_params[param_key]
            copied[inner["id"]] = inner_copy["id"]
            new_nodes.append(inner_copy)
        for inner_edge in inner_graph.get("edges") or []:
            new_edges.append(
                {
                    **inner_edge,
                    "id": prefix + str(inner_edge["id"]),
                    "source": copied.get(inner_edge["source"], prefix + str(inner_edge["source"])),
                    "target": copied.get(inner_edge["target"], prefix + str(inner_edge["target"])),
                }
            )
        replacements[node["id"]] = definition

    inputs_map = {}
    outputs_map = {}
    for composite_id, definition in replacements.items():
        inputs_map[composite_id] = {
            item["id"]: item for item in definition.get("inputs", [])
        }
        outputs_map[composite_id] = {
            item["id"]: item for item in definition.get("outputs", [])
        }

    for edge in edges:
        source = edge.get("source")
        target = edge.get("target")
        if source in replacements:
            port = edge.get("sourceHandle") or edge.get("from", {}).get("port") or "out"
            definition = replacements[source]
            mapping = outputs_map[source].get(port)
            if mapping is None:
                continue
            inner_port = mapping.get("inner") or {}
            new_edges.append(
                {
                    **edge,
                    "id": f"{source}--{edge.get('id')}",
                    "source": f"{source}/{inner_port.get('node')}",
                    "sourceHandle": inner_port.get("port") or "out",
                }
            )
            continue
        if target in replacements:
            port = edge.get("targetHandle") or edge.get("to", {}).get("port") or "in"
            definition = replacements[target]
            mapping = inputs_map[target].get(port)
            if mapping is None:
                continue
            inner_port = mapping.get("inner") or {}
            new_edges.append(
                {
                    **edge,
                    "id": f"{target}--{edge.get('id')}",
                    "target": f"{target}/{inner_port.get('node')}",
                    "targetHandle": inner_port.get("port") or "in",
                }
            )
            continue
        new_edges.append(edge)

    return expand_composite_nodes({"nodes": new_nodes, "edges": new_edges}, depth + 1)
