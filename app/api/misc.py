from __future__ import annotations

import hashlib
import hmac
import json
import uuid

from flask import Blueprint, Response, jsonify, request

from app import __version__ as APP_VERSION
from app.ai.service import AIService
from app.api.common import (
    ApiError,
    check_ci_token,
    engine,
    get_bool,
    json_body,
    mask_graph,
    secret_box,
    serialize_workflow,
    settings,
    source_service,
    telegram_service,
    validate_target,
)
from app.core.registry import catalog, get_spec
from app.db import (
    FindingRow,
    InboxMessageRow,
    RunRow,
    WorkflowRow,
    j_loads,
    utcnow,
)
from app.services.templates import clone_template, list_templates
from app.services.telegram import TelegramError

bp = Blueprint("misc", __name__)


@bp.get("/health")
def health():
    settings_ = settings()
    try:
        runs = RunRow.select().count()
        db_status = "ok"
    except Exception as exc:
        runs = 0
        db_status = f"error: {exc}"
    return jsonify(
        {
            "status": "ok" if db_status == "ok" else "degraded",
            "version": APP_VERSION,
            "database": {"status": db_status, "runs": runs},
            "llm": {
                "provider": settings_.effective_llm_provider,
                "model": settings_.llm_model or settings_.llm_model_path.name,
            },
            "scheduler": {"enabled": settings_.enable_scheduler},
            "auth": {"api_token": bool(settings_.api_token), "ci_token": bool(settings_.ci_token)},
        }
    )


@bp.get("/meta")
def meta():
    settings_ = settings()
    return jsonify(
        {
            "name": "LDWarden",
            "version": APP_VERSION,
            "description": "Visual AI security workflow backend",
            "categories": ["SECRET", "SAST", "SCA"],
            "severities": ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
            "node_categories": ["trigger", "source", "scanner", "ai", "logic", "report", "notification", "control"],
            "settings": settings_.public_dict(),
            "auth_required": bool(settings_.api_token),
            "endpoints": {
                "nodes": "/api/nodes",
                "workflows": "/api/workflows",
                "runs": "/api/runs",
                "templates": "/api/templates",
                "sources": "/api/sources",
                "generate": "/api/ai/workflows/generate",
                "ci": "/api/ci/run",
                "telegram": "/api/telegram/connect",
                "openapi": "/api/openapi.json",
            },
        }
    )


@bp.get("/targets")
def targets():
    settings_ = settings()
    return jsonify(
        {
            "default": str(settings_.default_target),
            "allowed_roots": [str(path) for path in settings_.allowed_roots],
            "sources": source_service().list_sources(),
        }
    )


@bp.get("/nodes")
def nodes():
    category = request.args.get("category")
    items = catalog()
    if category:
        items = [item for item in items if item["category"] == category]
    return jsonify({"items": items, "count": len(items)})


@bp.get("/nodes/<path:node_type>")
def node_detail(node_type: str):
    spec = get_spec(node_type)
    if spec is None:
        raise ApiError("Тип ноды не найден", 404, "not_found")
    return jsonify(spec.to_dict())


@bp.post("/sources")
def upload_source():
    file = request.files.get("file")
    if file is None:
        raise ApiError("Передайте ZIP-архив в поле file", 400, "missing_file")
    if not (file.filename or "").lower().endswith(".zip"):
        raise ApiError("Поддерживаются только ZIP-архивы", 400, "invalid_file")
    meta = source_service().create_from_zip(file, name=request.form.get("name"))
    return jsonify(meta), 201


@bp.get("/sources")
def list_sources():
    return jsonify({"items": source_service().list_sources()})


@bp.get("/sources/<source_id>")
def source_detail(source_id: str):
    meta = source_service().read_source_meta(source_id)
    if not meta:
        raise ApiError("Источник не найден", 404, "not_found")
    meta["exists"] = settings().source_dir(source_id).exists()
    return jsonify(meta)


@bp.delete("/sources/<source_id>")
def delete_source(source_id: str):
    meta = source_service().read_source_meta(source_id)
    if not meta:
        raise ApiError("Источник не найден", 404, "not_found")
    source_service().delete_source(source_id)
    return jsonify({"deleted": source_id})


@bp.get("/templates")
def templates():
    items = list_templates()
    for item in items:
        item["graph"] = mask_graph(item.get("graph") or {"nodes": [], "edges": []})
    return jsonify({"items": items, "count": len(items)})


@bp.post("/templates/<template_id>/clone")
def clone(template_id: str):
    data = json_body(required=False)
    row = clone_template(template_id, name=data.get("name"))
    return jsonify(serialize_workflow(row)), 201


@bp.post("/ai/workflows/generate")
def generate_workflow():
    data = json_body()
    prompt = str(data.get("prompt") or "").strip()
    if not prompt:
        raise ApiError("Опишите задачу текстом в поле prompt", 400, "missing_prompt")
    if len(prompt) > 4000:
        raise ApiError("Текст задачи слишком длинный (максимум 4000 символов)", 400, "invalid_prompt")
    source_hint = str(data.get("source") or "")
    result = AIService(settings()).generate_workflow(prompt, source_hint=source_hint)
    if data.get("save"):
        graph = result["graph"]
        row = WorkflowRow.create(
            id="wf-" + uuid.uuid4().hex[:12],
            name=result["name"][:160],
            description=result.get("description", "")[:4000],
            graph=json.dumps(graph, ensure_ascii=False),
            is_template=False,
            published=False,
            owner="local",
        )
        result["workflow"] = serialize_workflow(row)
    return jsonify(result)


@bp.post("/ci/run")
def ci_run():
    check_ci_token(settings())
    data = json_body()
    workflow_id = str(data.get("workflow_id") or "").strip()
    if not workflow_id:
        raise ApiError("Укажите workflow_id", 400, "missing_workflow")
    row = WorkflowRow.get_or_none(WorkflowRow.id == workflow_id)
    if row is None:
        raise ApiError("Workflow не найден", 404, "not_found")
    target = validate_target(data.get("target"))
    wait = bool(data.get("wait", True))
    run = engine().start_run(
        row.to_dict(),
        trigger="ci",
        target=target,
        wait=wait,
        ci_mode=True,
    )
    status = run.get("status", "queued")
    exit_code = 0 if status == "success" else (2 if status == "cancelled" else 1)
    return jsonify(
        {
            "run_id": run["id"],
            "status": status,
            "exit_code": exit_code,
            "gate": run.get("gate"),
            "summary": run.get("summary"),
            "reports": {
                "markdown": f"/api/runs/{run['id']}/report?format=md",
                "json": f"/api/runs/{run['id']}/report?format=json",
                "sarif": f"/api/runs/{run['id']}/report?format=sarif",
            },
        }
    )


@bp.get("/ci/status/<run_id>")
def ci_status(run_id: str):
    check_ci_token(settings())
    from app.api.runs import run_status

    return run_status(run_id)


@bp.get("/ci/snippets")
def ci_snippets():
    workflow_id = request.args.get("workflow_id", "")
    base_url = (request.args.get("base_url") or request.host_url.rstrip("/")).rstrip("/")
    body = json.dumps({"workflow_id": workflow_id, "wait": True}, ensure_ascii=False)
    github = f"""name: LDWarden security gate
on:
  pull_request:
  push:
    branches: [main]
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run LDWarden workflow
        env:
          LDWARDEN_CI_TOKEN: ${{{{ secrets.LDWARDEN_CI_TOKEN }}}}
        run: |
          response=$(curl -sS -X POST "{base_url}/api/ci/run" \\
            -H "Content-Type: application/json" \\
            -H "X-CI-Token: $LDWARDEN_CI_TOKEN" \\
            -d '{body}')
          echo "$response" | jq .
          echo "$response" | jq -e '.exit_code == 0'
"""
    gitlab = f"""ldwarden-security:
  image: alpine:3.20
  before_script:
    - apk add --no-cache curl jq
  script:
    - |
      response=$(curl -sS -X POST "{base_url}/api/ci/run" \\
        -H "Content-Type: application/json" \\
        -H "X-CI-Token: $LDWARDEN_CI_TOKEN" \\
        -d '{body}')
      echo "$response" | jq .
      echo "$response" | jq -e '.exit_code == 0'
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
"""
    return jsonify(
        {
            "base_url": base_url,
            "workflow_id": workflow_id,
            "github_actions": github,
            "gitlab_ci": gitlab,
            "notes": "Сохраните LDWARDEN_CI_TOKEN как секрет CI и включите нужную ветку.",
        }
    )


@bp.post("/hooks/<workflow_id>")
def webhook(workflow_id: str):
    row = WorkflowRow.get_or_none(WorkflowRow.id == workflow_id)
    if row is None:
        raise ApiError("Workflow не найден", 404, "not_found")
    graph = j_loads(row.graph, {"nodes": [], "edges": []})
    hook_node = next(
        (node for node in graph.get("nodes", []) if node.get("type") == "trigger.webhook"),
        None,
    )
    if hook_node is None:
        raise ApiError("В workflow нет webhook-триггера", 400, "no_webhook_trigger")
    params = (hook_node.get("data") or {}).get("params") or {}
    secret = params.get("secret") or ""
    if secret:
        try:
            secret = secret_box().decrypt(secret)
        except Exception:
            secret = ""
    raw_body = request.get_data(cache=True)
    if secret:
        signature = (
            request.headers.get("X-LDWarden-Signature")
            or request.headers.get("X-Hub-Signature-256")
            or ""
        )
        expected = "sha256=" + hmac.new(secret.encode(), raw_body, hashlib.sha256).hexdigest()
        if not signature or not hmac.compare_digest(signature, expected):
            raise ApiError("Неверная подпись webhook", 401, "invalid_signature")
    payload: dict = {}
    if raw_body:
        try:
            parsed = json.loads(raw_body)
            payload = parsed if isinstance(parsed, dict) else {"value": parsed}
        except ValueError:
            payload = {"raw": raw_body.decode("utf-8", errors="replace")[:5000]}
    target = payload.get("target") or request.args.get("target")
    target = validate_target(target)
    wait = get_bool(request.args.get("wait")) or bool(payload.get("wait"))
    run = engine().start_run(
        row.to_dict(),
        trigger="webhook",
        target=target,
        wait=wait,
        trigger_payload=payload,
    )
    return jsonify({"run_id": run["id"], "status": run.get("status", "queued")}), (200 if wait else 202)


@bp.post("/dev/inbox")
def inbox_receive():
    settings_ = settings()
    if not settings_.demo_inbox:
        raise ApiError("Демо-inbox отключён", 404, "not_found")
    data = request.get_json(silent=True)
    if isinstance(data, dict):
        run_id = data.get("run_id")
        subject = str(data.get("subject") or "")
        body = str(data.get("text") or data.get("body") or json.dumps(data, ensure_ascii=False))
    else:
        run_id = None
        subject = ""
        body = request.get_data(as_text=True)[:200_000]
    message = InboxMessageRow.create(
        run_id=run_id,
        channel="webhook",
        target=request.remote_addr or "",
        subject=subject[:300],
        body=body[:200_000],
        headers="{}",
        status="received",
    )
    return jsonify({"id": message.id, "status": "received"}), 202


@bp.get("/dev/inbox")
def inbox_list():
    if not settings().demo_inbox:
        raise ApiError("Демо-inbox отключён", 404, "not_found")
    limit = min(int(request.args.get("limit", 50)), 200)
    rows = list(InboxMessageRow.select().order_by(InboxMessageRow.created_at.desc()).limit(limit))
    return jsonify({"items": [row.to_dict() for row in rows]})


@bp.post("/telegram/connect")
def telegram_connect():
    try:
        return jsonify(telegram_service().connect())
    except TelegramError as exc:
        raise ApiError(str(exc), exc.status, "telegram_error") from exc


@bp.get("/telegram/chats")
def telegram_chats():
    state = request.args.get("state", "")
    if not state:
        raise ApiError("Укажите state", 400, "missing_state")
    try:
        return jsonify(telegram_service().poll(state))
    except TelegramError as exc:
        raise ApiError(str(exc), exc.status, "telegram_error") from exc


@bp.post("/telegram/link")
def telegram_link():
    data = json_body()
    state = str(data.get("state") or "")
    if not state:
        raise ApiError("Укажите state", 400, "missing_state")
    chat_id = data.get("chat_id")
    workflow_id = data.get("workflow_id")
    node_id = data.get("node_id")
    try:
        result = telegram_service().link(
            state,
            chat_id=chat_id,
            workflow_id=str(workflow_id) if workflow_id else None,
            node_id=str(node_id) if node_id else None,
        )
        if result.get("workflow"):
            result["workflow"] = serialize_workflow(WorkflowRow.get_by_id(result["workflow"]["id"]))
        return jsonify(result)
    except TelegramError as exc:
        raise ApiError(str(exc), exc.status, "telegram_error") from exc


@bp.get("/telegram/status")
def telegram_status():
    try:
        return jsonify(telegram_service().status())
    except TelegramError as exc:
        raise ApiError(str(exc), exc.status, "telegram_error") from exc


@bp.delete("/telegram/link")
def telegram_unlink():
    return jsonify(telegram_service().unlink())


@bp.get("/stats")
def stats():
    runs = RunRow.select().count()
    workflows = WorkflowRow.select().where(WorkflowRow.published == False).count()
    templates = WorkflowRow.select().where(WorkflowRow.published == True).count()
    findings = {}
    for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        findings[severity] = FindingRow.select().where(FindingRow.severity == severity).count()
    return jsonify(
        {
            "workflows": workflows,
            "templates": templates,
            "runs": runs,
            "findings": {**findings, "total": sum(findings.values())},
        }
    )


@bp.get("/openapi.json")
def openapi():
    base = request.host_url.rstrip("/")
    return jsonify(_openapi_spec(base))


def _openapi_spec(base: str) -> dict:
    return {
        "openapi": "3.0.3",
        "info": {
            "title": "LDWarden API",
            "version": APP_VERSION,
            "description": "Backend для визуального конструктора проверок безопасности (React Flow-совместимый граф).",
        },
        "servers": [{"url": base}],
        "paths": {
            "/api/health": {"get": {"summary": "Health check"}},
            "/api/meta": {"get": {"summary": "Метаданные и настройки"}},
            "/api/nodes": {"get": {"summary": "Каталог нод для React Flow"}},
            "/api/workflows": {
                "get": {"summary": "Список workflow"},
                "post": {"summary": "Создать workflow"},
            },
            "/api/workflows/{id}": {
                "get": {"summary": "Получить workflow"},
                "put": {"summary": "Обновить workflow"},
                "delete": {"summary": "Удалить workflow"},
            },
            "/api/workflows/{id}/runs": {"post": {"summary": "Запустить workflow"}},
            "/api/workflows/validate": {"post": {"summary": "Провалидировать черновик графа"}},
            "/api/runs": {"get": {"summary": "История запусков"}},
            "/api/runs/{id}": {"get": {"summary": "Детали запуска"}},
            "/api/runs/{id}/events": {"get": {"summary": "События выполнения (polling)"}},
            "/api/runs/{id}/stream": {"get": {"summary": "SSE-поток событий"}},
            "/api/runs/{id}/findings": {"get": {"summary": "Находки запуска"}},
            "/api/runs/{id}/report": {"get": {"summary": "Отчёт md/json/sarif"}},
            "/api/sources": {
                "get": {"summary": "Список источников"},
                "post": {"summary": "Загрузить ZIP проекта"},
            },
            "/api/templates": {"get": {"summary": "Библиотека шаблонов"}},
            "/api/templates/{id}/clone": {"post": {"summary": "Скопировать шаблон"}},
            "/api/ai/workflows/generate": {"post": {"summary": "Сгенерировать workflow по описанию"}},
            "/api/ci/run": {"post": {"summary": "Запуск из CI/CD"}},
            "/api/telegram/connect": {"post": {"summary": "Начать подключение Telegram-чата"}},
            "/api/telegram/chats": {"get": {"summary": "Найти чаты после Start"}},
            "/api/telegram/link": {"post": {"summary": "Сохранить chat_id и привязать к workflow"}},
            "/api/telegram/status": {"get": {"summary": "Статус Telegram-бота и привязки"}},
            "/api/hooks/{workflow_id}": {"post": {"summary": "Webhook-триггер"}},
            "/api/dev/inbox": {"get": {"summary": "Демо-inbox"}, "post": {"summary": "Приём webhook в демо"}},
        },
    }
