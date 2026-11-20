from __future__ import annotations

import atexit
import logging
import uuid

from flask import Flask, abort, jsonify, request, send_from_directory
from werkzeug.exceptions import HTTPException
from flask_cors import CORS

import app.nodes
from app.api.common import ApiError, require_api_token
from app.api.misc import bp as misc_bp
from app.api.runs import bp as runs_bp
from app.api.workflows import bp as workflows_bp
from app.config import Settings, load_settings
from app.core.engine import WorkflowEngine
from app.core.source import SourceService
from app.crypto import SecretBox
from app.db import init_db
from app.services.scheduler import ScheduleService
from app.services.telegram import TelegramService

logger = logging.getLogger(__name__)


def create_app(settings_override: Settings | None = None) -> Flask:
    settings = settings_override or load_settings()
    logging.basicConfig(
        level=getattr(logging, settings.log_level, logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    settings.ensure_dirs()
    init_db(settings)

    flask_app = Flask(__name__)
    flask_app.config["MAX_CONTENT_LENGTH"] = settings.max_upload_bytes
    flask_app.config["JSON_SORT_KEYS"] = False
    flask_app.json.ensure_ascii = False

    origins = "*" if settings.cors_origins.strip() == "*" else [
        item.strip() for item in settings.cors_origins.split(",") if item.strip()
    ]
    CORS(
        flask_app,
        resources={r"/api/*": {"origins": origins}},
        expose_headers=["Content-Disposition"],
        allow_headers=["Content-Type", "Authorization", "X-API-Token", "X-CI-Token", "X-LDWarden-Signature"],
    )

    engine = WorkflowEngine(settings)
    flask_app.extensions["ldwarden_settings"] = settings
    flask_app.extensions["ldwarden_engine"] = engine
    flask_app.extensions["ldwarden_source_service"] = SourceService(settings)
    flask_app.extensions["ldwarden_secret_box"] = SecretBox(settings.secret_key_path)
    flask_app.extensions["ldwarden_telegram"] = TelegramService(settings)

    flask_app.register_blueprint(misc_bp, url_prefix="/api")
    flask_app.register_blueprint(workflows_bp, url_prefix="/api")
    flask_app.register_blueprint(runs_bp, url_prefix="/api")

    @flask_app.before_request
    def authenticate():
        if request.method == "OPTIONS":
            return None
        if request.path.startswith("/api"):
            require_api_token(settings, request.path)
        return None

    @flask_app.after_request
    def security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        if request.path.startswith("/api/"):
            response.headers.setdefault("Cache-Control", "no-store")
        return response

    @flask_app.errorhandler(ApiError)
    def handle_api_error(exc: ApiError):
        return (
            jsonify(
                {
                    "error": {
                        "code": exc.code,
                        "message": exc.message,
                        "details": exc.details,
                        "request_id": getattr(request, "ldwarden_request_id", None),
                    }
                }
            ),
            exc.status,
        )

    @flask_app.errorhandler(HTTPException)
    def handle_http_exception(exc: HTTPException):
        return (
            jsonify(
                {
                    "error": {
                        "code": (exc.name or "http_error").lower().replace(" ", "_"),
                        "message": exc.description or exc.name,
                    }
                }
            ),
            exc.code or 500,
        )

    @flask_app.errorhandler(404)
    def handle_404(_exc):
        if request.path.startswith("/api"):
            return jsonify({"error": {"code": "not_found", "message": "Маршрут не найден"}}), 404
        return jsonify({"error": {"code": "not_found", "message": "Страница не найдена"}}), 404

    @flask_app.errorhandler(413)
    def handle_413(_exc):
        return (
            jsonify(
                {
                    "error": {
                        "code": "payload_too_large",
                        "message": f"Файл больше допустимого размера ({settings.max_upload_bytes} байт)",
                    }
                }
            ),
            413,
        )

    @flask_app.errorhandler(PermissionError)
    def handle_permission(exc):
        return jsonify({"error": {"code": "forbidden", "message": str(exc)}}), 403

    @flask_app.errorhandler(ValueError)
    def handle_value(exc):
        return jsonify({"error": {"code": "bad_request", "message": str(exc)}}), 400

    @flask_app.errorhandler(Exception)
    def handle_unexpected(exc):
        request_id = uuid.uuid4().hex[:8]
        logger.exception("Необработанная ошибка API (request_id=%s)", request_id)
        if not request.path.startswith("/api"):
            return jsonify({"error": {"code": "internal_error", "message": "Внутренняя ошибка"}}), 500
        return (
            jsonify(
                {
                    "error": {
                        "code": "internal_error",
                        "message": "Внутренняя ошибка сервера",
                        "request_id": request_id,
                    }
                }
            ),
            500,
        )

    frontend_dir = settings.frontend_dir

    def frontend_file(filename: str):
        path = frontend_dir / filename
        if not path.is_file():
            abort(404)
        return send_from_directory(frontend_dir, filename)

    @flask_app.get("/")
    def index():
        if (frontend_dir / "index.html").is_file():
            return send_from_directory(frontend_dir, "index.html")
        return jsonify(
            {
                "name": "LDWarden",
                "message": "Backend визуального конструктора проверок безопасности",
                "docs": "/api/meta",
                "openapi": "/api/openapi.json",
                "nodes": "/api/nodes",
                "templates": "/api/templates",
            }
        )

    @flask_app.get("/index.html")
    def index_file():
        return frontend_file("index.html")

    @flask_app.get("/styles.css")
    def styles():
        return frontend_file("styles.css")

    @flask_app.get("/js/<path:filename>")
    def frontend_js(filename: str):
        return frontend_file(f"js/{filename}")

    @flask_app.get("/assets/<path:filename>")
    def frontend_assets(filename: str):
        return frontend_file(f"assets/{filename}")

    @flask_app.get("/favicon.ico")
    def favicon():
        if (frontend_dir / "favicon.ico").is_file():
            return send_from_directory(frontend_dir, "favicon.ico")
        abort(404)

    @flask_app.get("/api")
    def api_index():
        return jsonify({"name": "LDWarden API", "meta": "/api/meta", "health": "/api/health"})

    scheduler = None
    if settings.enable_scheduler:
        scheduler = ScheduleService(settings, engine)
        scheduler.start()
        flask_app.extensions["ldwarden_scheduler"] = scheduler
        atexit.register(scheduler.stop)

    logger.info(
        "LDWarden backend готов: target=%s, LLM=%s, scheduler=%s",
        settings.default_target,
        settings.effective_llm_provider,
        settings.enable_scheduler,
    )
    return flask_app
