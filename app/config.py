from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")


def default_training_target(base: Path = BASE_DIR) -> Path:
    """Новый training-main лежит корнем, старый — в training-project/."""
    legacy = base / "training-main" / "training-project"
    if legacy.is_dir():
        return legacy
    return base / "training-main"


def _str(name: str, default: str = "") -> str:
    value = os.getenv(name)
    return default if value is None else value.strip()


def _int(name: str, default: int) -> int:
    try:
        return int(_str(name, str(default)))
    except ValueError:
        return default


def _float(name: str, default: float) -> float:
    try:
        return float(_str(name, str(default)))
    except ValueError:
        return default


def _bool(name: str, default: bool = False) -> bool:
    value = _str(name, "")
    if value == "":
        return default
    return value.lower() in {"1", "true", "yes", "on", "y"}


def _paths(name: str) -> list[Path]:
    raw = _str(name, "")
    result: list[Path] = []
    for chunk in raw.replace(",", os.pathsep).split(os.pathsep):
        item = chunk.strip()
        if item:

            result.append(Path(item).expanduser())
    return result


@dataclass
class Settings:
    """Runtime settings shared by the API, engine and analyzers."""

    base_dir: Path = BASE_DIR
    data_dir: Path = BASE_DIR / "data"
    db_path: Path = BASE_DIR / "data" / "ldwarden.db"
    sources_dir: Path = BASE_DIR / "data" / "sources"
    tmp_dir: Path = BASE_DIR / "data" / "tmp"
    secret_key_path: Path = BASE_DIR / "data" / "secret.key"
    default_target: Path = default_training_target()
    allowed_roots: list[Path] = field(default_factory=list)
    allow_arbitrary_paths: bool = False
    allow_absolute_paths: bool = True
    vulnerability_db_path: Path = BASE_DIR / "app" / "vulnerability-database" / "vulnerabilities.json"
    workflow_templates_dir: Path = BASE_DIR / "app" / "workflow_templates"
    frontend_dir: Path = BASE_DIR / "app" / "frontend"


    max_file_bytes: int = 2 * 1024 * 1024
    max_files: int = 20_000
    max_upload_bytes: int = 80 * 1024 * 1024
    max_zip_entries: int = 5_000
    max_zip_uncompressed: int = 200 * 1024 * 1024


    llm_provider: str = "auto"
    llm_models_dir: Path = BASE_DIR / "llms"
    llm_model_path: Path = BASE_DIR / "llms" / "qwen2.5-coder-7b-instruct-q4_k_m.gguf"
    llm_base_url: str = ""
    llm_api_key: str = ""
    llm_api_headers: str = ""
    llm_auth_header: str = "Authorization"
    llm_auth_prefix: str = "Bearer"
    llm_model: str = ""
    llm_timeout: int = 180
    llm_max_findings: int = 30
    llm_temperature: float = 0.2
    llm_n_ctx: int = 4096
    llm_n_threads: int = 4
    telegram_bot_token: str = ""
    telegram_chat_id: str = ""


    api_token: str = ""
    ci_token: str = ""
    cors_origins: str = "*"
    allow_local_webhooks: bool = True
    allowed_git_hosts: list[str] = field(default_factory=list)
    git_timeout: int = 120
    git_token: str = ""
    git_username: str = "x-access-token"
    library_repo: str = ""
    library_branch: str = "main"
    library_path: str = "presets"
    library_token: str = ""
    library_api_url: str = "https://api.github.com"


    enable_scheduler: bool = True
    scheduler_interval: int = 30
    scheduler_timezone: str = "UTC"


    seed_templates: bool = True
    log_level: str = "INFO"
    demo_inbox: bool = True

    def _resolve_path(self, value: str | Path) -> Path:
        path = Path(value).expanduser()
        if not path.is_absolute():
            path = self.base_dir / path
        return path.resolve()

    def __post_init__(self) -> None:
        self.base_dir = Path(self.base_dir).expanduser().resolve()
        self.data_dir = self._resolve_path(self.data_dir)
        self.db_path = self._resolve_path(self.db_path)
        self.sources_dir = self._resolve_path(self.sources_dir)
        self.tmp_dir = self._resolve_path(self.tmp_dir)
        self.secret_key_path = self._resolve_path(self.secret_key_path)
        self.default_target = self._resolve_path(self.default_target)
        self.vulnerability_db_path = self._resolve_path(self.vulnerability_db_path)
        self.workflow_templates_dir = self._resolve_path(self.workflow_templates_dir)
        self.frontend_dir = self._resolve_path(self.frontend_dir)
        self.llm_models_dir = self._resolve_path(self.llm_models_dir)
        self.llm_model_path = self._resolve_model_path(self.llm_model_path)
        if not self.allowed_roots:
            self.allowed_roots = [
                self.base_dir / "training-main",
                self.base_dir / "samples",
                self.sources_dir,
            ]
        self.allowed_roots = [self._resolve_path(p) for p in self.allowed_roots]


    def _resolve_model_path(self, value: str | Path) -> Path:
        """Ищет файл модели: относительный путь считается от корня проекта."""
        path = Path(value).expanduser()
        path = (self.base_dir / path).resolve() if not path.is_absolute() else path.resolve()
        if path.exists():
            return path

        if self.llm_models_dir.exists():
            matches = sorted(self.llm_models_dir.rglob(path.name))
            if matches:
                return matches[0].resolve()
        return path

    def ensure_dirs(self) -> None:
        for path in (self.data_dir, self.sources_dir, self.tmp_dir):
            path.mkdir(parents=True, exist_ok=True)

    def resolve_allowed_path(self, value: str | Path) -> Path:
        """Resolve a user supplied path against the configured allow-list.

        Абсолютный путь разрешён по умолчанию (удобно для локального проекта).
        Относительные пути ограничены LDWARDEN_ALLOWED_ROOTS. Для публичного
        контура отключите абсолютные пути:
        LDWARDEN_ALLOW_ABSOLUTE_PATHS=false.
        """
        path = Path(value).expanduser()
        if not path.is_absolute():
            path = self.base_dir / path
        resolved = path.resolve()
        if not resolved.exists():
            raise FileNotFoundError(f"Источник не найден: {resolved}")



        if self.allow_absolute_paths and Path(value).expanduser().is_absolute():
            return resolved
        if self.allow_arbitrary_paths:
            return resolved
        allowed = any(
            resolved == root or root in resolved.parents for root in self.allowed_roots
        )
        if not allowed:
            raise PermissionError(
                "Сканирование этого пути запрещено. Добавьте проект в "
                "LDWARDEN_ALLOWED_ROOTS или включите "
                "LDWARDEN_ALLOW_ARBITRARY_PATHS=true для локального использования."
            )
        return resolved

    def is_allowed_path(self, value: str | Path) -> bool:
        try:
            self.resolve_allowed_path(value)
            return True
        except (PermissionError, OSError):
            return False

    def source_dir(self, source_id: str) -> Path:
        if not source_id or not source_id.replace("-", "").isalnum():
            raise ValueError("Некорректный идентификатор источника")
        path = (self.sources_dir / source_id).resolve()
        if self.sources_dir not in path.parents and path != self.sources_dir:
            raise ValueError("Некорректный путь источника")
        return path

    @property
    def effective_llm_provider(self) -> str:
        provider = (self.llm_provider or "auto").lower()
        if provider != "auto":
            return provider
        if self.llm_base_url:
            return "openai"
        if self.llm_model_path.exists():
            return "local"
        return "none"

    def public_dict(self) -> dict:
        """Settings safe to expose through the API (no secrets)."""
        return {
            "default_target": str(self.default_target),
            "allowed_roots": [str(p) for p in self.allowed_roots],
            "allow_absolute_paths": self.allow_absolute_paths,
            "allow_arbitrary_paths": self.allow_arbitrary_paths,
            "llm": {
                "provider": self.effective_llm_provider,
                "models_dir": str(self.llm_models_dir),
                "model_path": str(self.llm_model_path),
                "model": self.llm_model,
                "base_url": self.llm_base_url,
                "max_findings": self.llm_max_findings,
            },
            "scheduler": {
                "enabled": self.enable_scheduler,
                "interval": self.scheduler_interval,
                "timezone": self.scheduler_timezone,
            },
            "max_file_bytes": self.max_file_bytes,
            "max_files": self.max_files,
            "frontend": str(self.frontend_dir),
            "git": {
                "hosts": list(self.allowed_git_hosts),
                "token_configured": bool(self.git_token),
            },
            "library": {
                "configured": bool(self.library_repo),
                "publish_enabled": bool(self.library_repo and (self.library_token or self.git_token)),
                "repo": self.library_repo,
                "branch": self.library_branch,
                "path": self.library_path,
            },
            "telegram": {
                "configured": bool(self.telegram_bot_token),
                "chat_id_configured": bool(self.telegram_chat_id),
            },
        }


def load_settings(overrides: dict | None = None) -> Settings:
    """Build settings from the environment, then apply explicit overrides."""
    data_dir = Path(_str("LDWARDEN_DATA_DIR", str(BASE_DIR / "data"))).expanduser()
    allowed = _paths("LDWARDEN_ALLOWED_ROOTS")
    if not allowed:
        allowed = [
            BASE_DIR / "training-main",
            BASE_DIR / "samples",
            data_dir / "sources",
        ]

    settings = Settings(
        base_dir=BASE_DIR,
        data_dir=data_dir,
        db_path=Path(_str("LDWARDEN_DB_PATH", str(data_dir / "ldwarden.db"))),
        sources_dir=Path(_str("LDWARDEN_SOURCES_DIR", str(data_dir / "sources"))),
        tmp_dir=Path(_str("LDWARDEN_TMP_DIR", str(data_dir / "tmp"))),
        secret_key_path=Path(_str("LDWARDEN_SECRET_KEY_FILE", str(data_dir / "secret.key"))),
        default_target=Path(
            _str("LDWARDEN_DEFAULT_TARGET", str(default_training_target()))
        ),
        allowed_roots=allowed,
        vulnerability_db_path=Path(
            _str(
                "LDWARDEN_VULN_DB",
                str(BASE_DIR / "app" / "vulnerability-database" / "vulnerabilities.json"),
            )
        ),
        max_file_bytes=_int("LDWARDEN_MAX_FILE_BYTES", 2 * 1024 * 1024),
        max_files=_int("LDWARDEN_MAX_FILES", 20_000),
        max_upload_bytes=_int("LDWARDEN_MAX_UPLOAD_BYTES", 80 * 1024 * 1024),
        max_zip_entries=_int("LDWARDEN_MAX_ZIP_ENTRIES", 5_000),
        max_zip_uncompressed=_int("LDWARDEN_MAX_ZIP_UNCOMPRESSED", 200 * 1024 * 1024),
        llm_provider=_str("LDWARDEN_LLM_PROVIDER", "auto").lower(),
        llm_models_dir=Path(
            _str("LDWARDEN_LLM_MODELS_DIR", str(BASE_DIR / "llms"))
        ),
        llm_model_path=Path(
            _str(
                "LDWARDEN_LLM_MODEL_PATH",
                str(BASE_DIR / "llms" / "qwen2.5-coder-7b-instruct-q4_k_m.gguf"),
            )
        ),
        llm_base_url=_str("LDWARDEN_LLM_BASE_URL", ""),
        llm_api_key=_str("LDWARDEN_LLM_API_KEY", ""),
        llm_api_headers=_str("LDWARDEN_LLM_API_HEADERS", ""),
        llm_auth_header=_str("LDWARDEN_LLM_AUTH_HEADER", "Authorization"),
        llm_auth_prefix=_str("LDWARDEN_LLM_AUTH_PREFIX", "Bearer"),
        llm_model=_str("LDWARDEN_LLM_MODEL", ""),
        llm_timeout=_int("LDWARDEN_LLM_TIMEOUT", 180),
        llm_max_findings=_int("LDWARDEN_LLM_MAX_FINDINGS", 30),
        llm_temperature=_float("LDWARDEN_LLM_TEMPERATURE", 0.2),
        llm_n_ctx=_int("LDWARDEN_LLM_N_CTX", 4096),
        llm_n_threads=_int("LDWARDEN_LLM_THREADS", 4),
        telegram_bot_token=_str("LDWARDEN_TELEGRAM_BOT_TOKEN", ""),
        telegram_chat_id=_str("LDWARDEN_TELEGRAM_CHAT_ID", ""),
        api_token=_str("LDWARDEN_API_TOKEN", ""),
        ci_token=_str("LDWARDEN_CI_TOKEN", ""),
        cors_origins=_str("LDWARDEN_CORS_ORIGINS", "*"),
        allow_local_webhooks=_bool("LDWARDEN_ALLOW_LOCAL_WEBHOOKS", True),
        allowed_git_hosts=[h.strip().lower() for h in _str("LDWARDEN_ALLOWED_GIT_HOSTS", "").split(",") if h.strip()],
        allow_arbitrary_paths=_bool("LDWARDEN_ALLOW_ARBITRARY_PATHS", False),
        allow_absolute_paths=_bool("LDWARDEN_ALLOW_ABSOLUTE_PATHS", True),
        git_timeout=_int("LDWARDEN_GIT_TIMEOUT", 120),
        git_token=_str("LDWARDEN_GIT_TOKEN", ""),
        git_username=_str("LDWARDEN_GIT_USERNAME", "x-access-token"),
        library_repo=_str("LDWARDEN_LIBRARY_REPO", ""),
        library_branch=_str("LDWARDEN_LIBRARY_BRANCH", "main"),
        library_path=_str("LDWARDEN_LIBRARY_PATH", "presets"),
        library_token=_str("LDWARDEN_LIBRARY_TOKEN", ""),
        library_api_url=_str("LDWARDEN_LIBRARY_API_URL", "https://api.github.com"),
        enable_scheduler=_bool("LDWARDEN_ENABLE_SCHEDULER", True),
        scheduler_interval=_int("LDWARDEN_SCHEDULER_INTERVAL", 30),
        scheduler_timezone=_str("LDWARDEN_SCHEDULER_TZ", "UTC"),
        seed_templates=_bool("LDWARDEN_SEED_TEMPLATES", True),
        log_level=_str("LDWARDEN_LOG_LEVEL", "INFO").upper(),
        demo_inbox=_bool("LDWARDEN_DEMO_INBOX", True),
        frontend_dir=Path(
            _str("LDWARDEN_FRONTEND_DIR", str(BASE_DIR / "app" / "frontend"))
        ),
    )
    if overrides:
        for key, value in overrides.items():
            if hasattr(settings, key):
                setattr(settings, key, value)
        settings.__post_init__()
    settings.ensure_dirs()
    return settings
