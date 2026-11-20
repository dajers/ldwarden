from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")


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
            result.append(Path(item).expanduser().resolve())
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
    default_target: Path = BASE_DIR / "training-main" / "training-project"
    allowed_roots: list[Path] = field(default_factory=list)
    vulnerability_db_path: Path = (
        BASE_DIR / "training-main" / "vulnerability-database" / "vulnerabilities.json"
    )
    workflow_templates_dir: Path = BASE_DIR / "app" / "workflow_templates"
    frontend_dir: Path = BASE_DIR / "app" / "frontend"


    max_file_bytes: int = 2 * 1024 * 1024
    max_files: int = 20_000
    max_upload_bytes: int = 80 * 1024 * 1024
    max_zip_entries: int = 5_000
    max_zip_uncompressed: int = 200 * 1024 * 1024


    llm_provider: str = "auto"
    llm_model_path: Path = BASE_DIR / "llms" / "qwen2.5-coder-7b-instruct-q4_k_m.gguf"
    llm_base_url: str = ""
    llm_api_key: str = ""
    llm_model: str = ""
    llm_timeout: int = 180
    llm_max_findings: int = 30
    llm_temperature: float = 0.2
    llm_n_ctx: int = 8192
    llm_n_threads: int = 0
    telegram_bot_token: str = ""
    telegram_chat_id: str = ""


    api_token: str = ""
    ci_token: str = ""
    cors_origins: str = "*"
    allow_local_webhooks: bool = True
    allowed_git_hosts: list[str] = field(default_factory=list)
    git_timeout: int = 120


    enable_scheduler: bool = False
    scheduler_interval: int = 30
    scheduler_timezone: str = "UTC"


    seed_templates: bool = True
    log_level: str = "INFO"
    demo_inbox: bool = True

    def __post_init__(self) -> None:
        self.data_dir = Path(self.data_dir).expanduser().resolve()
        self.db_path = Path(self.db_path).expanduser().resolve()
        self.sources_dir = Path(self.sources_dir).expanduser().resolve()
        self.tmp_dir = Path(self.tmp_dir).expanduser().resolve()
        self.secret_key_path = Path(self.secret_key_path).expanduser().resolve()
        self.default_target = Path(self.default_target).expanduser().resolve()
        self.vulnerability_db_path = Path(self.vulnerability_db_path).expanduser().resolve()
        self.workflow_templates_dir = Path(self.workflow_templates_dir).expanduser().resolve()
        self.frontend_dir = Path(self.frontend_dir).expanduser().resolve()
        self.llm_model_path = Path(self.llm_model_path).expanduser().resolve()
        if not self.allowed_roots:
            self.allowed_roots = [
                self.base_dir / "training-main",
                self.base_dir / "samples",
                self.sources_dir,
            ]
        self.allowed_roots = [Path(p).expanduser().resolve() for p in self.allowed_roots]


    def ensure_dirs(self) -> None:
        for path in (self.data_dir, self.sources_dir, self.tmp_dir):
            path.mkdir(parents=True, exist_ok=True)

    def resolve_allowed_path(self, value: str | Path) -> Path:
        """Resolve a user supplied path and ensure it stays inside allowed roots."""
        path = Path(value).expanduser()
        if not path.is_absolute():
            path = self.base_dir / path
        resolved = path.resolve()
        for root in self.allowed_roots:
            root = root.resolve()
            if resolved == root or root in resolved.parents:
                return resolved
        raise PermissionError(
            "Сканирование разрешено только внутри разрешённых каталогов: "
            + ", ".join(str(p) for p in self.allowed_roots)
        )

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
            "llm": {
                "provider": self.effective_llm_provider,
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
            _str("LDWARDEN_DEFAULT_TARGET", str(BASE_DIR / "training-main" / "training-project"))
        ),
        allowed_roots=allowed,
        vulnerability_db_path=Path(
            _str(
                "LDWARDEN_VULN_DB",
                str(BASE_DIR / "training-main" / "vulnerability-database" / "vulnerabilities.json"),
            )
        ),
        max_file_bytes=_int("LDWARDEN_MAX_FILE_BYTES", 2 * 1024 * 1024),
        max_files=_int("LDWARDEN_MAX_FILES", 20_000),
        max_upload_bytes=_int("LDWARDEN_MAX_UPLOAD_BYTES", 80 * 1024 * 1024),
        max_zip_entries=_int("LDWARDEN_MAX_ZIP_ENTRIES", 5_000),
        max_zip_uncompressed=_int("LDWARDEN_MAX_ZIP_UNCOMPRESSED", 200 * 1024 * 1024),
        llm_provider=_str("LDWARDEN_LLM_PROVIDER", "auto").lower(),
        llm_model_path=Path(
            _str(
                "LDWARDEN_LLM_MODEL_PATH",
                str(BASE_DIR / "llms" / "qwen2.5-coder-7b-instruct-q4_k_m.gguf"),
            )
        ),
        llm_base_url=_str("LDWARDEN_LLM_BASE_URL", ""),
        llm_api_key=_str("LDWARDEN_LLM_API_KEY", ""),
        llm_model=_str("LDWARDEN_LLM_MODEL", ""),
        llm_timeout=_int("LDWARDEN_LLM_TIMEOUT", 180),
        llm_max_findings=_int("LDWARDEN_LLM_MAX_FINDINGS", 30),
        llm_temperature=_float("LDWARDEN_LLM_TEMPERATURE", 0.2),
        llm_n_ctx=_int("LDWARDEN_LLM_N_CTX", 8192),
        llm_n_threads=_int("LDWARDEN_LLM_THREADS", 0),
        telegram_bot_token=_str("LDWARDEN_TELEGRAM_BOT_TOKEN", ""),
        telegram_chat_id=_str("LDWARDEN_TELEGRAM_CHAT_ID", ""),
        api_token=_str("LDWARDEN_API_TOKEN", ""),
        ci_token=_str("LDWARDEN_CI_TOKEN", ""),
        cors_origins=_str("LDWARDEN_CORS_ORIGINS", "*"),
        allow_local_webhooks=_bool("LDWARDEN_ALLOW_LOCAL_WEBHOOKS", True),
        allowed_git_hosts=[h.strip().lower() for h in _str("LDWARDEN_ALLOWED_GIT_HOSTS", "").split(",") if h.strip()],
        git_timeout=_int("LDWARDEN_GIT_TIMEOUT", 120),
        enable_scheduler=_bool("LDWARDEN_ENABLE_SCHEDULER", False),
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
