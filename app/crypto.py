from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Iterable

from cryptography.fernet import Fernet, InvalidToken

ENC_PREFIX = "enc:v1:"
MASK = "••••••"


class SecretBoxError(RuntimeError):
    pass


class SecretBox:
    def __init__(self, key_path: Path | str, key: str | None = None):
        self.key_path = Path(key_path)
        self._fernet = Fernet(self._load_or_create(key))

    def _load_or_create(self, key: str | None) -> bytes:
        if key:
            candidate = key.encode()
        elif self.key_path.exists():
            candidate = self.key_path.read_bytes().strip()
        else:
            candidate = Fernet.generate_key()
            self.key_path.parent.mkdir(parents=True, exist_ok=True)
            self.key_path.write_bytes(candidate)
            try:
                os.chmod(self.key_path, 0o600)
            except OSError:
                pass
        try:
            Fernet(candidate)
        except (ValueError, TypeError) as exc:
            raise SecretBoxError(
                f"Некорректный ключ шифрования в {self.key_path}: {exc}"
            ) from exc
        return candidate

    def encrypt(self, value: str) -> str:
        if value is None:
            return ""
        if value.startswith(ENC_PREFIX):
            return value
        token = self._fernet.encrypt(str(value).encode()).decode()
        return ENC_PREFIX + token

    def decrypt(self, value: str) -> str:
        if not value or not value.startswith(ENC_PREFIX):
            return value or ""
        try:
            return self._fernet.decrypt(value[len(ENC_PREFIX):].encode()).decode()
        except InvalidToken as exc:
            raise SecretBoxError(
                "Не удалось расшифровать секрет: ключ не совпадает с тем, "
                "которым он был зашифрован"
            ) from exc

    def is_encrypted(self, value: str | None) -> bool:
        return bool(value) and str(value).startswith(ENC_PREFIX)


def mask_value(value: str | None, keep: int = 3) -> str:
    """Полностью скрывает значение секрета — без префиксов и суффиксов."""
    if not value:
        return ""
    return "••••••"


def mask_for_api(value: str | None) -> dict:
    return {"has_value": bool(value), "preview": mask_value(value) if value else ""}


_PLACEHOLDER_HINTS = re.compile(
    r"(?i)(<[^>]*>|\$\{[^}]*\}|your[_-]?|example|sample|placeholder|changeme|change_me|"
    r"replace[_-]?me|dummy|fake|redacted|not[_-]?a[_-]?real|todo|xxx)"
)


def looks_like_placeholder(value: str | None) -> bool:
    if not value:
        return True
    text = str(value).strip()
    if not text:
        return True
    if _PLACEHOLDER_HINTS.search(text):
        return True
    if text.lower() in {
        "password",
        "passwd",
        "secret",
        "token",
        "apikey",
        "api_key",
        "none",
        "null",
        "undefined",
        "true",
        "false",
    }:
        return True
    return False


def scrub_text(text: str, secrets: Iterable[str]) -> str:
    """Replace known secret values inside free-form text (logs, payloads)."""
    result = text or ""
    for secret in secrets:
        if secret and len(secret) >= 4:
            result = result.replace(secret, MASK)
    return result
