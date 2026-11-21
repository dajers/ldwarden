from __future__ import annotations

import base64
import copy
import hashlib
import json
import re
import threading
import time
from datetime import datetime, timezone
from urllib.parse import quote, urlparse

import httpx

from app.config import Settings


class LibraryError(RuntimeError):
    pass


class PresetLibrary:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.config_error = ""
        try:
            self.repo = self._parse_repo(settings.library_repo)
        except LibraryError as exc:
            self.repo = ""
            self.config_error = str(exc)
        self.branch = (settings.library_branch or "main").strip()
        self.path = (settings.library_path or "presets").strip("/")
        self.token = settings.library_token or settings.git_token
        self.api_url = (settings.library_api_url or "https://api.github.com").rstrip("/")
        self._cache_lock = threading.Lock()
        self._cache_data = None
        self._cache_at = 0.0
        self.cache_ttl = 60

    @staticmethod
    def _parse_repo(value: str) -> str:
        raw = (value or "").strip()
        if not raw:
            return ""
        if raw.startswith("http://") or raw.startswith("https://"):
            raw = urlparse(raw).path.strip("/")
        raw = raw.removesuffix(".git").strip("/")
        parts = [part for part in raw.split("/") if part]
        if len(parts) < 2:
            raise LibraryError("LDWARDEN_LIBRARY_REPO должен быть в формате owner/repository")
        return f"{parts[0]}/{parts[1]}"

    @property
    def configured(self) -> bool:
        return bool(self.repo)

    @property
    def can_publish(self) -> bool:
        return bool(self.repo and self.token)

    def status(self) -> dict:
        return {
            "configured": self.configured,
            "publish_enabled": self.can_publish,
            "repo": self.repo,
            "branch": self.branch,
            "path": self.path,
            "url": f"https://github.com/{self.repo}" if self.repo else "",
            "error": self.config_error,
        }

    def _headers(self, accept: str = "application/vnd.github+json") -> dict:
        headers = {
            "Accept": accept,
            "User-Agent": "ldwarden-preset-library",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    def _request(self, method: str, path: str, **kwargs):
        if not self.repo:
            raise LibraryError("Библиотека не настроена: задайте LDWARDEN_LIBRARY_REPO")
        url = path if path.startswith("http") else f"{self.api_url}{path}"
        headers = {**self._headers(), **(kwargs.pop("headers", None) or {})}
        try:
            with httpx.Client(timeout=25, follow_redirects=True) as client:
                response = client.request(method, url, headers=headers, **kwargs)
        except httpx.HTTPError as exc:
            raise LibraryError(f"GitHub недоступен: {exc}") from exc
        if response.status_code >= 400:
            message = response.text[:300].strip()
            raise LibraryError(f"GitHub API {response.status_code}: {message}")
        return response

    def _directory(self) -> list[dict]:
        target = quote(self.path, safe="/")
        response = self._request(
            "GET",
            f"/repos/{self.repo}/contents/{target}",
            params={"ref": self.branch},
        )
        data = response.json()
        if isinstance(data, dict):
            return [data]
        if not isinstance(data, list):
            raise LibraryError("GitHub вернул неожиданный ответ для каталога пресетов")
        return data

    def _download(self, item: dict) -> dict | None:
        if item.get("type") != "file" or not str(item.get("name", "")).endswith(".json"):
            return None
        url = item.get("download_url") or item.get("url")
        if not url:
            return None
        response = self._request("GET", url, headers=self._headers("application/vnd.github.raw"))
        try:
            document = json.loads(response.text)
        except (TypeError, ValueError):
            return None
        if not isinstance(document, dict):
            return None
        graph = document.get("graph") if isinstance(document.get("graph"), dict) else document
        if not isinstance(graph, dict) or not isinstance(graph.get("nodes"), list):
            return None
        name = str(document.get("name") or item.get("name") or "Без названия")[:160]
        return {
            "id": str(document.get("id") or item.get("name") or name),
            "name": name,
            "description": str(document.get("description") or "")[:4000],
            "tags": [str(tag)[:40] for tag in (document.get("tags") or [])][:20]
            if isinstance(document.get("tags"), list)
            else [],
            "author": str(document.get("author") or "")[:80],
            "updated_at": document.get("updated_at") or item.get("updated_at") or "",
            "path": item.get("path") or "",
            "html_url": item.get("html_url") or "",
            "graph": graph,
        }

    def list_presets(self, force: bool = False) -> dict:
        if not self.configured:
            return {**self.status(), "items": []}
        now = time.monotonic()
        with self._cache_lock:
            if not force and self._cache_data is not None and now - self._cache_at < self.cache_ttl:
                cached = copy.deepcopy(self._cache_data)
                cached["cached"] = True
                cached["cached_age"] = round(now - self._cache_at, 1)
                return cached
        try:
            entries = self._directory()
        except LibraryError as exc:
            if "404" in str(exc):
                return {**self.status(), "items": [], "cached": False}
            raise
        items = []
        for entry in entries:
            item = self._download(entry)
            if item is not None:
                items.append(item)
        items.sort(key=lambda item: item["name"].lower())
        data = {**self.status(), "items": items, "cached": False, "cached_age": 0}
        with self._cache_lock:
            self._cache_data = copy.deepcopy(data)
            self._cache_at = time.monotonic()
        return data

    def publish(self, graph: dict, *, name: str, description: str = "", tags: list[str] | None = None, author: str = "local") -> dict:
        if not self.configured:
            raise LibraryError("Библиотека не настроена: задайте LDWARDEN_LIBRARY_REPO")
        if not self.token:
            raise LibraryError("Для публикации задайте LDWARDEN_LIBRARY_TOKEN")
        now = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        slug = re.sub(r"[^a-zA-Z0-9._-]+", "-", name.lower()).strip("-")[:48]
        digest = hashlib.sha1(name.encode("utf-8")).hexdigest()[:8]
        safe_name = f"{slug or 'preset'}-{digest}"
        file_path = f"{self.path}/{safe_name}.json"
        preset = {
            "format": "ldwarden-preset/v1",
            "id": f"{safe_name}-{now[:10]}",
            "name": name[:160],
            "description": description[:4000],
            "tags": [str(tag)[:40] for tag in (tags or [])][:20],
            "author": author[:80],
            "updated_at": now,
            "graph": graph,
        }
        payload = {
            "message": f"publish preset: {name[:120]}",
            "content": base64.b64encode(json.dumps(preset, ensure_ascii=False, indent=2).encode("utf-8")).decode("ascii"),
            "branch": self.branch,
        }
        try:
            existing = self._request(
                "GET",
                f"/repos/{self.repo}/contents/{quote(file_path, safe='/')}",
                params={"ref": self.branch},
            )
        except LibraryError as exc:
            if "404" not in str(exc):
                raise
            existing = None
        if existing is not None and existing.status_code == 200:
            payload["sha"] = existing.json().get("sha")
        response = self._request(
            "PUT",
            f"/repos/{self.repo}/contents/{quote(file_path, safe='/')}",
            json=payload,
        )
        data = response.json()
        with self._cache_lock:
            self._cache_data = None
            self._cache_at = 0.0
        return {
            "path": file_path,
            "url": (data.get("content") or {}).get("html_url") or f"https://github.com/{self.repo}/blob/{self.branch}/{file_path}",
            "commit": (data.get("commit") or {}).get("sha") or "",
            "preset": preset,
        }
