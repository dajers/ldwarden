from __future__ import annotations

import json
import os
import threading
import time
from typing import Any

from app.ai.prompts import build_analysis_request
from app.config import Settings


class ProviderUnavailable(RuntimeError):
    pass


class ProviderStopped(RuntimeError):
    def __init__(self, reason: str = "cancelled"):
        super().__init__(reason)
        self.reason = reason


_PROVIDER_CACHE: dict[tuple, "LLMProvider"] = {}
_PROVIDER_LOCK = threading.Lock()


def _cached(key: tuple, factory) -> "LLMProvider":
    with _PROVIDER_LOCK:
        provider = _PROVIDER_CACHE.get(key)
        if provider is None:
            provider = factory()
            _PROVIDER_CACHE[key] = provider
        return provider


def _stop_reason(cancel_event, deadline: float | None) -> str | None:
    if cancel_event is not None and cancel_event.is_set():
        return "cancelled"
    if deadline is not None and time.monotonic() >= deadline:
        return "timeout"
    return None


class LLMProvider:
    name = "base"
    model = ""

    def complete(
        self,
        messages: list[dict],
        *,
        response_format: dict | None = None,
        max_tokens: int = 2048,
        temperature: float = 0.2,
        cancel_event=None,
        deadline: float | None = None,
    ) -> str:
        raise NotImplementedError


class NullProvider(LLMProvider):
    name = "none"
    model = ""

    def complete(self, *args, **kwargs) -> str:
        raise ProviderUnavailable("LLM не настроена (provider=none)")


class LocalLlamaProvider(LLMProvider):
    name = "local"

    def __init__(self, model_path: str, n_ctx: int = 8192, n_threads: int = 0):
        self.model_path = model_path
        self.model = os.path.basename(model_path)
        self.n_ctx = n_ctx
        self.n_threads = n_threads or min(4, max(1, (os.cpu_count() or 4) // 3))
        self._llm = None
        self._lock = threading.Lock()

    def _ensure_llm(self):
        if self._llm is not None:
            return self._llm
        with self._lock:
            if self._llm is not None:
                return self._llm
            if not os.path.exists(self.model_path):
                raise ProviderUnavailable(f"Файл модели не найден: {self.model_path}")
            try:
                from llama_cpp import Llama
            except Exception as exc:
                raise ProviderUnavailable(f"llama-cpp-python недоступен: {exc}") from exc
            try:
                self._llm = Llama(
                    model_path=self.model_path,
                    n_ctx=self.n_ctx,
                    n_threads=max(1, min(16, self.n_threads)),
                    n_batch=128,
                    n_gpu_layers=0,
                    verbose=False,
                )
            except Exception as exc:
                raise ProviderUnavailable(f"Не удалось загрузить локальную модель: {exc}") from exc
        return self._llm

    def complete(
        self,
        messages: list[dict],
        *,
        response_format: dict | None = None,
        max_tokens: int = 2048,
        temperature: float = 0.2,
        cancel_event=None,
        deadline: float | None = None,
    ) -> str:
        stop = _stop_reason(cancel_event, deadline)
        if stop:
            raise ProviderStopped(stop)
        llm = self._ensure_llm()
        kwargs: dict[str, Any] = {
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "stream": True,
        }
        if response_format:
            kwargs["response_format"] = response_format
        try:
            with self._lock:
                stream = llm.create_chat_completion(**kwargs)
                if isinstance(stream, dict):
                    return stream["choices"][0]["message"]["content"] or ""
                parts: list[str] = []
                for chunk in stream:
                    stop = _stop_reason(cancel_event, deadline)
                    if stop:
                        try:
                            stream.close()
                        except Exception:
                            pass
                        raise ProviderStopped(stop)
                    choices = chunk.get("choices") or []
                    if not choices:
                        continue
                    delta = choices[0].get("delta") or {}
                    content = delta.get("content")
                    if content:
                        parts.append(content)
                return "".join(parts)
        except ProviderStopped:
            raise
        except TypeError:
            kwargs.pop("response_format", None)
            kwargs.pop("stream", None)
            try:
                with self._lock:
                    response = llm.create_chat_completion(**kwargs)
                return response["choices"][0]["message"]["content"] or ""
            except Exception as exc:
                raise ProviderUnavailable(f"Ошибка локальной модели: {exc}") from exc
        except Exception as exc:
            raise ProviderUnavailable(f"Ошибка локальной модели: {exc}") from exc


class OpenAICompatibleProvider(LLMProvider):
    name = "openai"

    def __init__(
        self,
        base_url: str,
        model: str,
        api_key: str = "",
        timeout: int = 180,
        provider_name: str = "openai",
    ):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.api_key = api_key
        self.timeout = timeout
        self.name = provider_name

    def complete(
        self,
        messages: list[dict],
        *,
        response_format: dict | None = None,
        max_tokens: int = 2048,
        temperature: float = 0.2,
        cancel_event=None,
        deadline: float | None = None,
    ) -> str:
        stop = _stop_reason(cancel_event, deadline)
        if stop:
            raise ProviderStopped(stop)
        if not self.base_url:
            raise ProviderUnavailable("Не задан LDWARDEN_LLM_BASE_URL")
        try:
            import httpx
        except Exception as exc:
            raise ProviderUnavailable(f"httpx недоступен: {exc}") from exc
        url = self.base_url + "/chat/completions"
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        if response_format:
            payload["response_format"] = response_format
        try:
            timeout = self.timeout
            if deadline is not None:
                timeout = max(1.0, min(float(timeout), deadline - time.monotonic()))
            with httpx.Client(timeout=timeout) as client:
                response = client.post(url, json=payload, headers=headers)
                if response.status_code == 400 and response_format:
                    payload.pop("response_format", None)
                    response = client.post(url, json=payload, headers=headers)
                response.raise_for_status()
                data = response.json()
        except Exception as exc:
            raise ProviderUnavailable(f"Ошибка LLM API ({url}): {exc}") from exc
        try:
            content = data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise ProviderUnavailable(f"Некорректный ответ LLM API: {exc}") from exc
        if isinstance(content, list):
            content = "".join(part.get("text", "") for part in content if isinstance(part, dict))
        return str(content or "")


class FakeProvider(LLMProvider):
    """Deterministic provider: derives a valid answer from the request payload."""

    name = "fake"

    def __init__(self, response: dict | None = None):
        self.response = response
        self.model = "fake"

    def complete(
        self,
        messages: list[dict],
        *,
        response_format: dict | None = None,
        max_tokens: int = 2048,
        temperature: float = 0.2,
        cancel_event=None,
        deadline: float | None = None,
    ) -> str:
        if cancel_event is not None and cancel_event.is_set():
            raise ProviderStopped("cancelled")
        if self.response is not None:
            return json.dumps(self.response, ensure_ascii=False)
        user = messages[-1]["content"] if messages else "{}"
        try:
            payload = json.loads(user)
        except ValueError:
            payload = {}
        findings = payload.get("findings", []) if isinstance(payload, dict) else []
        items = []
        for item in findings:
            items.append(
                {
                    "finding_id": item.get("id"),
                    "explanation": f"Находка {item.get('class')} в {item.get('path')}:{item.get('line')} требует внимания.",
                    "remediation": item.get("remediation") or "Устраните проблему согласно описанию.",
                    "severity_assessment": item.get("severity", "MEDIUM"),
                    "confidence": 0.8,
                }
            )
        return json.dumps(
            {
                "summary": "Обнаружены потенциальные проблемы безопасности; приоритет — находки высокой критичности.",
                "overall_risk": max(
                    (item.get("severity", "LOW") for item in findings),
                    key=lambda value: {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}.get(value, 0),
                    default="LOW",
                ),
                "findings": items,
                "next_steps": ["Исправить находки высокой критичности", "Перепроверить workflow"],
            },
            ensure_ascii=False,
        )


def get_local_provider(model_path: str, n_ctx: int = 4096, n_threads: int = 4) -> LLMProvider:
    key = ("local", str(model_path), int(n_ctx), int(n_threads))
    with _PROVIDER_LOCK:
        for cached_key in list(_PROVIDER_CACHE):
            if (
                cached_key[0] == "local"
                and cached_key[1] == str(model_path)
                and cached_key[2] == int(n_ctx)
                and cached_key[3] != int(n_threads)
            ):
                _PROVIDER_CACHE.pop(cached_key, None)
    return _cached(key, lambda: LocalLlamaProvider(str(model_path), n_ctx=n_ctx, n_threads=n_threads))


def get_openai_provider(
    base_url: str,
    model: str,
    api_key: str = "",
    timeout: int = 180,
    provider_name: str = "openai",
) -> LLMProvider:
    key = (provider_name, base_url.rstrip("/"), model, api_key, int(timeout))
    return _cached(
        key,
        lambda: OpenAICompatibleProvider(
            base_url=base_url,
            model=model,
            api_key=api_key,
            timeout=timeout,
            provider_name=provider_name,
        ),
    )


def build_provider(settings: Settings) -> LLMProvider:
    provider = settings.effective_llm_provider
    if provider == "local":
        return get_local_provider(
            str(settings.llm_model_path),
            n_ctx=settings.llm_n_ctx,
            n_threads=settings.llm_n_threads,
        )
    if provider in {"openai", "ollama"}:
        base_url = settings.llm_base_url
        model = settings.llm_model
        if provider == "ollama":
            base_url = base_url or "http://127.0.0.1:11434/v1"
            model = model or "qwen2.5-coder:7b"
        return get_openai_provider(
            base_url=base_url,
            model=model,
            api_key=settings.llm_api_key,
            timeout=settings.llm_timeout,
            provider_name=provider,
        )
    if provider == "fake":
        return FakeProvider()
    return NullProvider()
