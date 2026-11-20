from __future__ import annotations

from dataclasses import replace

from app.ai.providers import (
    FakeProvider,
    NullProvider,
    build_provider,
    get_local_provider,
    get_openai_provider,
)
from app.ai.service import AIService
from app.core.models import HandleSpec, NodeResult, ParamSpec, severity_counts
from app.core.registry import register_node
from app.nodes.base import BaseNode


@register_node
class AIAnalyzeNode(BaseNode):
    type = "ai.analyze"
    category = "ai"
    title = "AI-объяснение"
    description = (
        "Передаёт находки собственных анализаторов в LLM, проверяет структуру ответа и "
        "привязку к файлам/строкам/CVE. При недоступности модели работает детерминированный fallback."
    )
    icon = "🤖"
    color = "#a855f7"
    outputs = [HandleSpec("out", "AI-отчёт")]
    params = [
        ParamSpec(
            "provider",
            "select",
            "Провайдер",
            "auto — из настроек сервера",
            default="auto",
            options=[
                {"value": "auto", "label": "auto (из настроек)"},
                {"value": "local", "label": "local (GGUF/llama.cpp)"},
                {"value": "openai", "label": "openai-совместимый API"},
                {"value": "ollama", "label": "Ollama"},
                {"value": "none", "label": "без LLM (fallback)"},
            ],
        ),
        ParamSpec("model", "string", "Модель", "Переопределить имя модели/путь", default=""),
        ParamSpec(
            "max_findings",
            "number",
            "Сколько находок отдать модели",
            "Остальные получат детерминированное объяснение",
            default=30,
            min=1,
            max=200,
        ),
        ParamSpec(
            "temperature",
            "number",
            "Температура",
            "0 — детерминированно",
            default=0.2,
            min=0,
            max=1,
        ),
    ]
    tags = ["ai", "llm", "explain"]
    docs = (
        "Ответ модели проверяется JSON-схемой, привязывается к finding_id и фактическим путям; "
        "неподтверждённые CVE/GHSA удаляются."
    )

    def execute(self, ctx, params: dict) -> NodeResult:
        settings = ctx.settings
        provider_name = (params.get("provider") or "auto").lower()
        model_override = (params.get("model") or "").strip()
        if provider_name == "auto":
            provider = build_provider(settings)
        elif provider_name == "local":
            model_path = model_override or str(settings.llm_model_path)
            provider = get_local_provider(
                model_path, n_ctx=settings.llm_n_ctx, n_threads=settings.llm_n_threads
            )
        elif provider_name in {"openai", "ollama"}:
            base_url = settings.llm_base_url
            model = model_override or settings.llm_model
            if provider_name == "ollama":
                base_url = base_url or "http://127.0.0.1:11434/v1"
                model = model or "qwen2.5-coder:7b"
            provider = get_openai_provider(
                base_url=base_url,
                model=model,
                api_key=settings.llm_api_key,
                timeout=settings.llm_timeout,
                provider_name=provider_name,
            )
        elif provider_name == "none":
            provider = NullProvider()
        elif provider_name == "fake":
            provider = FakeProvider()
        else:
            provider = build_provider(settings)

        effective = replace(
            settings,
            llm_max_findings=max(1, int(params.get("max_findings") or settings.llm_max_findings)),
            llm_temperature=float(params.get("temperature", settings.llm_temperature)),
        )
        service = AIService(effective, provider=provider)
        result = service.analyze(
            ctx.findings,
            meta={
                "run_id": ctx.run_id,
                "workflow": ctx.workflow.get("name") if ctx.workflow else "",
                "source": ctx.source.to_dict() if ctx.source else {},
                "counts": severity_counts(ctx.findings),
            },
        )
        ctx.ai_analysis = result
        validation = result.get("validation") or {}
        if result.get("provider") == "fallback":
            ctx.emit(
                "warning",
                "LLM недоступна или ответ не прошёл проверку: использован детерминированный fallback",
                node_id=ctx.node_id,
                level="warning",
                payload={"errors": validation.get("errors", [])[:5]},
            )
        ctx.emit(
            "ai.completed",
            f"AI: {result.get('provider')} · риск {result.get('overall_risk')}",
            node_id=ctx.node_id,
            payload={
                "provider": result.get("provider"),
                "model": result.get("model"),
                "overall_risk": result.get("overall_risk"),
                "grounded": validation.get("grounded"),
                "coverage": validation.get("coverage"),
                "summary": result.get("summary", "")[:500],
            },
        )
        return NodeResult(
            outputs={
                "provider": result.get("provider"),
                "model": result.get("model"),
                "overall_risk": result.get("overall_risk"),
                "summary": result.get("summary", ""),
                "grounded": validation.get("grounded"),
                "coverage": validation.get("coverage"),
                "next_steps": result.get("next_steps", []),
            },
            message=f"AI-анализ: {result.get('provider')}",
            preview={
                "provider": result.get("provider"),
                "overall_risk": result.get("overall_risk"),
                "summary": result.get("summary", "")[:300],
            },
        )
