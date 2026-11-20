from __future__ import annotations

from app.core.models import HandleSpec, NodeResult, ParamSpec
from app.core.registry import register_node
from app.nodes.base import BaseNode


@register_node
class SourceTargetNode(BaseNode):
    type = "source.target"
    category = "source"
    title = "Источник кода"
    description = (
        "Выбирает учебный проект: путь внутри разрешённых каталогов, загруженный ZIP "
        "или (при явном allow-list) Git-репозиторий."
    )
    icon = "📦"
    color = "#f59e0b"
    outputs = [HandleSpec("out", "Файлы проекта")]
    params = [
        ParamSpec(
            "path",
            "string",
            "Путь к проекту",
            "Если пусто — используется источник запуска (target из запроса). Относительно корня LDWarden.",
            default="",
            placeholder="training-main/training-project",
        ),
        ParamSpec(
            "source_id",
            "string",
            "ID загруженного источника",
            "Идентификатор ZIP-загрузки (альтернатива пути)",
            default="",
        ),
        ParamSpec(
            "include",
            "string",
            "Включать globs",
            "Через запятую, например src/main/**/*.kt",
            default="",
        ),
        ParamSpec(
            "exclude",
            "string",
            "Исключать globs",
            "Через запятую, например **/test/**",
            default="",
        ),
    ]
    tags = ["source"]
    docs = "Нода нужна, чтобы сценарий был переносимым: источник можно задать в ноде или при запуске."

    def execute(self, ctx, params: dict) -> NodeResult:
        include = _split_globs(params.get("include"))
        exclude = _split_globs(params.get("exclude"))
        tree = ctx.resolve_source(
            path=params.get("path") or None,
            source_id=params.get("source_id") or None,
            include=include or None,
            exclude=exclude or None,
        )
        ctx.emit(
            "source.ready",
            f"Источник: {tree.label}, файлов: {len(tree.files)}",
            node_id=ctx.node_id,
            payload=tree.stats,
        )
        return NodeResult(
            outputs=tree.to_dict(),
            message=f"Загружено файлов: {len(tree.files)}",
            preview=tree.stats,
        )


def _split_globs(value: str | None) -> list[str]:
    if not value:
        return []
    return [item.strip() for item in str(value).replace("\n", ",").split(",") if item.strip()]
