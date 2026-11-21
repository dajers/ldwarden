from __future__ import annotations

import copy
import json
from typing import Any, TypeVar

from app.core.models import NodeSpec, ParamSpec

NODE_SPECS: dict[str, NodeSpec] = {}
NODE_CLASSES: dict[str, type] = {}

T = TypeVar("T", bound=type)


class NodeValidationError(ValueError):
    def __init__(self, message: str, details: list[str] | None = None):
        super().__init__(message)
        self.details = details or []


def register_node(cls: T) -> T:
    node_type = getattr(cls, "type", "")
    if not node_type:
        raise ValueError(f"У ноды {cls.__name__} не задан type")
    if node_type in NODE_SPECS:

        pass
    inputs = getattr(cls, "inputs", None)
    outputs = getattr(cls, "outputs", None)
    spec = NodeSpec(
        type=node_type,
        category=getattr(cls, "category", "other"),
        title=getattr(cls, "title", node_type),
        description=getattr(cls, "description", ""),
        icon=getattr(cls, "icon", ""),
        color=getattr(cls, "color", "#64748b"),
        inputs=copy.deepcopy(inputs) if inputs is not None else NodeSpec.__dataclass_fields__["inputs"].default_factory(),
        outputs=copy.deepcopy(outputs) if outputs is not None else NodeSpec.__dataclass_fields__["outputs"].default_factory(),
        params=copy.deepcopy(getattr(cls, "params", [])),
        tags=list(getattr(cls, "tags", [])),
        docs=getattr(cls, "docs", ""),
        examples=copy.deepcopy(getattr(cls, "examples", [])),
        version=getattr(cls, "version", "1.0"),
    )
    NODE_SPECS[node_type] = spec
    NODE_CLASSES[node_type] = cls
    return cls


def register_custom(node_type: str, spec: NodeSpec, cls: type) -> None:
    """Регистрирует динамическую ноду (созданную в интерфейсе)."""
    NODE_SPECS[node_type] = spec
    NODE_CLASSES[node_type] = cls


def unregister_custom(prefix: str = "custom.") -> None:
    for key in [key for key in NODE_SPECS if key.startswith(prefix)]:
        NODE_SPECS.pop(key, None)
        NODE_CLASSES.pop(key, None)


def get_spec(node_type: str) -> NodeSpec | None:
    return NODE_SPECS.get(node_type)


def get_class(node_type: str) -> type | None:
    return NODE_CLASSES.get(node_type)


def catalog() -> list[dict]:
    order = [
        "trigger",
        "source",
        "scanner",
        "ai",
        "logic",
        "report",
        "notification",
        "control",
        "custom",
    ]
    specs = sorted(
        NODE_SPECS.values(),
        key=lambda spec: (order.index(spec.category) if spec.category in order else 99, spec.type),
    )
    return [spec.to_dict() for spec in specs]


def validate_params(spec: NodeSpec, raw: dict | None) -> dict:
    """Apply defaults, coerce types and enforce required/secret rules."""
    raw = raw or {}
    if not isinstance(raw, dict):
        raise NodeValidationError("Параметры ноды должны быть объектом")
    known = {param.name: param for param in spec.params}
    unknown = [key for key in raw if key not in known and key not in {"label", "disabled", "notes"}]
    if unknown:
        raise NodeValidationError(
            f"Неизвестные параметры ноды {spec.type}: {', '.join(sorted(unknown))}",
            [f"Неизвестный параметр: {key}" for key in unknown],
        )
    result: dict[str, Any] = {}
    errors: list[str] = []
    for param in spec.params:
        if param.name in raw:
            value = raw[param.name]
        else:
            value = copy.deepcopy(param.default)
        if value is None or value == "":
            if param.required:
                errors.append(f"Обязательный параметр «{param.name}» не заполнен")
            result[param.name] = value
            continue
        try:
            result[param.name] = _coerce(param, value)
        except (TypeError, ValueError) as exc:
            errors.append(f"Параметр «{param.name}»: {exc}")
    if errors:
        raise NodeValidationError("Некорректные параметры ноды", errors)
    return result


def _coerce(param: ParamSpec, value: Any) -> Any:
    ptype = param.type
    if ptype in ("string", "text", "secret"):
        return str(value)
    if ptype == "number":
        number = float(value)
        if param.min is not None and number < param.min:
            raise ValueError(f"значение меньше {param.min}")
        if param.max is not None and number > param.max:
            raise ValueError(f"значение больше {param.max}")
        return int(number) if number.is_integer() else number
    if ptype == "boolean":
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.strip().lower() in {"1", "true", "yes", "on"}
        return bool(value)
    if ptype == "select":
        valid = {_option_value(option) for option in param.options}
        text = str(value)
        if valid and text not in valid:
            raise ValueError(f"допустимые значения: {', '.join(sorted(valid))}")
        return text
    if ptype == "multiselect":
        if isinstance(value, str):
            value = [item.strip() for item in value.split(",") if item.strip()]
        if not isinstance(value, list):
            raise ValueError("ожидался список значений")
        valid = {_option_value(option) for option in param.options}
        result = [str(item) for item in value]
        invalid = [item for item in result if valid and item not in valid]
        if invalid:
            raise ValueError(f"недопустимые значения: {', '.join(invalid)}")
        return result
    if ptype == "json":
        if isinstance(value, str):
            try:
                return json.loads(value)
            except ValueError as exc:
                raise ValueError(f"некорректный JSON: {exc}") from exc
        if not isinstance(value, (dict, list)):
            raise ValueError("ожидался JSON-объект или массив")
        return value
    if ptype == "keyvalue":
        if isinstance(value, str):
            try:
                value = json.loads(value)
            except ValueError as exc:
                raise ValueError(f"некорректный JSON-объект: {exc}") from exc
        if not isinstance(value, dict):
            raise ValueError("ожидался объект ключ-значение")
        return {str(k): str(v) for k, v in value.items()}
    return value


def _option_value(option: Any) -> str:
    if isinstance(option, dict):
        return str(option.get("value", ""))
    return str(option)


def default_params(spec: NodeSpec) -> dict:
    return {param.name: copy.deepcopy(param.default) for param in spec.params}


def secret_param_names(spec: NodeSpec) -> list[str]:
    return [param.name for param in spec.params if param.secret or param.type == "secret"]
