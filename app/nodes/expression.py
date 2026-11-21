"""Безопасные выражения для ноды «Своё условие».

`eval`/`exec` не используются: выражение разбирается через `ast`, а обходятся
только разрешённые узлы (сравнения, and/or/not, литералы, переменные и
небольшой набор функций). Всё остальное отклоняется.
"""
from __future__ import annotations

import ast
import re
from typing import Any

from app.core.models import severity_counts


class ExpressionError(ValueError):
    """Выражение некорректно или содержит недопустимую конструкцию."""


_ALLOWED_NODES = (
    ast.Expression,
    ast.BoolOp,
    ast.And,
    ast.Or,
    ast.UnaryOp,
    ast.Not,
    ast.Compare,
    ast.Eq,
    ast.NotEq,
    ast.Lt,
    ast.LtE,
    ast.Gt,
    ast.GtE,
    ast.Name,
    ast.Load,
    ast.Constant,
    ast.Call,
)

_FINDING_FIELDS = {
    "path": lambda finding: finding.path,
    "class": lambda finding: finding.class_name,
    "message": lambda finding: finding.message or finding.description,
    "category": lambda finding: finding.category,
}


def _normalize(source: str) -> str:
    text = str(source or "")
    text = text.replace("&&", " and ").replace("||", " or ")
    text = re.sub(r"!(?!=)", " not ", text)
    text = re.sub(r"\btrue\b", "True", text, flags=re.IGNORECASE)
    text = re.sub(r"\bfalse\b", "False", text, flags=re.IGNORECASE)
    return text


def _check(node: ast.AST) -> None:
    if not isinstance(node, _ALLOWED_NODES):
        raise ExpressionError(f"недопустимая конструкция: {type(node).__name__}")
    for child in ast.iter_child_nodes(node):
        _check(child)


def build_context(findings: list, target: str = "") -> dict[str, Any]:
    counts = severity_counts(findings)
    by_category = {"SECRET": 0, "SAST": 0, "SCA": 0}
    for finding in findings:
        category = (finding.category or "").upper()
        if category in by_category:
            by_category[category] += 1
    return {
        "findings": findings,
        "target": str(target or ""),
        "total": len(findings),
        "critical": counts.get("CRITICAL", 0),
        "high": counts.get("HIGH", 0),
        "medium": counts.get("MEDIUM", 0),
        "low": counts.get("LOW", 0),
        "secret": by_category["SECRET"],
        "sca": by_category["SCA"],
        "sast": by_category["SAST"],
        "hasCritical": counts.get("CRITICAL", 0) > 0,
        "hasSecrets": by_category["SECRET"] > 0,
    }


def _truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    return bool(value)


def _number(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _compare(left: Any, operator: ast.cmpop, right: Any) -> bool:
    left_number, right_number = _number(left), _number(right)
    if left_number is not None and right_number is not None:
        left, right = left_number, right_number
    elif isinstance(left, str) and isinstance(right, str):
        pass
    else:
        left, right = str(left), str(right)

    if isinstance(operator, ast.Eq):
        return left == right
    if isinstance(operator, ast.NotEq):
        return left != right
    if isinstance(operator, ast.Gt):
        return left > right
    if isinstance(operator, ast.GtE):
        return left >= right
    if isinstance(operator, ast.Lt):
        return left < right
    if isinstance(operator, ast.LtE):
        return left <= right
    raise ExpressionError("недопустимый оператор сравнения")


def _regex(pattern: Any) -> re.Pattern:
    try:
        return re.compile(str(pattern))
    except re.error as exc:
        raise ExpressionError(f"некорректное регулярное выражение: {exc}") from exc


def _call(name: str, args: list[Any], context: dict[str, Any]) -> Any:
    findings = context.get("findings") or []
    if name == "count":
        return len(findings)
    if name == "contains":
        left = str(args[0] if args else "")
        right = str(args[1] if len(args) > 1 else "")
        return right in left
    if name == "matches":
        text = str(args[0] if args else "")
        pattern = args[1] if len(args) > 1 else ""
        return _regex(pattern).search(text) is not None
    if name in {"anyPath", "anyClass", "anyMessage"}:
        field = {"anyPath": "path", "anyClass": "class", "anyMessage": "message"}[name]
        getter = _FINDING_FIELDS[field]
        pattern = _regex(args[0] if args else "")
        return any(pattern.search(str(getter(finding) or "")) for finding in findings)
    raise ExpressionError(f"неизвестная функция «{name}»")


def _eval(node: ast.AST, context: dict[str, Any]) -> Any:
    if isinstance(node, ast.Expression):
        return _eval(node.body, context)
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.Name):
        if node.id not in context:
            raise ExpressionError(f"неизвестная переменная «{node.id}»")
        return context[node.id]
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        return not _truthy(_eval(node.operand, context))
    if isinstance(node, ast.BoolOp):
        values = [_truthy(_eval(value, context)) for value in node.values]
        return all(values) if isinstance(node.op, ast.And) else any(values)
    if isinstance(node, ast.Compare):
        left = _eval(node.left, context)
        for operator, comparator in zip(node.ops, node.comparators):
            right = _eval(comparator, context)
            if not _compare(left, operator, right):
                return False
            left = right
        return True
    if isinstance(node, ast.Call):
        if not isinstance(node.func, ast.Name):
            raise ExpressionError("вызов разрешён только для встроенных функций")
        if node.keywords:
            raise ExpressionError("именованные аргументы не поддерживаются")
        args = [_eval(arg, context) for arg in node.args]
        return _call(node.func.id, args, context)
    raise ExpressionError(f"недопустимая конструкция: {type(node).__name__}")


def evaluate(source: str, findings: list, target: str = "") -> bool:
    """Возвращает результат выражения. Бросает ExpressionError при ошибке."""
    text = str(source or "").strip()
    if not text:
        raise ExpressionError("условие пустое")
    try:
        tree = ast.parse(_normalize(text), mode="eval")
    except SyntaxError as exc:
        raise ExpressionError(f"синтаксис: {exc.msg}") from exc
    _check(tree)
    return _truthy(_eval(tree, build_context(findings, target)))


__all__ = ["ExpressionError", "build_context", "evaluate"]
