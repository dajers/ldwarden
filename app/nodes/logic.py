from __future__ import annotations

import re

from app.core.models import (
    HandleSpec,
    NodeResult,
    ParamSpec,
    count_by,
    max_severity,
    severity_counts,
    severity_rank,
)
from app.core.registry import register_node
from app.nodes.base import BaseNode, NodeError
from app.nodes.expression import ExpressionError, evaluate as evaluate_expression

FINDING_FIELDS = {
    "path": lambda finding: finding.path,
    "class": lambda finding: finding.class_name,
    "message": lambda finding: finding.message or finding.description,
    "category": lambda finding: finding.category,
}

OPERATORS = [
    {"value": "eq", "label": "равно"},
    {"value": "ne", "label": "не равно"},
    {"value": "gt", "label": "больше"},
    {"value": "gte", "label": "больше или равно"},
    {"value": "lt", "label": "меньше"},
    {"value": "lte", "label": "меньше или равно"},
    {"value": "contains", "label": "содержит"},
    {"value": "regex", "label": "регулярное выражение"},
    {"value": "truthy", "label": "непустое/истина"},
    {"value": "empty", "label": "пустое"},
]


def logic_context(ctx) -> dict:
    counts = severity_counts(ctx.findings)
    lower_counts = {key.lower(): value for key, value in counts.items()}
    by_category = count_by(ctx.findings, "category")
    by_class = count_by(ctx.findings, "class_name")
    ai = ctx.ai_analysis or {}
    return {
        "findings": {
            **counts,
            **lower_counts,
            "total": len(ctx.findings),
            "by_category": by_category,
            "by_class": by_class,
        },
        "gate": ctx.gate or {},
        "trigger": {"type": ctx.trigger},
        "ai": {
            "provider": ai.get("provider"),
            "overall_risk": ai.get("overall_risk"),
            "summary": ai.get("summary", ""),
            "grounded": (ai.get("validation") or {}).get("grounded"),
        },
        "source": ctx.source.to_dict() if ctx.source else {},
        "vars": ctx.vars,
    }


def resolve_field(context: dict, path: str, default=None):
    current = context
    if not path:
        return default
    for part in str(path).split("."):
        if isinstance(current, dict):
            if part in current:
                current = current[part]
                continue

            lowered = part.lower()
            match = next((key for key in current if str(key).lower() == lowered), None)
            if match is not None:
                current = current[match]
                continue
            return default
        if isinstance(current, list):
            try:
                current = current[int(part)]
                continue
            except (ValueError, IndexError):
                return default
        return default
    return current


def _as_number(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def evaluate(actual, operator: str, expected, case_sensitive: bool = False) -> bool:
    operator = operator or "eq"
    if operator == "truthy":
        return bool(actual)
    if operator == "empty":
        return not actual
    if operator == "regex":
        flags = 0 if case_sensitive else re.IGNORECASE
        try:
            return re.search(str(expected), str(actual or ""), flags) is not None
        except re.error:
            return False
    if operator in {"gt", "gte", "lt", "lte"}:
        left = _as_number(actual)
        right = _as_number(expected)
        if left is None or right is None:
            return False
        return {
            "gt": left > right,
            "gte": left >= right,
            "lt": left < right,
            "lte": left <= right,
        }[operator]
    if operator == "contains":
        if isinstance(actual, (list, tuple, set)):
            return expected in actual
        if isinstance(actual, dict):
            return expected in actual
        left = str(actual or "")
        right = str(expected or "")
        if not case_sensitive:
            left, right = left.lower(), right.lower()
        return right in left
    left = actual
    right = expected
    if not case_sensitive and isinstance(left, str) and isinstance(right, str):
        left, right = left.lower(), right.lower()
    if isinstance(left, (int, float, bool)) or isinstance(right, (int, float, bool)):
        left_num, right_num = _as_number(left), _as_number(right)
        if left_num is not None and right_num is not None:
            left, right = left_num, right_num
    if operator == "eq":
        return left == right
    if operator == "ne":
        return left != right
    return False


@register_node
class IfNode(BaseNode):
    type = "logic.if"
    category = "logic"
    title = "Условие if/else"
    description = "Сравнивает значение из контекста (например, findings.total) и выбирает ветку true/false."
    icon = "🔀"
    color = "#06b6d4"
    outputs = [HandleSpec("true", "Да"), HandleSpec("false", "Нет")]
    params = [
        ParamSpec(
            "field",
            "string",
            "Поле",
            "Путь к значению: findings.total, findings.CRITICAL, findings.by_category.SECRET, gate.passed",
            default="findings.total",
            required=True,
            placeholder="findings.CRITICAL",
        ),
        ParamSpec("operator", "select", "Оператор", "", default="gt", options=OPERATORS, required=True),
        ParamSpec("value", "string", "Значение", "С чем сравнивать", default="0"),
        ParamSpec("case_sensitive", "boolean", "Учитывать регистр", "", default=False),
    ]
    tags = ["logic", "if", "condition"]

    def execute(self, ctx, params: dict) -> NodeResult:
        context = logic_context(ctx)
        actual = resolve_field(context, params.get("field", ""))
        result = evaluate(actual, params.get("operator", "eq"), params.get("value"), bool(params.get("case_sensitive")))
        handle = "true" if result else "false"
        ctx.emit(
            "logic.evaluated",
            f"{params.get('field')} {params.get('operator')} {params.get('value')} → {result}",
            node_id=ctx.node_id,
            payload={"actual": actual, "result": result},
        )
        return NodeResult(
            outputs={"result": result, "actual": actual, "operator": params.get("operator")},
            active_handles=[handle],
            message=f"Условие: {'да' if result else 'нет'}",
            preview={"actual": actual, "result": result},
        )


@register_node
class CompareNode(BaseNode):
    type = "logic.compare"
    category = "logic"
    title = "Сравнение"
    description = "Сравнивает два значения из контекста, например findings.CRITICAL и findings.HIGH."
    icon = "⚖️"
    color = "#14b8a6"
    outputs = [HandleSpec("true", "Да"), HandleSpec("false", "Нет")]
    params = [
        ParamSpec("left", "string", "Левое значение", "Путь к значению", default="findings.CRITICAL", required=True),
        ParamSpec("operator", "select", "Оператор", "", default="gte", options=OPERATORS, required=True),
        ParamSpec("right", "string", "Правое значение", "Путь к значению или литерал", default="findings.HIGH"),
        ParamSpec("case_sensitive", "boolean", "Учитывать регистр", "", default=False),
    ]
    tags = ["logic", "compare"]

    def execute(self, ctx, params: dict) -> NodeResult:
        context = logic_context(ctx)
        left = resolve_field(context, params.get("left", ""), params.get("left"))
        right = resolve_field(context, params.get("right", ""), params.get("right"))
        result = evaluate(left, params.get("operator", "eq"), right, bool(params.get("case_sensitive")))
        handle = "true" if result else "false"
        ctx.emit(
            "logic.evaluated",
            f"{params.get('left')} {params.get('operator')} {params.get('right')} → {result}",
            node_id=ctx.node_id,
            payload={"left": left, "right": right, "result": result},
        )
        return NodeResult(
            outputs={"result": result, "left": left, "right": right},
            active_handles=[handle],
            message=f"Сравнение: {'да' if result else 'нет'}",
            preview={"left": left, "right": right, "result": result},
        )


@register_node
class RegexNode(BaseNode):
    type = "logic.regex"
    category = "logic"
    title = "Регулярное выражение"
    description = "Проверяет значение из контекста регулярным выражением."
    icon = "🔤"
    color = "#0891b2"
    outputs = [HandleSpec("true", "Совпало"), HandleSpec("false", "Не совпало")]
    params = [
        ParamSpec("field", "string", "Поле", "Путь к значению", default="ai.summary", required=True),
        ParamSpec("pattern", "string", "Регулярное выражение", "Python regex", default="", required=True, placeholder="CRITICAL|HIGH"),
        ParamSpec("case_sensitive", "boolean", "Учитывать регистр", "", default=False),
        ParamSpec("negate", "boolean", "Инвертировать результат", "Совпадением считается отсутствие match", default=False),
    ]
    tags = ["logic", "regex"]

    def execute(self, ctx, params: dict) -> NodeResult:
        context = logic_context(ctx)
        field = str(params.get("field") or "")
        pattern = str(params.get("pattern") or "")
        case_sensitive = bool(params.get("case_sensitive"))
        negate = bool(params.get("negate"))


        if field.startswith("findings.") and field.split(".", 1)[1] in FINDING_FIELDS:
            attribute = field.split(".", 1)[1]
            try:
                expression = re.compile(pattern, 0 if case_sensitive else re.IGNORECASE)
            except re.error as exc:
                raise NodeError(f"Некорректное регулярное выражение: {exc}") from exc
            getter = FINDING_FIELDS[attribute]
            matched = any(expression.search(str(getter(finding) or "")) for finding in ctx.findings)
            result = (not matched) if negate else matched
            ctx.emit(
                "logic.evaluated",
                f"regex {pattern} по {field} → {result}",
                node_id=ctx.node_id,
                payload={"result": result, "matched": matched, "field": field},
            )
            return NodeResult(
                outputs={"result": result, "matched": matched, "count": len(ctx.findings)},
                active_handles=["true" if result else "false"],
                message=f"Regex: {'совпало' if result else 'не совпало'}",
            )

        actual = resolve_field(context, field)
        result = evaluate(actual, "regex", pattern, case_sensitive)
        if negate:
            result = not result
        ctx.emit(
            "logic.evaluated",
            f"regex {pattern} по {field} → {result}",
            node_id=ctx.node_id,
            payload={"result": result},
        )
        return NodeResult(
            outputs={"result": result, "actual": actual},
            active_handles=["true" if result else "false"],
            message=f"Regex: {'совпало' if result else 'не совпало'}",
        )


@register_node
class SeverityGateNode(BaseNode):
    type = "control.severity_gate"
    category = "control"
    title = "Порог критичности"
    description = "Пропускает сценарий, если максимальная критичность находок ниже порога. Для CI может валить сборку."
    icon = "🚦"
    color = "#f97316"
    outputs = [HandleSpec("pass", "Порог пройден"), HandleSpec("fail", "Порог превышен")]
    params = [
        ParamSpec(
            "threshold",
            "select",
            "Порог",
            "Сценарий не проходит, если есть находка этого уровня или выше",
            default="HIGH",
            required=True,
            options=[
                {"value": "CRITICAL", "label": "CRITICAL"},
                {"value": "HIGH", "label": "HIGH"},
                {"value": "MEDIUM", "label": "MEDIUM"},
                {"value": "LOW", "label": "LOW"},
            ],
        ),
        ParamSpec(
            "categories",
            "multiselect",
            "Категории",
            "Пусто — все категории",
            default=["SECRET", "SAST", "SCA"],
            options=[
                {"value": "SECRET", "label": "SECRET"},
                {"value": "SAST", "label": "SAST"},
                {"value": "SCA", "label": "SCA"},
            ],
        ),
        ParamSpec(
            "blocking",
            "boolean",
            "Блокировать запуск",
            "Если порог превышен, run получает статус failed (для CI)",
            default=True,
        ),
    ]
    tags = ["control", "ci", "gate"]

    def execute(self, ctx, params: dict) -> NodeResult:
        categories = params.get("categories") or []
        findings = [finding for finding in ctx.findings if not categories or finding.category in categories]
        maximum = max_severity(findings)
        threshold = params.get("threshold", "HIGH")
        passed = severity_rank(maximum) < severity_rank(threshold) if findings else True
        gate = {
            "passed": passed,
            "threshold": threshold,
            "max_severity": maximum,
            "blocking": bool(params.get("blocking", True)),
            "categories": categories,
            "findings": len(findings),
            "counts": severity_counts(findings),
        }
        ctx.gate = gate
        handle = "pass" if passed else "fail"
        ctx.emit(
            "gate.evaluated",
            f"Порог {threshold}: {'пройден' if passed else 'превышен'} (максимум {maximum or '—'})",
            node_id=ctx.node_id,
            level="warning" if not passed else "info",
            payload=gate,
        )
        return NodeResult(
            outputs=gate,
            active_handles=[handle],
            message=f"Порог {threshold} {'пройден' if passed else 'превышен'}",
            preview={"passed": passed, "max_severity": maximum, "threshold": threshold},
        )


@register_node
class ForkNode(BaseNode):
    type = "logic.fork"
    category = "logic"
    title = "Разветвитель"
    description = "Запускает несколько веток: все выходные пины становятся активными."
    icon = "🔱"
    color = "#0ea5e9"
    inputs = [HandleSpec("in", "Вход", position="left", kind="target")]
    outputs = [
        HandleSpec("a", "Ветка 1"),
        HandleSpec("b", "Ветка 2"),
        HandleSpec("c", "Ветка 3"),
    ]
    params = []
    tags = ["logic", "fork", "parallel"]

    def execute(self, ctx, params: dict) -> NodeResult:
        ctx.emit(
            "logic.forked",
            "Поток разветвлён на 3 ветки",
            node_id=ctx.node_id,
            payload={"branches": ["a", "b", "c"]},
        )
        return NodeResult(
            outputs={"branches": ["a", "b", "c"]},
            active_handles=["a", "b", "c"],
            message="Разветвление на 3 ветки",
        )


@register_node
class JoinNode(BaseNode):
    type = "logic.join"
    category = "logic"
    title = "Собиратель"
    description = "Ждёт все подключённые входы и продолжает поток один раз."
    icon = "🧩"
    color = "#0284c7"
    inputs = [HandleSpec("in", "Входы A/B", position="left", kind="target")]
    outputs = [HandleSpec("out", "Дальше")]
    params = []
    tags = ["logic", "join", "merge"]

    def execute(self, ctx, params: dict) -> NodeResult:
        ctx.emit(
            "logic.joined",
            "Ветки объединены",
            node_id=ctx.node_id,
            payload={"findings": len(ctx.findings)},
        )
        return NodeResult(
            outputs={"merged": True, "findings": len(ctx.findings)},
            active_handles=["out"],
            message="Ветки объединены",
        )


@register_node
class CustomConditionNode(BaseNode):
    type = "logic.custom"
    category = "logic"
    title = "Своё условие"
    description = (
        "Пользовательское выражение: total, critical, high, secret, hasCritical, "
        "anyPath('regex'), matches(target, '...'), and/or/not."
    )
    icon = "🧮"
    color = "#8b5cf6"
    outputs = [HandleSpec("true", "Да"), HandleSpec("false", "Нет")]
    params = [
        ParamSpec(
            "expr",
            "string",
            "Условие",
            "Выражение на переменных и функциях",
            default="critical >= 1",
            required=True,
            placeholder="critical >= 1 and not anyPath('/test/')",
        ),
    ]
    tags = ["logic", "condition", "expression"]

    def execute(self, ctx, params: dict) -> NodeResult:
        source = str(params.get("expr") or "")
        target = ctx.source.label if ctx.source else ""
        try:
            result = evaluate_expression(source, ctx.findings, target)
        except ExpressionError as exc:
            raise NodeError(f"Ошибка условия: {exc}") from exc
        handle = "true" if result else "false"
        ctx.emit(
            "logic.evaluated",
            f"{source} → {result}",
            node_id=ctx.node_id,
            payload={"expression": source, "result": result},
        )
        return NodeResult(
            outputs={"result": result, "expression": source, "findings": len(ctx.findings)},
            active_handles=[handle],
            message=f"Условие: {'да' if result else 'нет'}",
            preview={"expression": source, "result": result},
        )
