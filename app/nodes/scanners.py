from __future__ import annotations

from app.analysis import AnalysisResult
from app.analysis.sca.engine import SCAAnalyzer
from app.analysis.sast.engine import SASTAnalyzer
from app.analysis.secrets.engine import SecretAnalyzer
from app.core.models import HandleSpec, NodeResult, ParamSpec, filter_min_severity
from app.core.registry import register_node
from app.nodes.base import BaseNode

SEVERITY_OPTIONS = [
    {"value": "LOW", "label": "LOW и выше"},
    {"value": "MEDIUM", "label": "MEDIUM и выше"},
    {"value": "HIGH", "label": "HIGH и выше"},
    {"value": "CRITICAL", "label": "только CRITICAL"},
]


def _split_globs(value: str | None) -> list[str]:
    if not value:
        return []
    return [item.strip() for item in str(value).replace("\n", ",").split(",") if item.strip()]


class ScannerNode(BaseNode):
    category = "scanner"
    color = "#ef4444"
    outputs = [HandleSpec("out", "Находки")]

    def _common_params(self) -> list[ParamSpec]:
        return [
            ParamSpec(
                "path",
                "string",
                "Путь к проекту",
                "Пусто — использовать источник запуска",
                default="",
                placeholder="training-main/training-project",
            ),
            ParamSpec(
                "include",
                "string",
                "Включать globs",
                "Через запятую",
                default="",
            ),
            ParamSpec(
                "exclude",
                "string",
                "Исключать globs",
                "Через запятую",
                default="",
            ),
            ParamSpec(
                "min_severity",
                "select",
                "Минимальная критичность",
                "Находки ниже порога не попадут в результат",
                default="LOW",
                options=SEVERITY_OPTIONS,
            ),
            ParamSpec(
                "min_confidence",
                "number",
                "Минимальная уверенность",
                "0–1, отсекает слабые эвристики",
                default=0.0,
                min=0,
                max=1,
            ),
        ]

    def _run(self, ctx, params: dict, analyzer, node_type: str, filter_fn=None) -> NodeResult:
        tree = ctx.source_view(
            path=params.get("path") or None,
            source_id=params.get("source_id") or None,
            include=_split_globs(params.get("include")) or None,
            exclude=_split_globs(params.get("exclude")) or None,
        )
        result: AnalysisResult = analyzer.analyze(tree)
        findings = filter_min_severity(result.findings, params.get("min_severity"))
        min_confidence = float(params.get("min_confidence") or 0)
        if min_confidence > 0:
            findings = [finding for finding in findings if finding.confidence >= min_confidence]
        if filter_fn is not None:
            findings = [finding for finding in findings if filter_fn(finding)]
        for finding in findings:
            finding.source_node = node_type
        added = ctx.add_findings(findings, node_id=ctx.node_id)
        summary = self.findings_summary(findings)
        for finding in findings[:30]:
            ctx.emit(
                "finding",
                f"{finding.severity} {finding.class_name}: {finding.path}:{finding.line}",
                node_id=ctx.node_id,
                level="warning" if finding.severity in {"CRITICAL", "HIGH"} else "info",
                payload={
                    "id": finding.fingerprint,
                    "category": finding.category,
                    "class": finding.class_name,
                    "severity": finding.severity,
                    "path": finding.path,
                    "line": finding.line,
                    "end_line": finding.end_line,
                    "message": finding.message,
                    "advisory_id": finding.advisory_id,
                },
            )
        if result.warnings:
            for warning in result.warnings[:10]:
                ctx.emit("warning", warning, node_id=ctx.node_id, level="warning")
        ctx.emit(
            "scanner.completed",
            f"{self.title}: найдено {len(findings)} (новых {added})",
            node_id=ctx.node_id,
            payload=summary,
        )
        return NodeResult(
            outputs={
                **summary,
                "new_findings": added,
                "stats": result.stats,
                "warnings": result.warnings,
            },
            message=f"Найдено {len(findings)} находок, новых {added}",
            preview=summary,
            findings_count=len(findings),
        )


@register_node
class SecretsScanNode(ScannerNode):
    type = "scan.secrets"
    title = "Поиск секретов"
    description = (
        "Находит пароли, API-ключи, токены, приватные ключи, строки подключения и "
        "восстановимые токены. Значения маскируются."
    )
    icon = "🔑"
    tags = ["scanner", "secrets"]


    params = [
        ParamSpec("path", "string", "Путь к проекту", "Пусто — использовать источник запуска", default=""),
        ParamSpec("include", "string", "Включать globs", "Через запятую", default=""),
        ParamSpec("exclude", "string", "Исключать globs", "Через запятую", default=""),
        ParamSpec(
            "min_severity",
            "select",
            "Минимальная критичность",
            "Находки ниже порога не попадут в результат",
            default="LOW",
            options=SEVERITY_OPTIONS,
        ),
        ParamSpec("min_confidence", "number", "Минимальная уверенность", "0–1", default=0.0, min=0, max=1),
        ParamSpec(
            "scan_docs",
            "boolean",
            "Сканировать документацию",
            "Проверять README и другие .md (плейсхолдеры отфильтровываются)",
            default=True,
        ),
    ]

    def execute(self, ctx, params: dict) -> NodeResult:
        return self._run(ctx, params, SecretAnalyzer(scan_docs=bool(params.get("scan_docs", True))), self.type)


@register_node
class SCAScanNode(ScannerNode):
    type = "scan.sca"
    title = "Уязвимые зависимости (SCA)"
    description = (
        "Разбирает build.gradle.kts, разрешает версии через константы, gradle.properties "
        "и gradle.lockfile, сверяет с локальным справочником уязвимостей."
    )
    icon = "📚"
    params = [
        ParamSpec("path", "string", "Путь к проекту", "Пусто — использовать источник запуска", default=""),
        ParamSpec("include", "string", "Включать globs", "Через запятую", default=""),
        ParamSpec("exclude", "string", "Исключать globs", "Через запятую", default=""),
        ParamSpec(
            "min_severity",
            "select",
            "Минимальная критичность",
            "Находки ниже порога не попадут в результат",
            default="LOW",
            options=SEVERITY_OPTIONS,
        ),
        ParamSpec("min_confidence", "number", "Минимальная уверенность", "0–1", default=0.0, min=0, max=1),
        ParamSpec(
            "db_path",
            "string",
            "Справочник уязвимостей",
            "Пусто — встроенный учебный справочник Maven",
            default="",
        ),
        ParamSpec(
            "include_test_dependencies",
            "boolean",
            "Учитывать test-зависимости",
            "Проверять testImplementation/testRuntimeOnly",
            default=False,
        ),
    ]
    tags = ["scanner", "sca", "gradle"]

    def execute(self, ctx, params: dict) -> NodeResult:
        db_path = params.get("db_path") or ctx.settings.vulnerability_db_path
        analyzer = SCAAnalyzer(db_path)
        include_test = bool(params.get("include_test_dependencies"))

        def keep(finding) -> bool:
            if include_test:
                return True
            scope = str((finding.extra or {}).get("scope") or "")
            return not scope.startswith("test")

        return self._run(ctx, params, analyzer, self.type, filter_fn=keep)


@register_node
class SASTScanNode(ScannerNode):
    type = "scan.sast"
    title = "SAST Kotlin/Spring Boot"
    description = (
        "Собственные эвристики: SQL-инъекции, отключённая проверка TLS, credentialed CORS, "
        "доступ к маршрутам без роли и IDOR (чтение чужой заявки по ID)."
    )
    icon = "🛡️"
    params = [
        ParamSpec("path", "string", "Путь к проекту", "Пусто — использовать источник запуска", default=""),
        ParamSpec("include", "string", "Включать globs", "Через запятую", default=""),
        ParamSpec("exclude", "string", "Исключать globs", "Через запятую", default=""),
        ParamSpec(
            "min_severity",
            "select",
            "Минимальная критичность",
            "Находки ниже порога не попадут в результат",
            default="LOW",
            options=SEVERITY_OPTIONS,
        ),
        ParamSpec("min_confidence", "number", "Минимальная уверенность", "0–1", default=0.0, min=0, max=1),
        ParamSpec("sql_injection", "boolean", "SQL-инъекции", "Проверять конкатенацию/интерполяцию в SQL", default=True),
        ParamSpec("tls", "boolean", "Проверка TLS", "Искать отключённую проверку сертификата/хоста", default=True),
        ParamSpec("cors", "boolean", "CORS", "Искать wildcard origin с credentials", default=True),
        ParamSpec("route_auth", "boolean", "Авторизация маршрутов", "Искать permitAll на чувствительных маршрутах", default=True),
        ParamSpec("object_auth", "boolean", "Авторизация объектов", "Искать IDOR/чтение чужой записи", default=True),
    ]
    tags = ["scanner", "sast", "kotlin", "spring"]

    def execute(self, ctx, params: dict) -> NodeResult:
        analyzer = SASTAnalyzer(
            sql_injection=bool(params.get("sql_injection", True)),
            tls=bool(params.get("tls", True)),
            cors=bool(params.get("cors", True)),
            route_auth=bool(params.get("route_auth", True)),
            object_auth=bool(params.get("object_auth", True)),
        )
        return self._run(ctx, params, analyzer, self.type)
