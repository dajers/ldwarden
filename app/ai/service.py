from __future__ import annotations

import json
import re
import time
from datetime import datetime, timezone
from typing import Any

import jsonschema

from app.ai.prompts import SYSTEM_PROMPT, build_analysis_request, build_repair_request, build_workflow_ast_request
from app.ai.providers import (
    FakeProvider,
    LLMProvider,
    ProviderStopped,
    ProviderUnavailable,
    build_provider,
)
from app.ai.schema import ANALYSIS_SCHEMA, PLANNER_SCHEMA, WORKFLOW_INTENT_SCHEMA
from app.config import Settings
from app.core.models import Finding, max_severity, normalize_severity, severity_counts
from app.core.registry import NODE_SPECS, catalog, validate_params
from app.core.graph import normalize_graph, validate_graph

ADVISORY_RE = re.compile(r"\b(?:CVE-\d{4}-\d{4,}|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})\b")
FILE_RE = re.compile(
    r"(?:[A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+\.(?:kt|kts|java|ya?ml|json|gradle|xml|properties|toml|sql|md)"
)

FALLBACK_HINTS = {
    "sql-injection": "Пользовательские данные попадают в SQL-строку без параметризации; это позволяет изменить запрос и прочитать или изменить чужие данные.",
    "tls-verification": "Приложение принимает сертификат с любым именем хоста или отключает проверку TLS; трафик можно перехватить (MITM).",
    "credentialed-cors": "CORS разрешает любой сайт и передачу cookie; сторонний origin может прочитать приватные данные пользователя.",
    "route-authorization": "Маршрут открыт без проверки роли, хотя возвращает данные клиентов или служебную информацию.",
    "object-authorization": "Запись читается по переданному ID без проверки владельца; клиент может открыть чужую заявку.",
    "known-vulnerable-dependency": "Объявленная версия зависимости попадает в диапазон известной уязвимости из справочника.",
    "password": "Пароль хранится в исходниках в открытом виде; любой, у кого есть доступ к репозиторию, может его использовать.",
    "api-key": "API-ключ хранится в исходниках; его нужно перевыпустить и вынести в секретное хранилище.",
    "configuration-token": "Токен записан в конфигурации в открытом виде; он попадёт в репозиторий и логи.",
    "secret-fallback": "В коде есть встроенное значение секрета по умолчанию; при отсутствии переменной окружения используется оно.",
    "recoverable-token": "Токен собирается из литералов в коде, поэтому его можно восстановить и использовать.",
    "private-key": "Приватный ключ находится в репозитории и считается скомпрометированным.",
    "connection-string": "Строка подключения содержит пароль в открытом виде.",
    "token": "Токен хранится в коде в открытом виде.",
}


class AIService:
    def __init__(self, settings: Settings, provider: LLMProvider | None = None):
        self.settings = settings
        self.provider = provider or build_provider(settings)


    def analyze(
        self,
        findings: list[Finding],
        meta: dict | None = None,
        cancel_event=None,
        timeout: int | float | None = None,
    ) -> dict:
        meta = meta or {}
        if not findings:
            return self._empty_result()
        ordered = sorted(findings, key=lambda f: (-f.severity_rank, f.path, f.line))
        selected = ordered[: max(1, self.settings.llm_max_findings)]
        deadline = time.monotonic() + float(timeout) if timeout else None
        if cancel_event is not None and cancel_event.is_set():
            result = self._fallback(findings, selected, meta)
            result["validation"]["cancelled"] = True
            result["validation"]["stopped_reason"] = "cancelled"
            return result
        payload_findings = [_finding_payload(finding) for finding in selected]
        request = build_analysis_request(payload_findings, meta)
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": request},
        ]
        raw = ""
        errors: list[str] = []
        attempted_provider = getattr(self.provider, "name", "none")
        attempted_model = getattr(self.provider, "model", "")
        try:
            raw = self.provider.complete(
                messages,
                response_format={"type": "json_object"},
                temperature=self.settings.llm_temperature,
                max_tokens=384,
                cancel_event=cancel_event,
                deadline=deadline,
            )
        except ProviderStopped as exc:
            errors.append(f"AI остановлен: {exc.reason}")
        except ProviderUnavailable as exc:
            errors.append(str(exc))
        except Exception as exc:
            errors.append(f"Ошибка провайдера LLM: {exc}")

        parsed: dict | None = None
        schema_ok = False
        if raw:
            parsed = self._parse_json(raw)
            if parsed is not None:
                schema_ok = self._schema_ok(parsed)
            if parsed is None or not schema_ok:
                repair_error = self._schema_error(parsed) if parsed is not None else "ответ не является JSON"
                if cancel_event is not None and cancel_event.is_set():
                    errors.append("AI остановлен: cancelled")
                    parsed = None
                try:
                    if cancel_event is not None and cancel_event.is_set():
                        raise ProviderStopped("cancelled")
                    repaired = self.provider.complete(
                        [
                            {"role": "system", "content": SYSTEM_PROMPT},
                            {"role": "user", "content": build_repair_request(raw, repair_error)},
                        ],
                        response_format={"type": "json_object"},
                        temperature=0.0,
                        max_tokens=384,
                        cancel_event=cancel_event,
                        deadline=deadline,
                    )
                    candidate = self._parse_json(repaired)
                    if candidate is not None and self._schema_ok(candidate):
                        parsed = candidate
                        schema_ok = True
                        raw = repaired
                    else:
                        errors.append(f"Повторный ответ не прошёл схему: {repair_error}")
                except Exception as exc:
                    errors.append(f"Не удалось исправить JSON: {exc}")

        if parsed is None or not schema_ok:
            result = self._fallback(findings, selected, meta)
            result["validation"]["errors"] = errors + (result["validation"].get("errors") or [])
            result["validation"]["attempted_provider"] = attempted_provider
            result["validation"]["attempted_model"] = attempted_model
            result["validation"]["cancelled"] = bool(
                cancel_event is not None and cancel_event.is_set()
            )
            if result["validation"]["cancelled"]:
                result["validation"]["stopped_reason"] = "cancelled"
            else:
                for reason in ("timeout", "cancelled"):
                    if any(reason in error for error in errors):
                        result["validation"]["stopped_reason"] = reason
                        break
            return result

        grounded, validation = self._ground(parsed, findings, selected)
        if not grounded:
            result = self._fallback(findings, selected, meta)
            result["validation"]["errors"] = errors + validation.get("errors", [])
            for key in (
                "invalid_finding_ids",
                "invalid_file_references",
                "invented_advisories",
                "dropped_items",
            ):
                if key in validation:
                    result["validation"][key] = validation[key]
            result["validation"]["llm_coverage"] = validation.get("coverage")
            result["validation"]["grounded"] = False
            result["validation"]["attempted_provider"] = attempted_provider
            result["validation"]["attempted_model"] = attempted_model
            return result
        validation["errors"] = errors
        validation["attempted_provider"] = attempted_provider
        validation["attempted_model"] = attempted_model
        validation["schema_ok"] = True
        return {
            "provider": attempted_provider,
            "model": attempted_model,
            "summary": parsed["summary"],
            "overall_risk": self._actual_risk(findings),
            "findings": self._merge_items(parsed.get("findings", []), findings, selected),
            "next_steps": parsed.get("next_steps") or self._default_next_steps(findings),
            "validation": validation,
            "generated_at": _now(),
        }


    def generate_workflow(self, prompt: str, source_hint: str = "") -> dict:
        import app.nodes
        import app.ai.planner as planner

        request = build_workflow_ast_request(prompt, source_hint=source_hint)
        warnings: list[str] = []
        raw = ""
        try:
            raw = self.provider.complete(
                [
                    {
                        "role": "system",
                        "content": (
                            "Ты — архитектор сценариев безопасности. "
                            "Верни только валидный JSON AST с порядком шагов и условиями."
                        ),
                    },
                    {"role": "user", "content": request},
                ],
                response_format={"type": "json_object"},
                temperature=0.0,
                max_tokens=1024,
                deadline=time.monotonic() + min(max(180, int(self.settings.llm_timeout or 180)), 300),
            )
        except Exception as exc:
            warnings.append(f"LLM не вернула AST, использован эвристический разбор: {exc}")
        parsed = self._parse_json(raw) if raw else None
        if isinstance(parsed, dict):
            try:
                if isinstance(parsed.get("steps"), list):
                    result = planner.compose_ast(parsed, source_hint=source_hint)
                    report = result.get("validation") or {}
                    if report.get("valid"):
                        result["provider"] = getattr(self.provider, "name", "none")
                        result["warnings"] = warnings + (result.get("warnings") or []) + (report.get("warnings") or [])
                        return result
                    warnings.append(
                        "AST не прошёл валидацию: "
                        + "; ".join(report.get("errors") or [])[:500]
                        + "; использован эвристический разбор"
                    )
                elif isinstance(parsed.get("checks"), list):

                    intent = planner.merge_intent_with_prompt(parsed, prompt)
                    result = planner.compose_workflow(intent, source_hint=source_hint)
                    if (result.get("validation") or {}).get("valid"):
                        result["provider"] = getattr(self.provider, "name", "none")
                        result["warnings"] = warnings + (result.get("warnings") or [])
                        return result
                    warnings.append("Intent не прошёл валидацию; использован эвристический разбор")
            except Exception as exc:
                warnings.append(f"Не удалось собрать AST: {exc}; использован эвристический разбор")
        intent = planner.heuristic_intent(prompt)
        result = planner.compose_workflow(intent, source_hint=source_hint)
        result["provider"] = "heuristic"
        result["warnings"] = warnings + (result.get("warnings") or []) + (result.get("validation", {}).get("warnings") or [])
        return result

    def _planner_graph(self, parsed: dict) -> tuple[dict, list[str]]:
        warnings: list[str] = []
        nodes: list[dict] = []
        for index, item in enumerate(parsed.get("nodes", [])):
            node_type = item.get("type", "")
            spec = NODE_SPECS.get(node_type)
            if spec is None:
                warnings.append(f"Неизвестный тип ноды от LLM: {node_type}")
                continue
            params = item.get("params") if isinstance(item.get("params"), dict) else {}
            try:
                params = validate_params(spec, params)
            except ValueError as exc:
                warnings.append(f"Параметры ноды {node_type} скорректированы: {exc}")
                params = {}
            nodes.append(
                {
                    "id": str(item.get("id") or f"n{index + 1}"),
                    "type": node_type,
                    "position": {
                        "x": 80 + 280 * (index % 4),
                        "y": 80 + 180 * (index // 4),
                    },
                    "data": {
                        "label": item.get("label") or spec.title,
                        "params": params,
                    },
                }
            )
        edges = []
        for edge in parsed.get("edges", []):
            edges.append(
                {
                    "id": f"e-{edge.get('source')}-{edge.get('target')}",
                    "source": edge.get("source"),
                    "target": edge.get("target"),
                    "sourceHandle": edge.get("sourceHandle") or "out",
                    "targetHandle": edge.get("targetHandle") or "in",
                }
            )
        return normalize_graph({"nodes": nodes, "edges": edges}), warnings

    def _parse_json(self, text: str) -> dict | None:
        if not text:
            return None
        candidate = text.strip()
        if candidate.startswith("```"):
            candidate = re.sub(r"^```(?:json)?\s*", "", candidate)
            candidate = re.sub(r"\s*```$", "", candidate)
        try:
            data = json.loads(candidate)
            return data if isinstance(data, dict) else None
        except ValueError:
            start = candidate.find("{")
            end = candidate.rfind("}")
            if start >= 0 and end > start:
                try:
                    data = json.loads(candidate[start : end + 1])
                    return data if isinstance(data, dict) else None
                except ValueError:
                    return None
        return None

    def _schema_ok(self, data: dict) -> bool:
        try:
            jsonschema.validate(data, ANALYSIS_SCHEMA)
            return True
        except jsonschema.ValidationError:
            return False

    def _schema_error(self, data: dict | None) -> str:
        if data is None:
            return "ответ не является JSON-объектом"
        try:
            jsonschema.validate(data, ANALYSIS_SCHEMA)
            return ""
        except jsonschema.ValidationError as exc:
            return f"{exc.message} ({'/'.join(str(p) for p in exc.path)})"

    def _ground(self, parsed: dict, findings: list[Finding], selected: list[Finding]) -> tuple[bool, dict]:
        known = {finding.fingerprint: finding for finding in findings}
        selected_ids = {finding.fingerprint for finding in selected}
        known_paths = {finding.path for finding in findings}
        allowed_advisories = {
            value
            for finding in findings
            for value in ([finding.advisory_id] if finding.advisory_id else []) + list(finding.advisory_ids)
            if value
        }
        invalid_ids: list[str] = []
        invalid_refs: list[str] = []
        invented_advisories: list[str] = []
        dropped = 0
        sanitized_items: list[dict] = []
        for item in parsed.get("findings", []):
            finding_id = str(item.get("finding_id") or "")
            if finding_id not in known:
                invalid_ids.append(finding_id)
                dropped += 1
                continue
            cleaned = dict(item)
            for field in ("explanation", "remediation", "severity_assessment"):
                if field in cleaned and isinstance(cleaned[field], str):
                    value, refs, invented = self._sanitize_text(
                        cleaned[field], known_paths, allowed_advisories
                    )
                    cleaned[field] = value
                    invalid_refs.extend(refs)
                    invented_advisories.extend(invented)
            if finding_id not in selected_ids:


                cleaned["confidence"] = min(float(cleaned.get("confidence", 0.5)), 0.5)
            sanitized_items.append(cleaned)

        summary, refs, invented = self._sanitize_text(
            str(parsed.get("summary", "")), known_paths, allowed_advisories
        )
        invalid_refs.extend(refs)
        invented_advisories.extend(invented)
        next_steps: list[str] = []
        for step in parsed.get("next_steps", []) or []:
            if not isinstance(step, str):
                continue
            value, refs, invented = self._sanitize_text(step, known_paths, allowed_advisories)
            next_steps.append(value)
            invalid_refs.extend(refs)
            invented_advisories.extend(invented)

        if not summary.strip():
            summary = self._fallback_summary(findings)
        parsed["summary"] = summary
        parsed["findings"] = sanitized_items
        parsed["next_steps"] = next_steps
        explained = {item.get("finding_id") for item in sanitized_items}
        missing = [finding for finding in findings if finding.fingerprint not in explained]
        validation = {
            "grounded": not invalid_ids and not invented_advisories,
            "schema_ok": True,
            "referenced_findings": len(sanitized_items),
            "valid_finding_ids": len(explained),
            "invalid_finding_ids": invalid_ids,
            "invalid_file_references": sorted(set(invalid_refs)),
            "invented_advisories": sorted(set(invented_advisories)),
            "dropped_items": dropped,
            "coverage": {
                "explained": len(explained),
                "total": len(findings),
                "missing": [finding.fingerprint for finding in missing],
            },
            "errors": [],
        }
        return validation["grounded"], validation

    def _sanitize_text(
        self, text: str, known_paths: set[str], allowed_advisories: set[str]
    ) -> tuple[str, list[str], list[str]]:
        invalid_refs: list[str] = []
        invented: list[str] = []

        def advisory_replace(match: re.Match) -> str:
            value = match.group(0)
            if value in allowed_advisories:
                return value
            invented.append(value)
            return "[идентификатор удалён: не подтверждён находками]"

        cleaned = ADVISORY_RE.sub(advisory_replace, text)

        def file_replace(match: re.Match) -> str:
            value = match.group(0)
            if any(value == path or path.endswith("/" + value) or value in path for path in known_paths):
                return value
            invalid_refs.append(value)
            return "[файл не подтверждён]"

        cleaned = FILE_RE.sub(file_replace, cleaned)
        return cleaned, invalid_refs, invented

    def _merge_items(self, items: list[dict], findings: list[Finding], selected: list[Finding]) -> list[dict]:
        by_id = {item.get("finding_id"): item for item in items}
        merged: list[dict] = []
        for finding in findings:
            item = by_id.get(finding.fingerprint)
            if item:
                merged.append(
                    {
                        "finding_id": finding.fingerprint,
                        "category": finding.category,
                        "class": finding.class_name,
                        "path": finding.path,
                        "line": finding.line,
                        "severity": finding.severity,
                        "explanation": item.get("explanation", ""),
                        "remediation": item.get("remediation") or finding.remediation,
                        "severity_assessment": item.get("severity_assessment", finding.severity),
                        "confidence": float(item.get("confidence", finding.confidence)),
                        "source": "llm",
                    }
                )
            else:
                merged.append(_fallback_item(finding))
        return merged

    def _fallback(self, findings: list[Finding], selected: list[Finding], meta: dict) -> dict:
        items = [_fallback_item(finding) for finding in findings]
        return {
            "provider": "fallback",
            "model": "",
            "summary": self._fallback_summary(findings),
            "overall_risk": self._actual_risk(findings),
            "findings": items,
            "next_steps": self._default_next_steps(findings),
            "validation": {
                "grounded": True,
                "fallback": True,
                "schema_ok": False,
                "referenced_findings": len(items),
                "valid_finding_ids": len(items),
                "invalid_finding_ids": [],
                "invalid_file_references": [],
                "invented_advisories": [],
                "dropped_items": 0,
                "coverage": {"explained": len(items), "total": len(findings), "missing": []},
                "errors": [],
                "context": {"findings": len(findings), "selected_for_llm": len(selected)},
            },
            "generated_at": _now(),
        }

    def _empty_result(self) -> dict:
        return {
            "provider": "none",
            "model": "",
            "summary": "Находок не обнаружено: проверенные анализаторы не выявили проблем.",
            "overall_risk": "LOW",
            "findings": [],
            "next_steps": ["Запустить проверку на другом источнике или расширить набор правил."],
            "validation": {
                "grounded": True,
                "fallback": True,
                "schema_ok": True,
                "referenced_findings": 0,
                "valid_finding_ids": 0,
                "invalid_finding_ids": [],
                "invalid_file_references": [],
                "invented_advisories": [],
                "dropped_items": 0,
                "coverage": {"explained": 0, "total": 0, "missing": []},
                "errors": [],
            },
            "generated_at": _now(),
        }

    def _fallback_summary(self, findings: list[Finding]) -> str:
        counts = severity_counts(findings)
        classes: dict[str, int] = {}
        for finding in findings:
            classes[finding.class_name] = classes.get(finding.class_name, 0) + 1
        top = ", ".join(f"{name} ({count})" for name, count in sorted(classes.items(), key=lambda item: -item[1])[:4])
        categories = sorted({finding.category for finding in findings})
        return (
            f"Обнаружено {counts['total']} находок: CRITICAL — {counts['CRITICAL']}, "
            f"HIGH — {counts['HIGH']}, MEDIUM — {counts['MEDIUM']}, LOW — {counts['LOW']}. "
            f"Категории: {', '.join(categories)}. Самые частые типы: {top or 'нет'}."
        )

    def _actual_risk(self, findings: list[Finding]) -> str:
        return max_severity(findings) or "LOW"

    def _default_next_steps(self, findings: list[Finding]) -> list[str]:
        steps: list[str] = []
        if any(f.category == "SECRET" for f in findings):
            steps.append("Перевыпустить найденные секреты и вынести их в переменные окружения/хранилище.")
        if any(f.category == "SCA" for f in findings):
            steps.append("Обновить уязвимые зависимости до исправленных версий из отчёта.")
        if any(f.class_name in {"sql-injection", "object-authorization"} for f in findings):
            steps.append("Перейти на параметризованные SQL-запросы и проверять владельца записи.")
        if any(f.class_name in {"route-authorization", "credentialed-cors"} for f in findings):
            steps.append("Закрыть служебные маршруты ролью и ограничить CORS доверенным origin.")
        if any(f.class_name == "tls-verification" for f in findings):
            steps.append("Вернуть штатную проверку TLS и имя хоста.")
        if not steps:
            steps.append("Проверить находки вручную и добавить регрессионные тесты.")
        return steps


def _finding_payload(finding: Finding) -> dict:
    data = finding.to_dict()
    data["description"] = (data.get("description") or "")[:600]
    data["evidence"] = (data.get("evidence") or "")[:300]
    data["remediation"] = (data.get("remediation") or "")[:400]
    data["message"] = (data.get("message") or "")[:400]
    return data


def _fallback_item(finding: Finding) -> dict:
    hint = FALLBACK_HINTS.get(finding.class_name, finding.description or finding.message)
    explanation = f"{hint} Место: {finding.path}:{finding.line}."
    if finding.category == "SCA":
        explanation = (
            f"Зависимость {finding.group}:{finding.artifact}:{finding.version} "
            f"попадает в диапазон уязвимости {finding.advisory_id}. {hint}"
        )
    return {
        "finding_id": finding.fingerprint,
        "category": finding.category,
        "class": finding.class_name,
        "path": finding.path,
        "line": finding.line,
        "severity": finding.severity,
        "explanation": explanation,
        "remediation": finding.remediation or "Устраните проблему согласно описанию.",
        "severity_assessment": finding.severity,
        "confidence": finding.confidence,
        "source": "fallback",
    }


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
