from __future__ import annotations

import json
import threading
import time
import traceback
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from app.config import Settings
from app.core.graph import adjacency, graph_summary, is_trigger, normalize_graph, validate_graph, node_params
from app.core.models import (
    Finding,
    NodeResult,
    count_by,
    dedupe_findings,
    filter_min_severity,
    max_severity,
    severity_counts,
    sort_findings,
)
from app.core.registry import (
    NODE_CLASSES,
    NODE_SPECS,
    get_class,
    get_spec,
    secret_param_names,
    validate_params,
)
from app.core.source import SourceService, SourceTree, build_tree
from app.crypto import SecretBox, scrub_text
from app.db import (
    FindingRow,
    RunEventRow,
    RunRow,
    WorkflowRow,
    iso,
    j_dumps,
    j_loads,
    utcnow,
)
from app.reports.builder import build_all


import app.nodes


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def trigger_kind(trigger: str | None) -> str:
    value = (trigger or "manual").lower()
    if value in {"ci", "pipeline", "github", "gitlab", "pr"}:
        return "webhook"
    if value in {"manual", "schedule", "webhook"}:
        return value
    return "manual"


def _node_trigger_kind(node_type: str) -> str:
    return {
        "trigger.manual": "manual",
        "trigger.schedule": "schedule",
        "trigger.webhook": "webhook",
    }.get(node_type, "")


@dataclass
class RunContext:
    run_id: str
    settings: Settings
    workflow: dict
    graph: dict
    trigger: str
    trigger_payload: dict
    target: dict | str | None
    ci_mode: bool
    engine: "WorkflowEngine"
    source_service: SourceService
    source: SourceTree | None = None
    findings: list[Finding] = field(default_factory=list)
    ai_analysis: dict | None = None
    reports: dict[str, str] = field(default_factory=dict)
    gate: dict | None = None
    vars: dict = field(default_factory=dict)
    node_id: str | None = None
    status: str = "running"
    started_at: datetime | None = None
    duration_ms: int | None = None
    secret_values: list[str] = field(default_factory=list)
    node_states: dict[str, dict] = field(default_factory=dict)
    source_ready: bool = False
    target_explicit: bool = False
    cancel_event: threading.Event | None = None


    def emit(
        self,
        event_type: str,
        message: str = "",
        *,
        node_id: str | None = None,
        level: str = "info",
        payload: dict | None = None,
    ) -> None:
        self.engine._emit(
            self.run_id,
            event_type,
            message=message,
            node_id=node_id,
            level=level,
            payload=payload,
            secrets=self.secret_values,
        )


    def resolve_source(
        self,
        path: str | None = None,
        source_id: str | None = None,
        include: list[str] | None = None,
        exclude: list[str] | None = None,
        git_token: str | None = None,
        git_username: str | None = None,
    ) -> SourceTree:
        if path or source_id:
            target = {"kind": "source", "id": source_id} if source_id else {"kind": "path", "path": path}
            self.source = self.source_service.resolve(target, include=include, exclude=exclude)
            return self.source
        if self.source is None:
            target = self.target
            if isinstance(target, dict) and str(target.get("kind")) == "git":
                target = {
                    **target,
                    "token": git_token or target.get("token") or "",
                    "username": git_username or target.get("username") or "",
                }
            self.source = self.source_service.resolve(target, include=include, exclude=exclude)
            return self.source
        if include or exclude:
            self.source = build_tree(
                self.source.root,
                label=self.source.label,
                kind=self.source.kind,
                max_files=self.settings.max_files,
                max_file_bytes=self.settings.max_file_bytes,
                include=include,
                exclude=exclude,
            )
        return self.source

    def require_source(self) -> None:
        if self.source_ready or self.target_explicit:
            return
        raise RuntimeError(
            "Источник кода не подключён к проверке. Добавьте ноду «Репозиторий» "
            "и соедините её с проверками (или передайте target при запуске)."
        )

    def source_view(
        self,
        path: str | None = None,
        source_id: str | None = None,
        include: list[str] | None = None,
        exclude: list[str] | None = None,
    ) -> SourceTree:
        """Resolve a source for one node without mutating the run-wide source."""
        if path or source_id:
            target = {"kind": "source", "id": source_id} if source_id else {"kind": "path", "path": path}
            base = self.source_service.resolve(target)
        else:
            base = self.resolve_source()
        if include or exclude:
            return build_tree(
                base.root,
                label=base.label,
                kind=base.kind,
                max_files=self.settings.max_files,
                max_file_bytes=self.settings.max_file_bytes,
                include=include,
                exclude=exclude,
            )
        return base


    def add_findings(self, findings: list[Finding], node_id: str | None = None) -> int:
        before = {finding.fingerprint for finding in self.findings}
        for finding in findings:
            if not finding.source_node:
                finding.source_node = self.node_id or ""
        self.findings = dedupe_findings(self.findings + findings)
        after = {finding.fingerprint for finding in self.findings}
        return len(after - before)


    def display_status(self) -> str:
        if self.status in {"failed", "cancelled"}:
            return self.status
        if self.gate and self.gate.get("blocking") and not self.gate.get("passed"):
            return "failed"
        if any(state.get("status") == "error" for state in self.node_states.values()):
            return "failed"
        return "success" if self.status == "running" else self.status

    def run_info(self) -> dict:
        return {
            "id": self.run_id,
            "workflow_name": (self.workflow or {}).get("name", ""),
            "status": self.display_status(),
            "trigger": self.trigger,
            "started_at": iso(self.started_at),
            "duration_ms": self.duration_ms,
            "source_label": self.source.label if self.source else "",
        }


class WorkflowEngine:
    def __init__(self, settings: Settings, source_service: SourceService | None = None):
        self.settings = settings
        self.source_service = source_service or SourceService(settings)
        self.secret_box = SecretBox(settings.secret_key_path)
        self._cancel: dict[str, threading.Event] = {}
        self._threads: dict[str, threading.Thread] = {}
        self._lock = threading.Lock()


    def start_run(
        self,
        workflow: dict,
        *,
        trigger: str = "manual",
        target: dict | str | None = None,
        wait: bool = False,
        ci_mode: bool = False,
        trigger_payload: dict | None = None,
        run_params: dict | None = None,
    ) -> dict:
        graph = normalize_graph((workflow or {}).get("graph") or {"nodes": [], "edges": []})
        report = validate_graph(graph)
        if not report["valid"]:
            raise ValueError("; ".join(report["errors"]))
        graph = report["graph"]
        from app.services.custom_nodes import expand_composite_nodes

        graph = expand_composite_nodes(graph)
        run_id = uuid.uuid4().hex[:16]
        RunRow.create(
            id=run_id,
            workflow_id=(workflow or {}).get("id"),
            workflow_name=(workflow or {}).get("name", ""),
            status="queued",
            trigger=trigger,
            target=json.dumps(target, ensure_ascii=False) if target is not None else "",
            ci_mode=ci_mode,
        )
        cancel_event = threading.Event()
        with self._lock:
            self._cancel[run_id] = cancel_event
        if wait:
            self._execute(
                run_id,
                workflow,
                graph,
                trigger,
                target,
                ci_mode,
                trigger_payload or {},
                run_params or {},
            )
        else:
            thread = threading.Thread(
                target=self._execute,
                args=(
                    run_id,
                    workflow,
                    graph,
                    trigger,
                    target,
                    ci_mode,
                    trigger_payload or {},
                    run_params or {},
                ),
                name=f"ldwarden-run-{run_id}",
                daemon=True,
            )
            with self._lock:
                self._threads[run_id] = thread
            thread.start()
        run = RunRow.get_by_id(run_id)
        return run.to_dict()

    def cancel(self, run_id: str) -> bool:
        with self._lock:
            event = self._cancel.get(run_id)
        if event is None:
            run = RunRow.get_or_none(RunRow.id == run_id)
            if run and run.status in {"queued", "running"}:
                run.status = "cancelled"
                run.finished_at = utcnow()
                run.save()
                return True
            return False
        event.set()
        return True

    def wait(self, run_id: str, timeout: float | None = None) -> dict:
        with self._lock:
            thread = self._threads.get(run_id)
        if thread is not None:
            thread.join(timeout)
        run = RunRow.get_or_none(RunRow.id == run_id)
        return run.to_dict() if run else {}


    def _emit(
        self,
        run_id: str,
        event_type: str,
        *,
        message: str = "",
        node_id: str | None = None,
        level: str = "info",
        payload: dict | None = None,
        secrets: list[str] | None = None,
    ) -> None:
        try:
            last = (
                RunEventRow.select(RunEventRow.seq)
                .where(RunEventRow.run_id == run_id)
                .order_by(RunEventRow.seq.desc())
                .first()
            )
            seq = (last.seq if last else 0) + 1
            clean_message = scrub_text(message or "", secrets or [])
            clean_payload = _truncate_payload(payload or {})
            payload_text = scrub_text(j_dumps(clean_payload), secrets or [])
            RunEventRow.create(
                run_id=run_id,
                seq=seq,
                type=event_type,
                level=level,
                node_id=node_id,
                message=clean_message,
                payload=payload_text,
            )
        except Exception:

            pass


    def _execute(
        self,
        run_id: str,
        workflow: dict,
        graph: dict,
        trigger: str,
        target: dict | str | None,
        ci_mode: bool,
        trigger_payload: dict,
        run_params: dict,
    ) -> None:
        started = time.monotonic()
        run = RunRow.get_by_id(run_id)
        run.status = "running"
        run.started_at = utcnow()
        run.save()
        cancel_event = self._cancel.get(run_id) or threading.Event()
        ctx = RunContext(
            run_id=run_id,
            settings=self.settings,
            workflow=workflow or {},
            graph=graph,
            trigger=trigger,
            trigger_payload=trigger_payload,
            target=target,
            ci_mode=ci_mode,
            engine=self,
            source_service=self.source_service,
            started_at=run.started_at,
            target_explicit=target is not None,
            cancel_event=cancel_event,
        )
        ctx.vars["run_params"] = run_params
        failed_nodes: set[str] = set()
        persisted: set[str] = set()
        node_states: dict[str, dict] = {}

        self._emit(
            run_id,
            "run.started",
            message=f"Запуск workflow «{workflow.get('name', '')}»",
            payload={
                "workflow_id": (workflow or {}).get("id"),
                "trigger": trigger,
                "ci_mode": ci_mode,
                "graph": graph_summary(graph),
            },
        )

        try:
            nodes_by_id = {node["id"]: node for node in graph["nodes"]}
            outgoing, incoming = adjacency(graph)
            trigger_ids = [node["id"] for node in graph["nodes"] if is_trigger(node)]
            wanted = trigger_kind(trigger)
            selected_triggers = [
                node_id
                for node_id in trigger_ids
                if _node_trigger_kind(nodes_by_id[node_id]["type"]) == wanted
            ]
            if not selected_triggers:
                selected_triggers = trigger_ids
            if not selected_triggers:
                raise ValueError("В workflow нет триггера")

            pending: dict[str, int] = {}
            for node_id in nodes_by_id:
                pending[node_id] = 0 if node_id in selected_triggers else len(incoming[node_id])
            ready: deque[str] = deque(selected_triggers)
            queued = set(selected_triggers)
            active_edges: set[str] = set()
            inactive_edges: set[str] = set()
            executed: set[str] = set()
            skipped: set[str] = set()

            def emit_node_state(node_id: str, status: str, **extra) -> None:
                previous = node_states.get(node_id) or {}
                spec_ = get_spec(nodes_by_id[node_id]["type"])
                node_states[node_id] = {
                    **previous,
                    "status": status,
                    "title": spec_.title if spec_ else nodes_by_id[node_id]["type"],
                    **extra,
                }
                ctx.node_states = node_states

            def enqueue(node_id: str) -> None:
                if node_id in queued or node_id in executed or node_id in skipped:
                    return
                queued.add(node_id)
                ready.append(node_id)

            def skip_node(node_id: str, reason: str) -> None:
                if node_id in executed or node_id in skipped:
                    return
                skipped.add(node_id)
                emit_node_state(node_id, "skipped", message=reason)
                self._emit(run_id, "node.skipped", message=reason, node_id=node_id, level="info", secrets=ctx.secret_values)
                for edge in outgoing.get(node_id, []):
                    resolve_edge(edge, False)

            def resolve_edge(edge: dict, active: bool) -> None:
                edge_id = edge["id"]
                if edge_id in active_edges or edge_id in inactive_edges:
                    return
                if active:
                    active_edges.add(edge_id)
                else:
                    inactive_edges.add(edge_id)
                target_id = edge["target"]
                pending[target_id] = max(0, pending.get(target_id, 1) - 1)
                if pending[target_id] == 0:
                    if any(incoming_edge["id"] in active_edges for incoming_edge in incoming.get(target_id, [])):
                        enqueue(target_id)
                    else:
                        skip_node(target_id, "Ветка не выбрана условием")

            persisted_here: set[str] = persisted

            while ready:
                if cancel_event.is_set():
                    break
                node_id = ready.popleft()
                queued.discard(node_id)
                if node_id in executed or node_id in skipped:
                    continue
                node = nodes_by_id.get(node_id)
                if node is None:
                    continue
                spec = get_spec(node.get("type", ""))
                if spec is None:
                    failed_nodes.add(node_id)
                    emit_node_state(node_id, "error", message="Неизвестный тип ноды")
                    self._emit(
                        run_id,
                        "node.failed",
                        message=f"Неизвестный тип ноды: {node.get('type')}",
                        node_id=node_id,
                        level="error",
                    )
                    for edge in outgoing.get(node_id, []):
                        resolve_edge(edge, False)
                    continue
                data = node.get("data") or {}
                if data.get("disabled"):
                    skipped.add(node_id)
                    emit_node_state(node_id, "skipped", message="Нода отключена")
                    self._emit(run_id, "node.skipped", message="Нода отключена", node_id=node_id)
                    for edge in outgoing.get(node_id, []):
                        resolve_edge(edge, False)
                    continue

                ctx.node_id = node_id
                node_started = time.monotonic()
                raw_params = node_params(node, spec)
                try:
                    params = validate_params(spec, raw_params)
                except ValueError as exc:
                    failed_nodes.add(node_id)
                    executed.add(node_id)
                    emit_node_state(node_id, "error", message=str(exc))
                    self._emit(
                        run_id,
                        "node.failed",
                        message=f"Некорректные параметры: {exc}",
                        node_id=node_id,
                        level="error",
                        payload={"details": getattr(exc, "details", [])},
                    )
                    for edge in outgoing.get(node_id, []):
                        resolve_edge(edge, False)
                    continue


                for param_name in secret_param_names(spec):
                    value = params.get(param_name)
                    if isinstance(value, str) and value.startswith("enc:v1:"):
                        try:
                            params[param_name] = self.secret_box.decrypt(value)
                            if params[param_name]:
                                ctx.secret_values.append(params[param_name])
                        except Exception as exc:
                            failed_nodes.add(node_id)
                            executed.add(node_id)
                            emit_node_state(node_id, "error", message=f"Ошибка расшифровки: {exc}")
                            self._emit(
                                run_id,
                                "node.failed",
                                message=f"Не удалось расшифровать секрет «{param_name}»",
                                node_id=node_id,
                                level="error",
                            )
                            for edge in outgoing.get(node_id, []):
                                resolve_edge(edge, False)
                            break
                else:
                    emitted_start = time.monotonic()
                    emit_node_state(node_id, "running", started_at=_now_iso())
                    self._emit(
                        run_id,
                        "node.started",
                        message=f"Запуск: {spec.title}",
                        node_id=node_id,
                        payload={"type": spec.type, "category": spec.category},
                    )
                    try:
                        node_instance = get_class(spec.type)()
                        result = node_instance.execute(ctx, params)
                        result = node_instance.validate_output(result)
                        duration_ms = int((time.monotonic() - node_started) * 1000)
                        emit_node_state(
                            node_id,
                            "success" if result.status == "success" else result.status,
                            duration_ms=duration_ms,
                            message=result.message,
                            active_handles=result.active_handles,
                        )
                        self._emit(
                            run_id,
                            "node.finished",
                            message=result.message or f"Нода выполнена за {duration_ms} мс",
                            node_id=node_id,
                            payload={
                                "duration_ms": duration_ms,
                                "status": result.status,
                                "active_handles": result.active_handles,
                                "outputs": _safe_outputs(result.outputs),
                                "preview": result.preview,
                                "findings_count": result.findings_count,
                            },
                            secrets=ctx.secret_values,
                        )
                        if result.status == "error":
                            failed_nodes.add(node_id)
                        for edge in outgoing.get(node_id, []):
                            handle = edge.get("sourceHandle", "out")
                            resolve_edge(edge, handle in result.active_handles)
                    except Exception as exc:
                        duration_ms = int((time.monotonic() - node_started) * 1000)
                        failed_nodes.add(node_id)
                        error_text = f"{type(exc).__name__}: {exc}"
                        emit_node_state(node_id, "error", duration_ms=duration_ms, message=error_text)
                        self._emit(
                            run_id,
                            "node.failed",
                            message=f"Ошибка ноды: {exc}",
                            node_id=node_id,
                            level="error",
                            payload={"error": error_text, "traceback": traceback.format_exc()[-3000:]},
                            secrets=ctx.secret_values,
                        )
                        for edge in outgoing.get(node_id, []):
                            resolve_edge(edge, False)

                executed.add(node_id)


                for finding in ctx.findings:
                    if finding.fingerprint in persisted_here:
                        continue
                    try:
                        FindingRow.create(
                            run_id=run_id,
                            node_id=finding.source_node or node_id,
                            fingerprint=finding.fingerprint,
                            category=finding.category,
                            class_code=finding.class_name,
                            rule_id=finding.rule_id,
                            severity=finding.severity,
                            path=finding.path,
                            line=finding.line,
                            end_line=finding.end_line,
                            message=finding.message,
                            description=finding.description,
                            remediation=finding.remediation,
                            cwe=finding.cwe,
                            evidence=finding.evidence,
                            confidence=str(finding.confidence),
                            detector=finding.detector,
                            extra=j_dumps(finding.extra),
                        )
                        persisted_here.add(finding.fingerprint)
                    except Exception:
                        pass


            for node_id in nodes_by_id:
                if node_id not in executed and node_id not in skipped and node_id not in failed_nodes:
                    skip_node(node_id, "Нода не достигнута")

            if cancel_event.is_set():
                ctx.status = "cancelled"
                self._emit(run_id, "run.cancelled", message="Запуск отменён пользователем", level="warning")
            elif failed_nodes:
                ctx.status = "failed"
            elif ctx.gate and ctx.gate.get("blocking") and not ctx.gate.get("passed"):
                ctx.status = "failed"
            else:
                ctx.status = "success"


            if not ctx.reports:
                ctx.reports.update(
                    build_all(
                        ctx.findings,
                        ctx.run_info(),
                        ai=ctx.ai_analysis,
                        gate=ctx.gate,
                        source=ctx.source.to_dict() if ctx.source else None,
                    )
                )
            ctx.duration_ms = int((time.monotonic() - started) * 1000)
            summary = self._build_summary(ctx, node_states)
            run = RunRow.get_by_id(run_id)
            run.status = ctx.status
            run.finished_at = utcnow()
            run.duration_ms = ctx.duration_ms
            run.source_label = ctx.source.label if ctx.source else ""
            run.summary = j_dumps(summary)
            run.ai = j_dumps(ctx.ai_analysis) if ctx.ai_analysis else ""
            run.gate = j_dumps(ctx.gate) if ctx.gate else ""
            run.report_md = ctx.reports.get("md", "")
            run.report_json = ctx.reports.get("json", "")
            run.report_sarif = ctx.reports.get("sarif", "")
            run.error = ""
            run.save()
            self._emit(
                run_id,
                "run.finished",
                message=f"Запуск завершён: {ctx.status}",
                level="info" if ctx.status == "success" else "warning",
                payload={
                    "status": ctx.status,
                    "duration_ms": ctx.duration_ms,
                    "summary": summary,
                    "notification": ctx.vars.get("notification"),
                },
            )
        except Exception as exc:
            ctx.duration_ms = int((time.monotonic() - started) * 1000)
            run = RunRow.get_by_id(run_id)
            run.status = "failed"
            run.finished_at = utcnow()
            run.duration_ms = ctx.duration_ms
            run.error = f"{type(exc).__name__}: {exc}"
            run.summary = j_dumps(self._build_summary(ctx, node_states))
            run.save()
            self._emit(
                run_id,
                "run.failed",
                message=f"Запуск завершился ошибкой: {exc}",
                level="error",
                payload={"error": str(exc), "traceback": traceback.format_exc()[-4000:]},
            )
        finally:
            with self._lock:
                self._threads.pop(run_id, None)
                self._cancel.pop(run_id, None)

    def _build_summary(self, ctx: RunContext, node_states: dict) -> dict:
        counts = severity_counts(ctx.findings)
        return {
            "findings": {
                "total": counts["total"],
                "by_severity": counts,
                "by_category": count_by(ctx.findings, "category"),
                "by_class": count_by(ctx.findings, "class_name"),
                "max_severity": max_severity(ctx.findings),
            },
            "nodes": node_states,
            "gate": ctx.gate,
            "ai": {
                "provider": (ctx.ai_analysis or {}).get("provider"),
                "model": (ctx.ai_analysis or {}).get("model"),
                "overall_risk": (ctx.ai_analysis or {}).get("overall_risk"),
                "grounded": ((ctx.ai_analysis or {}).get("validation") or {}).get("grounded"),
                "coverage": ((ctx.ai_analysis or {}).get("validation") or {}).get("coverage"),
            }
            if ctx.ai_analysis
            else None,
            "source": ctx.source.to_dict() if ctx.source else None,
            "notification": ctx.vars.get("notification"),
            "duration_ms": ctx.duration_ms,
            "trigger": ctx.trigger,
            "ci_mode": ctx.ci_mode,
        }


def _truncate_payload(value: Any, depth: int = 0) -> Any:
    if depth > 5:
        return "…"
    if isinstance(value, str):
        return value if len(value) <= 3000 else value[:3000] + "…"
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    if isinstance(value, dict):
        return {str(key)[:80]: _truncate_payload(item, depth + 1) for key, item in list(value.items())[:60]}
    if isinstance(value, (list, tuple, set)):
        return [_truncate_payload(item, depth + 1) for item in list(value)[:40]]
    return str(value)[:1000]


def _safe_outputs(outputs: dict) -> dict:
    return _truncate_payload(outputs or {})
