from __future__ import annotations

import json
import logging
import threading
import time
from datetime import date, datetime, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from app.config import Settings
from app.core.engine import WorkflowEngine
from app.db import ScheduleStateRow, WorkflowRow, utcnow

logger = logging.getLogger(__name__)

FIELD_RANGES = [(0, 59), (0, 23), (1, 31), (1, 12), (0, 7)]


def _parse_field(expression: str, minimum: int, maximum: int) -> set[int]:
    values: set[int] = set()
    for part in expression.split(","):
        part = part.strip()
        if not part:
            continue
        step = 1
        if "/" in part:
            base, step_text = part.split("/", 1)
            step = int(step_text)
            if step <= 0:
                raise ValueError("Шаг cron должен быть положительным")
        else:
            base = part
        if base == "*":
            start, end = minimum, maximum
        elif "-" in base:
            start_text, end_text = base.split("-", 1)
            start, end = int(start_text), int(end_text)
        else:
            start = end = int(base)
        if start < minimum or end > maximum or start > end:
            raise ValueError(f"Значение cron вне диапазона: {part}")
        values.update(range(start, end + 1, step))
    return values


def cron_matches(expression: str, moment: datetime) -> bool:
    fields = (expression or "").split()
    if len(fields) != 5:
        return False
    try:
        minute = _parse_field(fields[0], 0, 59)
        hour = _parse_field(fields[1], 0, 23)
        day = _parse_field(fields[2], 1, 31)
        month = _parse_field(fields[3], 1, 12)
        weekday = _parse_field(fields[4], 0, 7)
        weekday = {0 if value == 7 else value for value in weekday}
    except (ValueError, TypeError):
        return False
    if moment.minute not in minute or moment.hour not in hour or moment.month not in month:
        return False
    dom_restricted = fields[2].strip() != "*"
    dow_restricted = fields[4].strip() != "*"
    dom_ok = moment.day in day
    dow_ok = (moment.weekday() + 1) % 7 in weekday
    if dom_restricted and dow_restricted:
        return dom_ok or dow_ok
    return dom_ok and dow_ok


def _time_matches(value: str, moment: datetime) -> bool:
    try:
        hour_text, minute_text = str(value or "09:00").strip().split(":", 1)
        return moment.hour == int(hour_text) and moment.minute == int(minute_text)
    except (TypeError, ValueError):
        return False


def schedule_matches(params: dict, moment: datetime) -> bool:
    mode = str(params.get("mode") or "").strip().lower()
    if mode == "once":
        raw_date = str(params.get("run_date") or "").strip()
        try:
            target = date.fromisoformat(raw_date)
        except ValueError:
            return False
        return moment.date() == target and _time_matches(params.get("run_time"), moment)
    if mode in {"weekly", "daily"}:
        weekday = str(params.get("weekday") or "*").strip()
        if mode == "daily":
            weekday = "*"
        if weekday != "*":
            try:
                if moment.isoweekday() != int(weekday):
                    return False
            except ValueError:
                return False
        return _time_matches(params.get("run_time"), moment)
    cron = str(params.get("cron") or "")
    return cron_matches(cron, moment)


class ScheduleService:
    def __init__(self, settings: Settings, engine: WorkflowEngine):
        self.settings = settings
        self.engine = engine
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="ldwarden-scheduler", daemon=True)
        self._thread.start()
        logger.info("Планировщик запущен (интервал %s с)", self.settings.scheduler_interval)

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.tick()
            except Exception:
                logger.exception("Ошибка планировщика")
            self._stop.wait(max(5, self.settings.scheduler_interval))

    def tick(self, now: datetime | None = None) -> list[str]:
        started: list[str] = []
        workflows = WorkflowRow.select()
        for workflow in workflows:
            if workflow.is_template or workflow.published:
                continue
            try:
                graph = json.loads(workflow.graph)
            except (TypeError, ValueError):
                continue
            for node in graph.get("nodes", []):
                if node.get("type") != "trigger.schedule":
                    continue
                params = (node.get("data") or {}).get("params") or {}
                cron = str(params.get("cron") or "")
                timezone_name = str(params.get("timezone") or self.settings.scheduler_timezone)
                try:
                    tz = ZoneInfo(timezone_name)
                except (ZoneInfoNotFoundError, ValueError):
                    tz = timezone.utc
                local_now = (now or datetime.now(timezone.utc)).astimezone(tz)
                if not schedule_matches(params, local_now):
                    continue
                state = ScheduleStateRow.get_or_none(
                    (ScheduleStateRow.workflow_id == workflow.id)
                    & (ScheduleStateRow.node_id == node.get("id"))
                )
                if state and state.last_fired_at:
                    last = state.last_fired_at.replace(tzinfo=timezone.utc)
                    if (datetime.now(timezone.utc) - last).total_seconds() < 55:
                        continue
                try:
                    run = self.engine.start_run(
                        workflow.to_dict(),
                        trigger="schedule",
                        target=None,
                        wait=False,
                    )
                    if state is None:
                        ScheduleStateRow.create(
                            workflow_id=workflow.id,
                            node_id=node.get("id"),
                            last_fired_at=utcnow(),
                        )
                    else:
                        state.last_fired_at = utcnow()
                        state.save()
                    started.append(run["id"])
                except Exception:
                    logger.exception("Не удалось запустить workflow %s по расписанию", workflow.id)
        return started
