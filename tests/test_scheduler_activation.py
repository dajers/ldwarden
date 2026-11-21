from __future__ import annotations

import json
import unittest
from datetime import datetime, timezone

from app.db import WorkflowRow, close_db
from app.services.scheduler import ScheduleService
from tests.helpers import make_app


class FakeEngine:
    def __init__(self):
        self.calls = []

    def start_run(self, workflow, **kwargs):
        self.calls.append((workflow.get("id"), kwargs))
        return {"id": f"run-{len(self.calls)}"}


class SchedulerActivationTests(unittest.TestCase):
    def setUp(self):
        self.app, self.settings = make_app(enable_scheduler=False, seed_templates=False)
        self.engine = FakeEngine()

    def tearDown(self):
        close_db()

    def _workflow(self, params):
        graph = {
            "nodes": [
                {"id": "schedule", "type": "trigger.schedule", "position": {"x": 0, "y": 0}, "data": {"params": params}}
            ],
            "edges": [],
        }
        return WorkflowRow.create(
            id="wf-schedule-test",
            name="schedule",
            graph=json.dumps(graph),
            is_template=False,
            published=False,
        )

    def test_weekly_activation_and_cooldown(self):
        self._workflow({"mode": "weekly", "weekday": "5", "run_time": "09:00", "timezone": "UTC"})
        service = ScheduleService(self.settings, self.engine)
        now = datetime(2026, 11, 20, 9, 0, tzinfo=timezone.utc)
        self.assertEqual(len(service.tick(now)), 1)
        self.assertEqual(len(service.tick(now)), 0)
        self.assertEqual(len(self.engine.calls), 1)

    def test_once_does_not_repeat_next_day(self):
        self._workflow({"mode": "once", "run_date": "2026-11-20", "run_time": "14:00", "timezone": "UTC"})
        service = ScheduleService(self.settings, self.engine)
        self.assertEqual(len(service.tick(datetime(2026, 11, 20, 14, 0, tzinfo=timezone.utc))), 1)
        self.assertEqual(len(service.tick(datetime(2026, 11, 21, 14, 0, tzinfo=timezone.utc))), 0)
