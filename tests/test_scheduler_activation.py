from __future__ import annotations

import json
import unittest
from datetime import datetime, timezone

from app.db import WorkflowRow, close_db
from app.nodes.triggers import ScheduleTrigger
from app.services.scheduler import ScheduleService, next_run
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
        self.client = self.app.test_client()

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

    def test_schedules_endpoint_lists_upcoming(self):
        self._workflow({"mode": "weekly", "weekday": "*", "run_time": "09:00", "timezone": "UTC"})
        response = self.client.get("/api/schedules")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["count"], 1)
        self.assertEqual(data["items"][0]["workflow_id"], "wf-schedule-test")
        self.assertIsNotNone(data["items"][0]["next_run"])
        self.assertTrue(data["items"][0]["valid"])

    def test_once_does_not_repeat_next_day(self):
        self._workflow({"mode": "once", "run_date": "2026-11-20", "run_time": "14:00", "timezone": "UTC"})
        service = ScheduleService(self.settings, self.engine)
        self.assertEqual(len(service.tick(datetime(2026, 11, 20, 14, 0, tzinfo=timezone.utc))), 1)
        self.assertEqual(len(service.tick(datetime(2026, 11, 21, 14, 0, tzinfo=timezone.utc))), 0)


class NextRunTests(unittest.TestCase):
    def test_daily_default_is_every_day(self):
        spec = next(param for param in ScheduleTrigger.params if param.name == "weekday")
        self.assertEqual(spec.default, "*")

    def test_next_run_daily(self):
        params = {"mode": "weekly", "weekday": "*", "run_time": "09:00", "timezone": "UTC"}
        now = datetime(2026, 11, 21, 8, 30, tzinfo=timezone.utc)
        self.assertEqual(next_run(params, now), datetime(2026, 11, 21, 9, 0, tzinfo=timezone.utc))

    def test_next_run_specific_weekday(self):
        params = {"mode": "weekly", "weekday": "5", "run_time": "09:00", "timezone": "UTC"}
        now = datetime(2026, 11, 21, 8, 30, tzinfo=timezone.utc)  # суббота
        scheduled = next_run(params, now)
        self.assertIsNotNone(scheduled)
        self.assertEqual(scheduled.isoweekday(), 5)
        self.assertGreater(scheduled, now)

    def test_next_run_once_in_past_is_none(self):
        params = {"mode": "once", "run_date": "2026-11-20", "run_time": "14:00", "timezone": "UTC"}
        now = datetime(2026, 11, 21, 8, 30, tzinfo=timezone.utc)
        self.assertIsNone(next_run(params, now))

    def test_preview_endpoint(self):
        client = make_app(enable_scheduler=False, seed_templates=False)[0].test_client()
        response = client.post(
            "/api/schedules/preview",
            json={"mode": "weekly", "weekday": "*", "run_time": "09:00", "timezone": "UTC"},
        )
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertTrue(data["ok"])
        self.assertIn("09:00", data["human"])
        close_db()
