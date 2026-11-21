from __future__ import annotations

import unittest
from datetime import datetime

from app.services.scheduler import cron_matches, schedule_matches


class CronTests(unittest.TestCase):
    def test_daily(self):
        moment = datetime(2026, 11, 20, 14, 0)
        self.assertTrue(cron_matches("0 14 * * *", moment))
        self.assertFalse(cron_matches("0 15 * * *", moment))
        self.assertFalse(cron_matches("1 14 * * *", moment))

    def test_weekday(self):
        friday = datetime(2026, 11, 20, 9, 0)
        self.assertTrue(cron_matches("0 9 * * 5", friday))
        self.assertFalse(cron_matches("0 9 * * 1", friday))

    def test_steps_and_lists(self):
        moment = datetime(2026, 11, 20, 9, 30)
        self.assertTrue(cron_matches("*/15 9 * * *", moment))
        self.assertTrue(cron_matches("0,30 9 * * *", moment))
        self.assertFalse(cron_matches("*/15 9 * * *", datetime(2026, 11, 20, 9, 31)))

    def test_range(self):
        self.assertTrue(cron_matches("0 9-18 * * 1-5", datetime(2026, 11, 20, 10, 0)))
        self.assertFalse(cron_matches("0 9-18 * * 1-5", datetime(2026, 11, 21, 10, 0)))

    def test_one_time_date_and_time(self):
        params = {"mode": "once", "run_date": "2026-11-20", "run_time": "14:30"}
        self.assertTrue(schedule_matches(params, datetime(2026, 11, 20, 14, 30)))
        self.assertFalse(schedule_matches(params, datetime(2026, 11, 20, 14, 31)))
        self.assertFalse(schedule_matches(params, datetime(2026, 11, 21, 14, 30)))

    def test_weekly_time(self):
        params = {"mode": "weekly", "weekday": "5", "run_time": "09:00"}
        self.assertTrue(schedule_matches(params, datetime(2026, 11, 20, 9, 0)))
        self.assertFalse(schedule_matches(params, datetime(2026, 11, 19, 9, 0)))
        params["weekday"] = "*"
        self.assertTrue(schedule_matches(params, datetime(2026, 11, 19, 9, 0)))

    def test_invalid_schedule_values(self):
        self.assertFalse(schedule_matches({"mode": "once", "run_date": "bad", "run_time": "09:00"}, datetime(2026, 11, 20, 9, 0)))
        self.assertFalse(schedule_matches({"mode": "weekly", "weekday": "8", "run_time": "09:00"}, datetime(2026, 11, 20, 9, 0)))

    def test_invalid(self):
        self.assertFalse(cron_matches("bad cron", datetime(2026, 11, 20, 9, 0)))
        self.assertFalse(cron_matches("0 25 * * *", datetime(2026, 11, 20, 9, 0)))


if __name__ == "__main__":
    unittest.main()
