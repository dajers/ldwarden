from __future__ import annotations

import unittest
from datetime import datetime

from app.services.scheduler import cron_matches


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

    def test_invalid(self):
        self.assertFalse(cron_matches("bad cron", datetime(2026, 11, 20, 9, 0)))
        self.assertFalse(cron_matches("0 25 * * *", datetime(2026, 11, 20, 9, 0)))


if __name__ == "__main__":
    unittest.main()
