from __future__ import annotations

import unittest

from app.core.models import Finding
from app.reports.builder import build_all, build_html


class HtmlReportTests(unittest.TestCase):
    def _finding(self) -> Finding:
        return Finding(
            category="SECRET",
            class_name="password",
            path="src/main/kotlin/App.kt",
            line=12,
            severity="HIGH",
            message="Пароль в открытом виде",
            description="<script>alert(1)</script>",
            evidence='val password = "secret"',
            remediation="Вынести в переменные окружения",
        )

    def test_html_contains_findings_and_ai(self):
        finding = self._finding()
        html = build_html(
            [finding],
            {"id": "run-1", "workflow_name": "Тест", "status": "success", "trigger": "manual"},
            ai={
                "summary": "Найден пароль",
                "provider": "fake",
                "model": "fake",
                "findings": [
                    {
                        "finding_id": finding.fingerprint,
                        "explanation": "Пароль можно прочитать",
                        "remediation": "Используйте секрет-хранилище",
                    }
                ],
            },
            source={"label": "training-project"},
        )
        self.assertIn("LDWarden", html)
        self.assertIn("src/main/kotlin/App.kt", html)
        self.assertIn("Пароль можно прочитать", html)
        self.assertIn("Используйте секрет-хранилище", html)

    def test_html_escapes_markup(self):
        html = build_html([self._finding()], {"id": "run-1", "workflow_name": "Тест"})
        self.assertIn("&lt;script&gt;", html)
        self.assertNotIn("<script>alert(1)</script>", html)

    def test_build_all_includes_html(self):
        reports = build_all([self._finding()], {"id": "run-1"}, formats=["html"])
        self.assertIn("html", reports)
        self.assertTrue(reports["html"].startswith("<!doctype html>"))


if __name__ == "__main__":
    unittest.main()
