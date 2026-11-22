from __future__ import annotations

import unittest

from app.ai.providers import FakeProvider, NullProvider
from app.ai.service import AIService
from app.config import load_settings
from app.core.models import Finding


def _findings() -> list[Finding]:
    return [
        Finding(
            category="SAST",
            class_name="sql-injection",
            path="src/main/kotlin/App.kt",
            line=10,
            end_line=11,
            severity="HIGH",
            message="SQL injection",
            description="Параметр подставляется в SQL",
            remediation="Используйте ?",
            cwe="CWE-89",
            rule_id="sast-sql-injection",
            evidence="SELECT ... $id",
            confidence=0.9,
        ),
        Finding(
            category="SCA",
            class_name="known-vulnerable-dependency",
            path="build.gradle.kts",
            line=31,
            severity="CRITICAL",
            message="commons-text",
            description="Уязвимая зависимость",
            remediation="Обновите",
            group="org.apache.commons",
            artifact="commons-text",
            version="1.9",
            advisory_id="CVE-2022-42889",
            advisory_ids=["CVE-2022-42889", "GHSA-599f-7c49-w659"],
        ),
    ]


class AIServiceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.settings = load_settings({"seed_templates": False, "llm_provider": "fake"})

    def test_fake_provider_grounded(self):
        service = AIService(self.settings, provider=FakeProvider())
        result = service.analyze(_findings())
        self.assertEqual(result["provider"], "fake")
        self.assertTrue(result["validation"]["grounded"])
        self.assertEqual(result["validation"]["coverage"]["explained"], 2)
        self.assertEqual(len(result["findings"]), 2)
        self.assertEqual(result["overall_risk"], "CRITICAL")

    def test_invented_cve_is_rejected(self):
        response = {
            "summary": "Найдена уязвимость CVE-2099-0001 и файл src/main/kotlin/Evil.kt.",
            "overall_risk": "HIGH",
            "findings": [
                {
                    "finding_id": _findings()[0].fingerprint,
                    "explanation": "Проблема подтверждена CVE-2099-0001.",
                    "remediation": "Исправьте.",
                }
            ],
            "next_steps": ["Исправить"],
        }
        service = AIService(self.settings, provider=FakeProvider(response=response))
        result = service.analyze(_findings())


        self.assertEqual(result["provider"], "fallback")
        self.assertFalse(result["validation"]["grounded"])
        self.assertIn("CVE-2099-0001", result["validation"]["invented_advisories"])
        self.assertEqual(result["validation"]["coverage"]["explained"], 2)

    def test_invalid_schema_falls_back(self):
        response = {"summary": "", "findings": []}
        service = AIService(self.settings, provider=FakeProvider(response=response))
        result = service.analyze(_findings())
        self.assertEqual(result["provider"], "fallback")
        self.assertFalse(result["validation"]["schema_ok"])
        self.assertTrue(result["findings"])

    def test_unavailable_provider_falls_back(self):
        service = AIService(self.settings, provider=NullProvider())
        result = service.analyze(_findings())
        self.assertEqual(result["provider"], "fallback")
        self.assertTrue(result["validation"]["fallback"])
        self.assertIn("LLM", " ".join(result["validation"]["errors"]))

    def test_empty_findings(self):
        service = AIService(self.settings, provider=FakeProvider())
        result = service.analyze([])
        self.assertEqual(result["provider"], "none")
        self.assertEqual(result["overall_risk"], "LOW")

    def test_llm_intent_is_composed(self):
        provider = FakeProvider(
            response={
                "name": "Ночной аудит",
                "description": "Проверка по расписанию",
                "trigger": "schedule",
                "schedule_mode": "weekly",
                "schedule_time": "23:30",
                "schedule_weekday": "5",
                "checks": ["secrets", "sast"],
                "ai": True,
                "gate": "HIGH",
                "notify": "telegram",
                "report_formats": ["md", "json"],
            }
        )
        result = AIService(self.settings, provider=provider).generate_workflow("Ночной аудит")
        self.assertEqual(result["provider"], "fake")
        self.assertTrue(result["validation"]["valid"])
        types = [node["type"] for node in result["graph"]["nodes"]]
        self.assertIn("trigger.schedule", types)
        self.assertIn("scan.secrets", types)
        self.assertIn("scan.sast", types)
        self.assertIn("control.severity_gate", types)
        self.assertIn("notify.telegram", types)
        schedule = next(node for node in result["graph"]["nodes"] if node["type"] == "trigger.schedule")
        self.assertEqual(schedule["data"]["params"]["run_time"], "23:30")
        self.assertEqual(schedule["data"]["params"]["weekday"], "5")

    def test_heuristic_workflow_generation(self):
        service = AIService(self.settings, provider=NullProvider())
        result = service.generate_workflow(
            "Каждый день в 14:00 проверяй секреты и отправляй отчёт на почту"
        )
        self.assertTrue(result["validation"]["valid"])
        types = [node["type"] for node in result["graph"]["nodes"]]
        self.assertIn("trigger.schedule", types)
        self.assertIn("scan.secrets", types)
        self.assertIn("notify.webhook", types)
        schedule = next(node for node in result["graph"]["nodes"] if node["type"] == "trigger.schedule")
        self.assertEqual(schedule["data"]["params"]["run_time"], "14:00")
        self.assertEqual(schedule["data"]["params"]["mode"], "weekly")
        notify = next(node for node in result["graph"]["nodes"] if node["type"] == "notify.webhook")
        self.assertEqual(notify["data"]["params"]["url"], "local://inbox")

    def test_ast_with_condition_is_composed(self):
        provider = FakeProvider(
            response={
                "name": "CI condition",
                "trigger": {"type": "webhook"},
                "steps": [
                    {"type": "source.target", "params": {}},
                    {"type": "scan.sast", "params": {}},
                    {
                        "type": "condition",
                        "field": "findings.CRITICAL",
                        "operator": "gte",
                        "value": "1",
                        "then": [
                            {"type": "report.build", "params": {"formats": ["md", "json"]}},
                            {"type": "notify.telegram", "params": {}},
                        ],
                        "else": [{"type": "notify.webhook", "params": {}}],
                    },
                ],
            }
        )
        result = AIService(self.settings, provider=provider).generate_workflow("Проверь критичные")
        self.assertEqual(result["provider"], "fake")
        self.assertTrue(result["validation"]["valid"])
        types = [node["type"] for node in result["graph"]["nodes"]]
        self.assertIn("logic.if", types)
        self.assertIn("report.build", types)
        self.assertIn("notify.telegram", types)
        self.assertIn("notify.webhook", types)

    def test_ast_gate_inside_branch_is_valid(self):
        from app.ai.planner import compose_ast

        result = compose_ast(
            {
                "name": "gate branch",
                "trigger": {"type": "webhook"},
                "steps": [
                    {"type": "source.target", "params": {}},
                    {"type": "scan.sast", "params": {}},
                    {
                        "type": "condition",
                        "field": "findings.HIGH",
                        "operator": "gt",
                        "value": "0",
                        "then": [{"type": "control.severity_gate", "params": {}}],
                        "else": [],
                    },
                    {"type": "report.build", "params": {}},
                    {"type": "notify.telegram", "params": {}},
                ],
            }
        )
        self.assertTrue(result["validation"]["valid"])
        handles = {(edge["sourceHandle"]) for edge in result["graph"]["edges"]}
        self.assertIn("pass", handles)
        self.assertIn("fail", handles)

    def test_heuristic_ci_workflow(self):
        service = AIService(self.settings, provider=NullProvider())
        result = service.generate_workflow("В CI на каждый pull request проверяй код и блокируй при HIGH")
        types = [node["type"] for node in result["graph"]["nodes"]]
        self.assertIn("trigger.webhook", types)
        self.assertIn("control.severity_gate", types)


if __name__ == "__main__":
    unittest.main()
