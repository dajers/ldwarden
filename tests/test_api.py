from __future__ import annotations

import hashlib
import hmac
import io
import json
import sqlite3
import unittest
import zipfile

from app.db import close_db
from tests.helpers import make_app


def _secret_workflow() -> dict:
    return {
        "nodes": [
            {"id": "t", "type": "trigger.manual", "position": {"x": 0, "y": 0}, "data": {"params": {}}},
            {
                "id": "n",
                "type": "notify.send",
                "position": {"x": 300, "y": 0},
                "data": {
                    "params": {
                        "channel": "telegram",
                        "bot_token": "super-secret-token-123",
                        "chat_id": "42",
                        "dry_run": True,
                    }
                },
            },
        ],
        "edges": [{"id": "e1", "source": "t", "target": "n"}],
    }


def _webhook_workflow(secret: str = "") -> dict:
    return {
        "nodes": [
            {
                "id": "hook",
                "type": "trigger.webhook",
                "position": {"x": 0, "y": 0},
                "data": {"params": {"secret": secret}},
            },
            {
                "id": "notify",
                "type": "notify.send",
                "position": {"x": 300, "y": 0},
                "data": {"params": {"channel": "webhook", "url": "local://inbox"}},
            },
        ],
        "edges": [{"id": "e1", "source": "hook", "target": "notify"}],
    }


class ApiTests(unittest.TestCase):
    def setUp(self):
        self.app, self.settings = make_app()
        self.client = self.app.test_client()

    def tearDown(self):
        close_db()

    def test_health_nodes_and_templates(self):
        self.assertEqual(self.client.get("/api/health").status_code, 200)
        nodes = self.client.get("/api/nodes").get_json()
        self.assertGreaterEqual(len(nodes["items"]), 10)
        self.assertTrue(any(node["type"] == "scan.sast" for node in nodes["items"]))
        templates = self.client.get("/api/templates").get_json()
        self.assertEqual(templates["count"], 5)

    def test_secret_is_encrypted_and_masked(self):
        response = self.client.post("/api/workflows", json={"name": "Secrets", "graph": _secret_workflow()})
        self.assertEqual(response.status_code, 201)
        workflow = response.get_json()
        width = workflow["id"]
        serialized = json.dumps(workflow, ensure_ascii=False)
        self.assertNotIn("super-secret-token-123", serialized)
        self.assertNotIn("enc:v1:", serialized)
        params = workflow["graph"]["nodes"][1]["data"]["params"]
        self.assertEqual(params["bot_token"], "••••••")
        self.assertTrue(workflow["graph"]["nodes"][1]["data"]["secret_meta"]["bot_token"]["has_value"])

        with sqlite3.connect(self.settings.db_path) as connection:
            graph_text = connection.execute("select graph from workflowrow where id = ?", (width,)).fetchone()[0]
        self.assertNotIn("super-secret-token-123", graph_text)
        self.assertIn("enc:v1:", graph_text)


        updated = self.client.put(f"/api/workflows/{width}", json={"graph": workflow["graph"]})
        self.assertEqual(updated.status_code, 200)
        with sqlite3.connect(self.settings.db_path) as connection:
            graph_text2 = connection.execute("select graph from workflowrow where id = ?", (width,)).fetchone()[0]
        self.assertIn("enc:v1:", graph_text2)
        self.assertNotIn("super-secret-token-123", graph_text2)

    def test_full_audit_run_and_reports(self):
        response = self.client.post(
            "/api/workflows/tpl-full-audit/runs", json={"wait": True, "target": {"kind": "default"}}
        )
        self.assertEqual(response.status_code, 200)
        run = response.get_json()
        self.assertEqual(run["status"], "success")
        self.assertEqual(run["summary"]["findings"]["total"], 15)
        run_id = run["id"]

        events = self.client.get(f"/api/runs/{run_id}/events").get_json()
        self.assertGreater(len(events["items"]), 20)
        types = [event["type"] for event in events["items"]]
        self.assertIn("run.finished", types)
        self.assertIn("finding", types)

        findings = self.client.get(f"/api/runs/{run_id}/findings").get_json()
        self.assertEqual(findings["count"], 15)
        blob = json.dumps(findings, ensure_ascii=False)
        self.assertNotIn("cg26_parts_", blob)

        report = self.client.get(f"/api/runs/{run_id}/report?format=md")
        self.assertEqual(report.status_code, 200)
        self.assertIn("Отчёт о проверке", report.data.decode("utf-8"))
        submission = self.client.get(f"/api/runs/{run_id}/report?format=json").get_json()
        self.assertEqual(len(submission["findings"]), 15)
        sca = [item for item in submission["findings"] if item["category"] == "SCA"]
        self.assertTrue(all("advisoryId" in item for item in sca))
        self.assertEqual(self.client.get(f"/api/runs/{run_id}/report?format=sarif").status_code, 200)
        ai = self.client.get(f"/api/runs/{run_id}/ai").get_json()
        self.assertEqual(ai["provider"], "fake")
        self.assertTrue(ai["validation"]["grounded"])
        inbox = self.client.get("/api/dev/inbox").get_json()
        self.assertEqual(len(inbox["items"]), 1)

    def test_ci_gate_fails_on_critical(self):
        response = self.client.post("/api/ci/run", json={"workflow_id": "tpl-ci-gate", "wait": True})
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["status"], "failed")
        self.assertEqual(data["exit_code"], 1)
        self.assertFalse(data["gate"]["passed"])
        status = self.client.get(f"/api/ci/status/{data['run_id']}").get_json()
        self.assertEqual(status["exit_code"], 1)

    def test_upload_zip_and_scan(self):
        payload = io.BytesIO()
        with zipfile.ZipFile(payload, "w") as archive:
            archive.writestr(
                "project/build.gradle.kts",
                'dependencies { implementation("org.apache.commons:commons-text:1.9") }',
            )
            archive.writestr(
                "project/src/main/kotlin/App.kt",
                'val password = "SuperSecret12345"\n',
            )
            archive.writestr("project/__MACOSX/._junk", "x")
        payload.seek(0)
        response = self.client.post(
            "/api/sources",
            data={"file": (payload, "project.zip"), "name": "uploaded"},
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 201)
        source = response.get_json()
        self.assertEqual(source["files"], 2)

        run = self.client.post(
            "/api/workflows/tpl-full-audit/runs",
            json={"wait": True, "target": {"kind": "source", "id": source["id"]}},
        ).get_json()
        self.assertEqual(run["status"], "success")
        findings = self.client.get(f"/api/runs/{run['id']}/findings").get_json()["items"]
        self.assertGreaterEqual(len(findings), 2)
        self.assertTrue(any(item["class"] == "password" for item in findings))
        self.assertTrue(any(item["category"] == "SCA" for item in findings))

    def test_zip_traversal_is_rejected(self):
        payload = io.BytesIO()
        with zipfile.ZipFile(payload, "w") as archive:
            archive.writestr("../evil.txt", "x")
        payload.seek(0)
        response = self.client.post(
            "/api/sources",
            data={"file": (payload, "evil.zip")},
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 400)
        self.assertFalse((self.settings.data_dir / "evil.txt").exists())

    def test_forbidden_target(self):
        response = self.client.post(
            "/api/workflows/tpl-full-audit/runs",
            json={"wait": True, "target": {"kind": "path", "path": "/etc"}},
        )
        self.assertEqual(response.status_code, 403)

    def test_invalid_graph(self):
        draft = self.client.post(
            "/api/workflows/validate",
            json={"graph": {"nodes": [{"id": "x", "type": "nope"}], "edges": []}},
        ).get_json()
        self.assertFalse(draft["valid"])
        created = self.client.post("/api/workflows", json={"name": "bad", "graph": {"nodes": [], "edges": []}})
        self.assertEqual(created.status_code, 400)

    def test_webhook_with_hmac(self):
        secret = "hook-secret"
        workflow = self.client.post("/api/workflows", json={"name": "hook", "graph": _webhook_workflow(secret)})
        self.assertEqual(workflow.status_code, 201)
        workflow_id = workflow.get_json()["id"]
        body = json.dumps({"ref": "refs/heads/main"}, ensure_ascii=False).encode()

        unsigned = self.client.post(f"/api/hooks/{workflow_id}", data=body, content_type="application/json")
        self.assertEqual(unsigned.status_code, 401)

        signature = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
        signed = self.client.post(
            f"/api/hooks/{workflow_id}?wait=1",
            data=body,
            content_type="application/json",
            headers={"X-LDWarden-Signature": signature},
        )
        self.assertEqual(signed.status_code, 200)
        self.assertEqual(signed.get_json()["status"], "success")

    def test_ask_generate_workflow(self):
        response = self.client.post(
            "/api/ai/workflows/generate",
            json={"prompt": "Каждый день в 14:00 проверяй секреты и отправляй отчёт на почту"},
        )
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertTrue(data["validation"]["valid"])
        types = [node["type"] for node in data["graph"]["nodes"]]
        self.assertIn("trigger.schedule", types)
        self.assertIn("scan.secrets", types)
        self.assertIn("notify.send", types)


class AuthTests(unittest.TestCase):
    def setUp(self):
        self.app, _settings = make_app(api_token="top-secret", ci_token="ci-secret")
        self.client = self.app.test_client()

    def tearDown(self):
        close_db()

    def test_api_token(self):
        self.assertEqual(self.client.get("/api/health").status_code, 200)
        self.assertEqual(self.client.get("/api/nodes").status_code, 401)
        self.assertEqual(
            self.client.get("/api/nodes", headers={"Authorization": "Bearer top-secret"}).status_code,
            200,
        )
        self.assertEqual(
            self.client.get("/api/nodes", headers={"X-API-Token": "top-secret"}).status_code,
            200,
        )

    def test_ci_token(self):
        self.assertEqual(
            self.client.post("/api/ci/run", json={"workflow_id": "tpl-quick-smoke"}).status_code,
            401,
        )
        response = self.client.post(
            "/api/ci/run",
            json={"workflow_id": "tpl-quick-smoke", "wait": True},
            headers={"X-CI-Token": "ci-secret"},
        )
        self.assertEqual(response.status_code, 200)


if __name__ == "__main__":
    unittest.main()


class TelegramEnvFallbackTests(unittest.TestCase):
    def setUp(self):
        self.app, self.settings = make_app(
            telegram_bot_token="123456:telegram-token",
            telegram_chat_id="987654321",
        )
        self.client = self.app.test_client()

    def tearDown(self):
        close_db()

    def test_env_credentials_are_used_when_node_params_empty(self):
        graph = {
            "nodes": [
                {"id": "t", "type": "trigger.manual", "position": {"x": 0, "y": 0}, "data": {}},
                {
                    "id": "notify",
                    "type": "notify.send",
                    "position": {"x": 250, "y": 0},
                    "data": {
                        "params": {
                            "channel": "telegram",
                            "dry_run": True,
                        }
                    },
                },
            ],
            "edges": [{"id": "e1", "source": "t", "target": "notify"}],
        }
        created = self.client.post(
            "/api/workflows", json={"name": "Telegram env", "graph": graph}
        )
        self.assertEqual(created.status_code, 201)
        run = self.client.post(
            f"/api/workflows/{created.get_json()['id']}/runs", json={"wait": True}
        ).get_json()
        notification = run["summary"]["notification"]
        self.assertEqual(notification["channel"], "telegram")
        self.assertEqual(notification["target"], "chat:987654321")
        self.assertEqual(notification["status"], "skipped")
        self.assertIn("Dry-run", notification["message"])
