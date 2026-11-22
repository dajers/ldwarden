from __future__ import annotations

import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from app.db import close_db
from tests.helpers import make_app


class _JsonHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps(
            {"items": [{"id": "h1", "level": "HIGH", "message": "No HSTS", "file": "src/App.kt", "line": 3}]}
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class CustomNodeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _JsonHandler)
        cls.port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def setUp(self):
        self.app, self.settings = make_app()
        self.client = self.app.test_client()

    def tearDown(self):
        close_db()

    def _http_node(self):
        return self.client.post(
            "/api/custom-nodes",
            json={
                "name": "Проверить заголовки",
                "kind": "http",
                "params": [{"name": "url", "type": "string", "label": "URL", "required": True}],
                "runtime": {
                    "method": "GET",
                    "url": "{{params.url}}",
                    "findings": {
                        "from": "items",
                        "category": "CUSTOM",
                        "map": {"severity": "level", "title": "message", "path": "file", "line": "line", "rule": "id"},
                    },
                },
            },
        ).get_json()

    def test_network_defaults_and_update(self):
        rules = self.client.get("/api/settings/network").get_json()
        self.assertIn("api.github.com", rules["allow_hosts"])
        updated = self.client.put(
            "/api/settings/network", json={"allow_hosts": ["example.com", "*.test.io"], "timeout": 5}
        ).get_json()
        self.assertEqual(updated["allow_hosts"], ["example.com", "*.test.io"])
        self.assertEqual(updated["timeout"], 5)

    def test_create_validate_and_version(self):
        node = self._http_node()
        self.assertTrue(node["id"].startswith("custom-"))
        self.assertEqual(node["version"], 1)
        listed = self.client.get("/api/custom-nodes").get_json()["items"]
        self.assertEqual(len(listed), 1)
        updated = self.client.put(
            f"/api/custom-nodes/{node['id']}",
            json={**node, "name": "Новое имя"},
        ).get_json()
        self.assertEqual(updated["version"], 2)
        bad = self.client.post("/api/custom-nodes", json={"name": "x", "kind": "http", "runtime": {"url": ""}})
        self.assertEqual(bad.status_code, 400)

    def test_http_node_test_and_run(self):
        node = self._http_node()
        url = f"http://127.0.0.1:{self.port}/checks"
        result = self.client.post(f"/api/custom-nodes/{node['id']}/test", json={"params": {"url": url}}).get_json()
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["findings_count"], 1)
        graph = {
            "nodes": [
                {"id": "t", "type": "trigger.manual", "position": {"x": 0, "y": 0}, "data": {}},
                {"id": "c", "type": node["id"], "position": {"x": 250, "y": 0}, "data": {"params": {"url": url}}},
            ],
            "edges": [{"id": "e1", "source": "t", "target": "c"}],
        }
        workflow = self.client.post("/api/workflows", json={"name": "custom", "graph": graph}).get_json()
        run = self.client.post(f"/api/workflows/{workflow['id']}/runs", json={"wait": True}).get_json()
        self.assertEqual(run["status"], "success")
        self.assertEqual(run["summary"]["findings"]["by_category"], {"CUSTOM": 1})

    def test_import_updates_existing(self):
        node = self._http_node()
        imported = self.client.post(
            "/api/custom-nodes/import",
            json={**node, "version": 1, "name": "Импорт"},
        ).get_json()
        self.assertEqual(imported["name"], "Импорт")
        self.assertGreater(imported["version"], 1)

    def test_ai_node_publishes_run_summary(self):
        node = self.client.post(
            "/api/custom-nodes",
            json={
                "name": "AI summary",
                "kind": "ai",
                "inputs": [{"id": "in", "kind": "exec"}],
                "outputs": [{"id": "out", "kind": "exec"}],
                "runtime": {
                    "provider": "auto",
                    "prompt": "Суммируй находки",
                    "max_tokens": 128,
                    "findings": {"enabled": False},
                },
            },
        ).get_json()
        graph = {
            "nodes": [
                {"id": "t", "type": "trigger.manual", "position": {"x": 0, "y": 0}, "data": {}},
                {"id": "c", "type": node["id"], "position": {"x": 250, "y": 0}, "data": {"params": {}}},
            ],
            "edges": [{"id": "e1", "source": "t", "target": "c"}],
        }
        workflow = self.client.post("/api/workflows", json={"name": "custom ai", "graph": graph}).get_json()
        run = self.client.post(f"/api/workflows/{workflow['id']}/runs", json={"wait": True}).get_json()
        self.assertEqual(run["status"], "success")
        self.assertIn("summary", run["ai"])
        self.assertTrue(run["ai"]["summary"])

    def test_composite_without_inner_bindings_uses_boundaries(self):
        composite = self.client.post(
            "/api/custom-nodes",
            json={
                "name": "Без привязок",
                "kind": "composite",
                "inputs": [{"id": "in", "kind": "exec"}],
                "outputs": [{"id": "out", "kind": "exec"}],
                "runtime": {
                    "graph": {
                        "nodes": [
                            {"id": "n1", "type": "notify.webhook", "position": {"x": 0, "y": 0},
                             "data": {"params": {"url": "local://inbox"}}}
                        ],
                        "edges": [],
                    }
                },
            },
        ).get_json()
        graph = {
            "nodes": [
                {"id": "t", "type": "trigger.manual", "position": {"x": 0, "y": 0}, "data": {}},
                {"id": "c", "type": composite["id"], "position": {"x": 250, "y": 0}, "data": {}},
            ],
            "edges": [{"id": "e1", "source": "t", "target": "c", "targetHandle": "in"}],
        }
        workflow = self.client.post("/api/workflows", json={"name": "composite auto", "graph": graph}).get_json()
        run = self.client.post(f"/api/workflows/{workflow['id']}/runs", json={"wait": True}).get_json()
        self.assertEqual(run["status"], "success")
        self.assertIn("c/n1", run["summary"]["nodes"])

    def test_composite_node_expands(self):
        composite = self.client.post(
            "/api/custom-nodes",
            json={
                "name": "Уведомление внутри",
                "kind": "composite",
                "inputs": [{"id": "in", "kind": "exec", "inner": {"node": "n1", "port": "in"}}],
                "outputs": [{"id": "out", "kind": "exec", "inner": {"node": "n1", "port": "out"}}],
                "runtime": {
                    "graph": {
                        "nodes": [
                            {"id": "n1", "type": "notify.webhook", "position": {"x": 0, "y": 0},
                             "data": {"params": {"url": "local://inbox"}}}
                        ],
                        "edges": [],
                    }
                },
            },
        ).get_json()
        graph = {
            "nodes": [
                {"id": "t", "type": "trigger.manual", "position": {"x": 0, "y": 0}, "data": {}},
                {"id": "c", "type": composite["id"], "position": {"x": 250, "y": 0}, "data": {}},
            ],
            "edges": [{"id": "e1", "source": "t", "target": "c", "targetHandle": "in"}],
        }
        workflow = self.client.post("/api/workflows", json={"name": "composite", "graph": graph}).get_json()
        run = self.client.post(f"/api/workflows/{workflow['id']}/runs", json={"wait": True}).get_json()
        self.assertEqual(run["status"], "success")
        self.assertIn("c/n1", run["summary"]["nodes"])


if __name__ == "__main__":
    unittest.main()
