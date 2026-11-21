from __future__ import annotations

import base64
import json
import unittest
from unittest.mock import patch

from app.db import close_db
from app.services.library import LibraryError, PresetLibrary
from tests.helpers import make_app, make_settings


class LibraryTests(unittest.TestCase):
    def setUp(self):
        self.app, self.settings = make_app(library_repo="", library_token="")
        self.client = self.app.test_client()

    def tearDown(self):
        close_db()

    def test_not_configured(self):
        service = PresetLibrary(self.settings)
        self.assertFalse(service.configured)
        self.assertFalse(service.can_publish)
        self.assertEqual(service.list_presets()["items"], [])

    def test_repo_parser(self):
        self.assertEqual(PresetLibrary._parse_repo("owner/repo"), "owner/repo")
        self.assertEqual(PresetLibrary._parse_repo("https://github.com/owner/repo.git"), "owner/repo")
        with self.assertRaises(LibraryError):
            PresetLibrary._parse_repo("invalid")

    def test_api_library_is_optional(self):
        response = self.client.get("/api/library")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertFalse(data["configured"])
        self.assertEqual(data["items"], [])
        self.assertEqual(data["nodes"], [])

    def test_publish_requires_configuration(self):
        response = self.client.post(
            "/api/library/publish",
            json={
                "graph": {
                    "nodes": [{"id": "t", "type": "trigger.manual", "position": {"x": 0, "y": 0}, "data": {}}],
                    "edges": [],
                },
                "name": "test",
            },
        )
        self.assertEqual(response.status_code, 502)

    def test_list_uses_cache_and_force_refreshes(self):
        settings = make_settings(library_repo="owner/repo", library_token="")
        service = PresetLibrary(settings)
        calls = {"directory": 0}

        def directory():
            calls["directory"] += 1
            return [{"type": "file", "name": "one.json"}]

        def download(_entry):
            return {"id": "one", "name": "One", "graph": {"nodes": [], "edges": []}}

        service._directory = directory
        service._download = download
        first = service.list_presets()
        second = service.list_presets()
        self.assertEqual(calls["directory"], 1)
        self.assertFalse(first["cached"])
        self.assertTrue(second["cached"])
        service.list_presets(force=True)
        self.assertEqual(calls["directory"], 2)

    def test_publish_builds_github_preset(self):
        settings = make_settings(
            library_repo="owner/repo",
            library_branch="main",
            library_path="presets",
            library_token="ghp_test",
        )
        service = PresetLibrary(settings)
        response = type("Response", (), {"json": lambda self: {"content": {"html_url": "https://example.test/preset"}, "commit": {"sha": "abc"}}})()

        def fake_request(method, path, **kwargs):
            if method == "GET":
                raise LibraryError("GitHub API 404: not found")
            return response

        with patch.object(service, "_request", side_effect=fake_request):
            result = service.publish(
                {"nodes": [{"id": "t", "type": "trigger.manual", "data": {"params": {}}}], "edges": []},
                name="My preset",
                description="demo",
                tags=["ci"],
            )
        self.assertTrue(result["path"].endswith(".json"))
        self.assertEqual(result["preset"]["format"], "ldwarden-preset/v1")
        self.assertEqual(result["preset"]["tags"], ["ci"])

    def test_notification_nodes_are_separate(self):
        items = self.client.get("/api/nodes?category=notification").get_json()["items"]
        types = {item["type"] for item in items}
        self.assertTrue({"notify.telegram", "notify.webhook"} <= types)


class LibraryNodesTests(unittest.TestCase):
    def setUp(self):
        self.settings = make_settings(
            library_repo="owner/repo", library_branch="main", library_path="presets", library_token="ghp_test"
        )
        self.service = PresetLibrary(self.settings)

    def test_nodes_path_is_sibling_of_presets(self):
        self.assertEqual(self.service.nodes_path, "nodes")
        self.settings.library_path = "team/presets"
        self.assertEqual(PresetLibrary(self.settings).nodes_path, "team/nodes")

    def test_list_nodes_reads_node_files(self):
        definition = {
            "id": "custom-1",
            "name": "Проверка",
            "kind": "http",
            "version": 2,
            "description": "demo",
            "icon": "shield",
        }
        self.service._directory = lambda path=None: [
            {"type": "file", "name": "custom-1.json", "path": "nodes/custom-1.json", "html_url": "https://x"}
        ]
        self.service._read_json = lambda path: dict(definition)
        data = self.service.list_nodes(force=True)
        self.assertEqual(data["count"] if "count" in data else len(data["items"]), 1)
        self.assertEqual(data["items"][0]["id"], "custom-1")
        self.assertEqual(data["items"][0]["kind"], "http")
        self.assertEqual(data["items"][0]["version"], 2)

    def test_publish_node_writes_node_file(self):
        calls = []
        self.service._write_json = lambda path, document, message: calls.append((path, document, message)) or "https://x"
        result = self.service.publish_node({"id": "custom-1", "name": "Проверка", "version": 3})
        self.assertEqual(calls[0][0], "nodes/custom-1.json")
        self.assertEqual(calls[0][1]["format"], "ldwarden-node/v1")
        self.assertEqual(result["version"], 3)
        self.assertEqual(result["url"], "https://x")
