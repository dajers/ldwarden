from __future__ import annotations

import unittest

from app.db import close_db
from tests.helpers import make_app


class FrontendServingTests(unittest.TestCase):
    def setUp(self):
        self.app, self.settings = make_app()
        self.client = self.app.test_client()

    def tearDown(self):
        close_db()

    def test_index_is_served(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("text/html", response.content_type)
        self.assertIn("ldwarden", response.data.decode("utf-8").lower())
        self.assertIn("js/app.js", response.data.decode("utf-8"))
        self.assertIn("workspaceTabs", response.data.decode("utf-8"))
        self.assertIn("libraryView", response.data.decode("utf-8"))
        self.assertIn("ciView", response.data.decode("utf-8"))
        self.assertIn("generatorView", response.data.decode("utf-8"))
        response.close()

    def test_static_assets_are_served(self):
        for path in ("/styles.css", "/js/api.js", "/js/app.js", "/assets/palm.jpg"):
            response = self.client.get(path)
            self.assertEqual(response.status_code, 200, path)
            self.assertGreater(len(response.data), 0, path)
            response.close()

    def test_api_still_works_under_frontend_root(self):
        response = self.client.get("/api/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["status"], "ok")
        response.close()


if __name__ == "__main__":
    unittest.main()
