import unittest

try:
    from fastapi.testclient import TestClient
    from ftm.web import create_app
except ImportError:
    create_app = None
from ftm.web_auth import make_config


@unittest.skipUnless(create_app, "Install web development dependencies")
class WebBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.config = make_config("admin", "synthetic web admin phrase")

    def test_login_csrf_origin_and_logout_protect_mutations(self):
        calls = []
        def rpc(operation, args):
            calls.append(operation)
            return [] if operation.endswith(".list") else {"id": "synthetic"}
        app = create_app(self.config, rpc=rpc)
        base = "/a/" + self.config["panel_slug"] + "/api"
        with TestClient(app, base_url="http://localhost") as client:
            self.assertEqual(client.get(base + "/users").status_code, 401)
            self.assertEqual(client.post(base + "/users", json={"name": "Family"}).status_code, 401)
            login = client.post(base + "/auth/login", json={"username": "admin", "password": "synthetic web admin phrase"}, headers={"Origin": "http://localhost"})
            self.assertEqual(login.status_code, 200)
            csrf = login.json()["csrf"]
            self.assertEqual(client.post(base + "/users", json={"name": "Family"}, headers={"Origin": "http://localhost"}).status_code, 403)
            self.assertEqual(client.post(base + "/users", json={"name": "Family"}, headers={"Origin": "http://untrusted.example", "X-CSRF-Token": csrf}).status_code, 403)
            self.assertNotIn("users.create", calls)
            headers = {"Origin": "http://localhost", "X-CSRF-Token": csrf}
            self.assertEqual(client.post(base + "/users", json={"name": "Family"}, headers=headers).status_code, 200)
            self.assertIn("users.create", calls)
            self.assertEqual(client.post(base + "/auth/logout", headers=headers).status_code, 200)
            self.assertEqual(client.get(base + "/users").status_code, 401)

    def test_invalid_or_oversized_input_is_rejected_without_echoing_password(self):
        app = create_app(self.config, rpc=lambda *args: {})
        base = "/a/" + self.config["panel_slug"] + "/api"
        with TestClient(app, base_url="http://localhost") as client:
            response = client.post(base + "/auth/login", json={"username": "admin", "password": "synthetic secret", "extra": True})
            self.assertEqual(response.status_code, 422)
            self.assertNotIn("synthetic secret", response.text)
            response = client.post(base + "/auth/login", content="x" * 17000)
            self.assertEqual(response.status_code, 413)
            self.assertEqual(client.get("/docs").status_code, 404)
            self.assertEqual(client.get("/openapi.json").status_code, 404)
