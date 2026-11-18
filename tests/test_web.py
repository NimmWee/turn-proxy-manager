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

    def test_dashboard_reads_and_subscription_revoke_respect_session_boundaries(self):
        config = dict(self.config, version=2, public_origin="https://8.8.8.8", secure_cookie=True)
        calls = []

        def rpc(operation, args):
            calls.append((operation, args))
            return {"ok": True}

        base = "/a/" + config["panel_slug"] + "/api"
        revoke = base + "/users/11111111-1111-4111-8111-111111111111/subscription-revoke"
        payload = {"expected_version": 2, "password": "synthetic web admin phrase"}
        origin = {"Origin": config["public_origin"]}
        with TestClient(create_app(config, rpc=rpc), base_url=config["public_origin"]) as client:
            for path in ("/metrics/history", "/subscriptions", "/settings"):
                self.assertEqual(client.get(base + path).status_code, 401)
            self.assertEqual(client.post(revoke, json=payload, headers=origin).status_code, 401)
            self.assertEqual(calls, [])
            response = client.post(base + "/auth/login", headers=origin,
                                   json={"username": "admin", "password": payload["password"]})
            self.assertEqual(response.status_code, 200)
            headers = {**origin, "X-CSRF-Token": response.json()["csrf"]}
            self.assertEqual(client.get(base + "/metrics/history?hours=6").status_code, 200)
            self.assertEqual(client.get(base + "/subscriptions?page=2&search=Family").status_code, 200)
            self.assertEqual(client.get(base + "/settings").status_code, 200)
            self.assertEqual(client.post(revoke, json=payload, headers=origin).status_code, 403)
            self.assertEqual(client.post(revoke, json=payload, headers={**headers, "Origin": "https://wrong.invalid"}).status_code, 403)
            self.assertEqual(client.post(revoke, json={**payload, "expected_version": True}, headers=headers).status_code, 422)
            self.assertEqual(calls, [("metrics.history", {"hours": 6}), ("subscriptions.list", {"page": 2, "search": "Family"})])
            self.assertEqual(client.post(revoke, json=payload, headers=headers).status_code, 200)
            self.assertEqual(calls[-1][0], "admin.subscription_revoke")

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

    def test_public_https_cookie_origin_and_host_boundary(self):
        config = dict(self.config, version=2, public_origin="https://8.8.8.8", secure_cookie=True)
        app = create_app(config, rpc=lambda *args: [])
        base = "/a/" + config["panel_slug"] + "/api"
        payload = {"username": "admin", "password": "synthetic web admin phrase"}
        with TestClient(app, base_url="http://localhost") as internal:
            self.assertEqual(internal.post(base + "/auth/login", json=payload, headers={"Origin": config["public_origin"]}).status_code, 403)
        with TestClient(app, base_url="https://8.8.8.8") as client:
            self.assertEqual(client.post(base + "/auth/login", json=payload, headers={"Origin": "http://8.8.8.8"}).status_code, 403)
            login = client.post(base + "/auth/login", json=payload, headers={"Origin": config["public_origin"]})
            self.assertEqual(login.status_code, 200)
            self.assertIn("Secure", login.headers["set-cookie"])
            self.assertEqual(client.get(base + "/users").status_code, 200)
            csrf = login.json()["csrf"]
            self.assertEqual(client.post(base + "/users", json={"name": "Family"}, headers={"Origin": "http://8.8.8.8", "X-CSRF-Token": csrf}).status_code, 403)
            self.assertEqual(client.get(base + "/users", headers={"Host": "untrusted.example"}).status_code, 400)
            self.assertEqual(client.post(base + "/auth/logout", headers={"Origin": config["public_origin"], "X-CSRF-Token": csrf}).status_code, 200)
            self.assertEqual(client.get(base + "/users").status_code, 401)
