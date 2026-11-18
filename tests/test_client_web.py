import unittest

from ftm.agent import reconcile
from ftm.control import execute
from ftm.web_auth import make_config
from tests import test_client_service

try:
    from fastapi.testclient import TestClient
    from ftm.web import create_app
except ImportError:
    TestClient = None


@unittest.skipUnless(TestClient, "Install web development dependencies")
class ClientHttpSafetyTests(unittest.TestCase):
    def setUp(self):
        test_client_service.ClientDisclosureTests.setUp(self)
        config = dict(make_config("admin", "synthetic http client phrase"), version=2,
                      public_origin="https://8.8.8.8", secure_cookie=True)
        rpc = lambda operation, args: execute({"v": 1, "op": operation, "args": args or {}},
                                             uid=456, api_uid=456, store=self.store, agent=self.agent)
        self.client = TestClient(create_app(config, rpc=rpc), base_url="https://8.8.8.8")
        self.admin_prefix = "/a/" + config["panel_slug"] + "/api"
        self.addCleanup(self.client.close)
        self.base = "/api/client/v1/"

    def test_native_bearer_pending_config_conditional_and_revoke_boundary(self):
        login = self.client.post(self.admin_prefix + "/auth/login", json={"username": "admin", "password": "synthetic http client phrase"}, headers={"Origin": "https://8.8.8.8"})
        self.assertEqual(login.status_code, 200)
        cookie = self.client.cookies.get("ftm_session")
        self.assertEqual(self.client.get(self.base + "subscription", headers={"Cookie": "ftm_session=" + cookie}).status_code, 401)
        enrolled = self.client.post(self.base + "enroll", json=self.args, headers={"Authorization": "Bearer " + self.link})
        self.assertEqual(enrolled.status_code, 202)
        device = {"Authorization": "Bearer " + self.token}
        self.assertEqual(self.client.get(self.base + "subscription", headers={"Authorization": "Bearer " + self.link}).status_code, 401)
        pending = self.client.get(self.base + "subscription", headers=device)
        self.assertEqual(pending.status_code, 202)
        self.assertNotIn("wireguard", pending.text)
        reconcile(self.store, self.agent)
        config = self.client.get(self.base + "subscription", headers=device)
        self.assertEqual(config.status_code, 200)
        etag = config.headers["etag"]
        cached = self.client.get(self.base + "subscription", headers={**device, "If-None-Match": "W/" + etag})
        self.assertEqual(cached.status_code, 304)
        self.assertEqual(cached.content, b"")
        self.store.revoke_device(enrolled.json()["device_id"])
        revoked = self.client.get(self.base + "subscription", headers={**device, "If-None-Match": etag})
        self.assertEqual(revoked.status_code, 403)
        self.assertEqual(revoked.json()["error"]["code"], "device_disabled")

    def test_private_key_input_and_token_query_are_rejected_without_echo(self):
        marker = "synthetic-sensitive-marker"
        response = self.client.post(self.base + "enroll", json={**self.args, "private_key": marker}, headers={"Authorization": "Bearer " + self.link})
        self.assertEqual(response.status_code, 422)
        self.assertNotIn(marker, response.text)
        response = self.client.get(self.base + "status?token=" + marker)
        self.assertEqual(response.status_code, 422)
        self.assertNotIn(marker, response.text)
        response = self.client.post(self.base + "enroll", content="x" * 17000)
        self.assertEqual(response.status_code, 413)
        self.assertIn("correlation_id", response.json()["error"])

    def test_failed_enrollment_attempts_are_throttled_before_root_work(self):
        for _ in range(10):
            response = self.client.post(self.base + "enroll", json=self.args, headers={"Authorization": "Bearer ftmu1_" + "x" * 43})
            self.assertEqual(response.status_code, 401)
        response = self.client.post(self.base + "enroll", json=self.args, headers={"Authorization": "Bearer ftmu1_" + "x" * 43})
        self.assertEqual(response.status_code, 429)
        self.assertEqual(response.headers["retry-after"], "60")

    def test_routing_requires_capability_device_auth_and_admin_csrf(self):
        prefix=self.admin_prefix
        self.assertEqual(self.client.get(prefix+"/routing").status_code,401)
        login=self.client.post(prefix+"/auth/login",json={"username":"admin","password":"synthetic http client phrase"},headers={"Origin":"https://8.8.8.8"})
        self.assertEqual(login.status_code,200)
        policy=self.client.get(prefix+"/routing").json()
        body={"expected_revision":policy["revision"],"policy":policy["policy"]}
        self.assertEqual(self.client.post(prefix+"/routing",json=body).status_code,403)
        headers={"Origin":"https://8.8.8.8","X-CSRF-Token":login.json()["csrf"]}
        self.assertEqual(self.client.post(prefix+"/routing",json=body,headers=headers).status_code,200)
        self.assertEqual(self.client.post(prefix+"/routing",json=body,headers=headers).status_code,409)
        self.service.enroll(self.link,self.args);reconcile(self.store,self.agent)
        bearer={"Authorization":"Bearer "+self.token}
        self.assertEqual(self.client.get(self.base+"routing",headers=bearer).status_code,422)
        delivered=self.client.get(self.base+"routing",headers={**bearer,"X-FreeTurn-Capability":"routing-bundle-v1"})
        self.assertEqual(delivered.status_code,200)
        self.assertEqual(delivered.json()["revision"],1)
        self.store.revoke_device(self.service.status(self.token)["device_id"])
        self.assertEqual(self.client.get(self.base+"routing",headers={**bearer,"X-FreeTurn-Capability":"routing-bundle-v1"}).status_code,403)
