import secrets
import unittest
import uuid

from ftm.client_service import ClientService
from ftm.client_protocol import ClientFault
from ftm.credentials import Credentials, _digest
from ftm.agent import reconcile
from ftm.managed import adopt_legacy
from tests import test_managed
from tests.test_store import key


class ClientDisclosureTests(unittest.TestCase):
    def setUp(self):
        test_managed.ManagedAdoptionTests.setUp(self)
        adopt_legacy(self.store, self.agent)
        self.user = self.store.create_user("Client API verification", 2)
        self.credentials = Credentials(self.store)
        self.link = self.credentials.issue_subscription(self.user["id"])["token"]
        self.token = "ftmd1_" + secrets.token_urlsafe(32)
        self.args = {"name": "Phone", "platform": "android", "public_key": key(85), "client_id": secrets.token_hex(16),
                     "device_token_hash": _digest(self.token, "device"), "request_id": str(uuid.uuid4())}
        self.service = ClientService(self.store, self.agent)

    def test_pending_is_redacted_and_scopes_cannot_export_config(self):
        result = self.service.enroll(self.link, self.args)
        self.assertFalse(self.service.subscription(self.token)["ready"])
        self.assertFalse(self.service.status(self.token)["ready"])
        for token in (self.link, "invalid"):
            with self.assertRaises(ClientFault):
                self.service.subscription(token)
        self.assertEqual(result["state"], "pending")
        self.assertNotIn("preshared_key", str(result))

    def test_own_manifest_stable_etag_and_revocation_precedes_conditional_match(self):
        self.service.enroll(self.link, self.args)
        reconcile(self.store, self.agent)
        value = self.service.subscription(self.token)
        manifest = value["config"]
        self.assertNotIn("private_key", str(manifest))
        self.assertEqual(manifest["wireguard"]["client_public_key"], self.args["public_key"])
        self.assertEqual(manifest["freeturn"]["cid"], self.args["client_id"])
        self.assertNotIn(self.state["clients"]["iphone"]["preshared_key"], str(manifest))
        self.credentials.issue_subscription(self.user["id"])
        self.assertEqual(self.service.subscription(self.token)["etag"], value["etag"])
        self.assertTrue(self.service.subscription(self.token, value["etag"])["not_modified"])
        self.store.revoke_device(manifest["device_id"])
        with self.assertRaises(ClientFault):
            self.service.subscription(self.token, value["etag"])

    def test_metadata_active_without_matching_root_ownership_does_not_export(self):
        result = self.service.enroll(self.link, self.args)
        reconcile(self.store, self.agent)
        import json
        registry = self.agent._registry()
        registry["devices"].pop(result["device_id"])
        self.agent.registry.write_text(json.dumps(registry))
        with self.assertRaises(ClientFault):
            self.service.subscription(self.token)
