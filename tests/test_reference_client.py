import copy
import unittest
from unittest.mock import patch

from ftm.agent import reconcile
from ftm.reference_client import ReferenceClient, ClientSyncError
from ftm.profile_codec import decode
from tests import test_client_service
from tests.test_store import key


class LastGoodConfigSafetyTests(unittest.TestCase):
    def setUp(self):
        test_client_service.ClientDisclosureTests.setUp(self)
        self.service.enroll(self.link, self.args)
        reconcile(self.store, self.agent)
        self.value = self.service.subscription(self.token)
        self.client = ReferenceClient("https://" + self.state["endpoint"], private_key=key(86), public_key=self.args["public_key"],
                                      device_token=self.token, client_id=self.args["client_id"])

    def test_local_private_key_assembly_and_bad_update_keep_the_last_good_config(self):
        with patch.object(self.client, "_request", return_value=(200, self.value["config"], self.value["etag"])):
            self.assertTrue(self.client.refresh())
        share = decode(self.client.last_share)
        self.assertIn(key(86), share["wg"])
        self.assertNotIn(key(86), str(self.value["config"]))
        before = self.client.last_share
        wrong = copy.deepcopy(self.value["config"])
        wrong["wireguard"]["client_public_key"] = key(87)
        with patch.object(self.client, "_request", return_value=(200, wrong, '"invalid"')):
            with self.assertRaises(ClientSyncError):
                self.client.refresh()
        self.assertEqual(self.client.last_share, before)
        self.assertEqual(self.client.state, "DEGRADED")
        with patch.object(self.client, "_request", side_effect=ClientSyncError(403)):
            with self.assertRaises(ClientSyncError):
                self.client.refresh()
        self.assertEqual(self.client.last_share, before)
        self.assertEqual(self.client.state, "REVOKED")
