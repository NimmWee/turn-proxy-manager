import concurrent.futures
from pathlib import Path
import unittest

from ftm.credentials import Credentials
from ftm.agent import reconcile
from ftm.managed import adopt_legacy
from tests import test_managed
from tests.test_store import key


class CredentialSafetyTests(unittest.TestCase):
    def setUp(self):
        test_managed.ManagedAdoptionTests.setUp(self)
        adopt_legacy(self.store, self.agent)
        self.user = self.store.create_user("Credential verification", 2)
        self.device = self.store.create_device(self.user["id"], "Phone", "android", key(81), "credential-check")
        self.assertEqual(reconcile(self.store, self.agent)["errors"], 0)
        self.credentials = Credentials(self.store)

    def test_url_rotation_preserves_device_access_and_only_hashes_are_persisted(self):
        first = self.credentials.issue_subscription(self.user["id"])
        device = self.credentials.issue_device(self.device["id"])
        second = self.credentials.issue_subscription(self.user["id"])
        self.assertEqual(first["id"], second["id"])
        self.assertEqual(second["version"], first["version"] + 1)
        self.assertIsNone(self.credentials.subscription(first["token"]))
        self.assertEqual(self.credentials.subscription(second["token"])["user_id"], self.user["id"])
        self.assertEqual(self.credentials.device(device["token"])["device_id"], self.device["id"])
        self.credentials.revoke_subscription(self.user["id"])
        self.assertIsNone(self.credentials.subscription(second["token"]))
        self.assertIsNotNone(self.credentials.device(device["token"]))
        backup = Path(self.folder.name) / "credential-copy.sqlite3"
        self.store.backup(backup)
        for token in (first["token"], second["token"], device["token"]):
            self.assertNotIn(token.encode(), backup.read_bytes())

    def test_device_and_user_disable_do_not_revive_old_credentials_on_enable(self):
        old = self.credentials.issue_device(self.device["id"])
        current = self.credentials.issue_device(self.device["id"])
        self.assertIsNone(self.credentials.device(old["token"]))
        self.store.revoke_device(self.device["id"])
        self.assertIsNone(self.credentials.device(current["token"]))
        self.store.set_device_enabled(self.device["id"], True)
        reconcile(self.store, self.agent)
        self.assertIsNone(self.credentials.device(current["token"]))
        fresh = self.credentials.issue_device(self.device["id"])
        self.store.set_user_enabled(self.user["id"], False)
        self.assertIsNone(self.credentials.device(fresh["token"]))
        self.store.set_user_enabled(self.user["id"], True)
        self.store.set_device_enabled(self.device["id"], True)
        reconcile(self.store, self.agent)
        self.assertIsNone(self.credentials.device(fresh["token"]))

    def test_scope_separation_and_ios_remains_manual(self):
        user = self.credentials.issue_subscription(self.user["id"])
        device = self.credentials.issue_device(self.device["id"])
        self.assertIsNone(self.credentials.device(user["token"]))
        self.assertIsNone(self.credentials.subscription(device["token"]))
        for value in (None, 1, "", "ftmu1_" + "x" * 10000):
            self.assertIsNone(self.credentials.subscription(value))
        iphone = next(item for item in self.store.list_devices() if item["platform"] == "ios")
        with self.assertRaises(ValueError):
            self.credentials.issue_device(iphone["id"])

    def test_concurrent_url_rotations_keep_one_identity_and_one_valid_token(self):
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as workers:
            issued = list(workers.map(lambda _: self.credentials.issue_subscription(self.user["id"]), range(2)))
        self.assertEqual(len({value["id"] for value in issued}), 1)
        self.assertEqual(sorted(value["version"] for value in issued), [1, 2])
        self.assertEqual(sum(self.credentials.subscription(value["token"]) is not None for value in issued), 1)

    def test_failed_private_delivery_does_not_rotate_current_credentials(self):
        user = self.credentials.issue_subscription(self.user["id"])
        device = self.credentials.issue_device(self.device["id"])
        def delivery_failure(value):
            raise OSError("Synthetic full output device")
        for operation, identifier in ((self.credentials.issue_subscription, self.user["id"]),
                                      (self.credentials.issue_device, self.device["id"])):
            with self.assertRaises(OSError):
                operation(identifier, deliver=delivery_failure)
        self.assertIsNotNone(self.credentials.subscription(user["token"]))
        self.assertIsNotNone(self.credentials.device(device["token"]))
