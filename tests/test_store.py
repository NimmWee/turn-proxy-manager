import base64
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest

from ftm.store import Store, Conflict, ValidationError
from tests.fixtures import legacy_state


def key(n):
    return base64.b64encode(n.to_bytes(32, "big")).decode()


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.path = Path(self.folder.name) / "private/manager.sqlite3"
        self.store = Store(self.path)

    def test_schema_pragmas_reopen_and_permissions(self):
        self.store.initialize()
        self.store.initialize()
        with self.store.connect() as db:
            self.assertEqual(db.execute("PRAGMA journal_mode").fetchone()[0], "wal")
            self.assertEqual(db.execute("PRAGMA foreign_keys").fetchone()[0], 1)
            self.assertGreaterEqual(db.execute("PRAGMA busy_timeout").fetchone()[0], 5000)
            self.assertEqual(db.execute("SELECT max(version) FROM migration_versions").fetchone()[0], 1)
        if os.name == "posix":
            self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(self.path.parent.stat().st_mode & 0o777, 0o700)

    def test_users_and_three_independent_devices(self):
        self.store.initialize()
        user = self.store.create_user("Александр")
        devices = [self.store.create_device(user["id"], f"Phone {n}", "ios", key(n), f"operation-{n}") for n in range(1, 4)]
        for field in ("ip", "cid", "wg_public_key", "preshared_key"):
            self.assertEqual(len({device[field] for device in devices}), 3)
        self.assertEqual([device["ip"] for device in devices], ["10.77.43.10", "10.77.43.11", "10.77.43.12"])
        self.assertTrue(all(device["state"] == "pending" for device in devices))
        self.assertEqual(len(self.store.list_devices()), 3)
        self.assertNotIn("preshared_key", self.store.list_devices()[0])
        self.assertNotIn("cid", self.store.list_devices()[0])

    def test_idempotent_enrollment_rejects_changed_request_and_duplicate_public_key(self):
        self.store.initialize()
        user = self.store.create_user("User")
        first = self.store.create_device(user["id"], "Phone", "ios", key(1), "same-request")
        self.assertEqual(first, self.store.create_device(user["id"], "Phone", "ios", key(1), "same-request"))
        with self.assertRaises(Conflict):
            self.store.create_device(user["id"], "Changed", "ios", key(2), "same-request")
        with self.assertRaises(Conflict):
            self.store.create_device(user["id"], "Other", "android", key(1), "other-request")

    def test_twenty_users_sixty_devices_and_concurrent_allocation(self):
        self.store.initialize()
        users = [self.store.create_user(f"Family {n}") for n in range(20)]
        def create(n):
            return Store(self.path).create_device(users[n // 3]["id"], f"Device {n}", "other", key(n + 1), f"req-{n}")
        with ThreadPoolExecutor(max_workers=10) as pool:
            devices = list(pool.map(create, range(60)))
        self.assertEqual(len({device["ip"] for device in devices}), 60)
        self.assertEqual(len({device["cid"] for device in devices}), 60)

    def test_concurrent_same_request_only_creates_one_device(self):
        self.store.initialize()
        user = self.store.create_user("User")
        with ThreadPoolExecutor(max_workers=10) as pool:
            devices = list(pool.map(lambda _: Store(self.path).create_device(user["id"], "Phone", "ios", key(1), "same"), range(10)))
        self.assertEqual(len({device["id"] for device in devices}), 1)
        self.assertEqual(len(self.store.list_devices()), 1)

    def test_disabled_user_limits_and_unchecked_awg_fail(self):
        self.store.initialize()
        user = self.store.create_user("User", device_limit=1)
        device = self.store.create_device(user["id"], "Phone", "ios", key(1), "a")
        with self.assertRaises(ValidationError):
            self.store.create_device(user["id"], "Other", "ios", key(2), "b")
        self.store.revoke_device(device["id"])
        self.assertEqual(self.store.get_device(device["id"])["state"], "revoking")
        self.store.set_user_enabled(user["id"], False)
        with self.assertRaises(ValidationError):
            self.store.create_device(user["id"], "Other", "ios", key(2), "c")
        with self.assertRaises(ValidationError):
            self.store.create_device(user["id"], "Other", "ios", key(2), "d", vpn_type="awg")

    def test_import_legacy_is_idempotent_and_contains_no_private_keys(self):
        self.store.initialize()
        state = legacy_state()
        before = json.dumps(state, sort_keys=True)
        report = self.store.import_legacy(state)
        self.assertEqual(report["imported_devices"], 2)
        self.assertEqual(self.store.import_legacy(state)["imported_devices"], 0)
        devices = self.store.list_devices()
        self.assertEqual({device["ip"] for device in devices}, {"10.77.43.2", "10.77.43.3"})
        self.assertTrue(all(device["state"] == "active" for device in devices))
        with self.store.connect() as db:
            dump = "".join(db.iterdump())
        for secret in [state["server_private"], state["obf_key"], state["vk_link"], state["clients"]["iphone"]["private_key"]]:
            self.assertNotIn(secret, dump)
        self.assertEqual(before, json.dumps(state, sort_keys=True))
        changed = legacy_state()
        changed["clients"]["iphone"]["cid"] = "f" * 32
        with self.assertRaises(Conflict):
            self.store.import_legacy(changed)

    def test_backup_api_integrity_and_no_overwrite(self):
        self.store.initialize()
        self.store.create_user("Family")
        destination = Path(self.folder.name) / "backup.sqlite3"
        self.store.backup(destination)
        with sqlite3.connect(destination) as db:
            self.assertEqual(db.execute("PRAGMA integrity_check").fetchone()[0], "ok")
            self.assertEqual(db.execute("SELECT name FROM users").fetchone()[0], "Family")
        with self.assertRaises(FileExistsError):
            self.store.backup(destination)

    def test_bad_input_never_exposes_secrets_in_errors_or_audit(self):
        self.store.initialize()
        user = self.store.create_user("User")
        for public in ["PRIVATE-DO-NOT-ECHO", "x;reboot", key(0), key(1) + "junk"]:
            with self.subTest(public=public), self.assertRaises(ValidationError) as caught:
                self.store.create_device(user["id"], "Phone", "ios", public, "request")
            self.assertNotIn(public, str(caught.exception))
        with self.store.connect() as db:
            self.assertEqual(db.execute("SELECT count(*) FROM devices").fetchone()[0], 0)

    def test_pool_exhaustion_is_transactional(self):
        self.store.initialize()
        user = self.store.create_user("User")
        with self.store.connect() as db:
            db.execute("INSERT OR REPLACE INTO settings(key,value) VALUES('next_ip','254')")
        self.store.create_device(user["id"], "Last", "other", key(1), "last")
        with self.assertRaises(ValidationError):
            self.store.create_device(user["id"], "Full", "other", key(2), "full")
        self.assertEqual(len(self.store.list_devices()), 1)

    def test_legacy_revoke_and_disable_are_rejected_before_metadata_changes(self):
        self.store.initialize()
        report = self.store.import_legacy(legacy_state())
        device = self.store.list_devices()[0]
        with self.assertRaises(ValidationError):
            self.store.revoke_device(device["id"])
        with self.assertRaises(ValidationError):
            self.store.set_user_enabled(report["user_id"], False)
        self.assertEqual(self.store.get_device(device["id"])["state"], "active")
        self.assertEqual(self.store.list_users()[0]["enabled"], 1)

    def test_future_schema_version_is_not_silently_downgraded(self):
        self.store.initialize()
        with self.store.connect() as db:
            db.execute("UPDATE migration_versions SET version=2")
        with self.assertRaises(ValidationError):
            self.store.initialize()
