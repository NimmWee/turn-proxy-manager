import concurrent.futures
import secrets
import unittest
import uuid

from ftm.agent import reconcile
from ftm.credentials import Credentials, _digest
from ftm.enrollment import Enrollment
from ftm.managed import adopt_legacy
from tests import test_managed
from tests.test_store import key


class EnrollmentSafetyTests(unittest.TestCase):
    def setUp(self):
        test_managed.ManagedAdoptionTests.setUp(self)
        adopt_legacy(self.store, self.agent)
        self.user = self.store.create_user("Enrollment verification", 1)
        self.credentials = Credentials(self.store)
        self.user_token = self.credentials.issue_subscription(self.user["id"])["token"]
        self.device_token = "ftmd1_" + secrets.token_urlsafe(32)
        self.request = {"name": "Phone", "platform": "android", "public_key": key(82),
                        "client_id": secrets.token_hex(16), "device_token_hash": _digest(self.device_token, "device"),
                        "request_id": str(uuid.uuid4())}
        self.enrollment = Enrollment(self.store)

    def test_concurrent_retry_has_one_device_credential_and_outbox(self):
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as workers:
            values = list(workers.map(lambda _: self.enrollment.register(self.user_token, **self.request), range(2)))
        self.assertEqual(values[0]["device_id"], values[1]["device_id"])
        with self.store.connect() as db:
            self.assertEqual(db.execute("SELECT count(*) FROM device_tokens").fetchone()[0], 1)
            self.assertEqual(db.execute("SELECT count(*) FROM operations WHERE state='pending'").fetchone()[0], 1)
        self.assertIsNone(self.credentials.device(self.device_token))
        reconcile(self.store, self.agent)
        self.assertIsNotNone(self.credentials.device(self.device_token))
        self.assertFalse(set(values[0]) & {"token", "private_key", "cid", "preshared_key"})

    def test_concurrent_new_requests_cannot_exceed_user_limit(self):
        second = dict(self.request, public_key=key(83), client_id=secrets.token_hex(16),
                      request_id=str(uuid.uuid4()), device_token_hash=_digest("ftmd1_" + secrets.token_urlsafe(32), "device"))
        def register(value):
            try:
                return self.enrollment.register(self.user_token, **value)
            except ValueError:
                return None
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as workers:
            values = list(workers.map(register, [self.request, second]))
        self.assertEqual(sum(value is not None for value in values), 1)

    def test_binding_changes_and_revocation_cannot_reissue_credentials(self):
        value = self.enrollment.register(self.user_token, **self.request)
        changed = dict(self.request, device_token_hash="a" * 64)
        with self.assertRaises(ValueError):
            self.enrollment.register(self.user_token, **changed)
        reconcile(self.store, self.agent)
        self.credentials.issue_device(value["device_id"])
        with self.assertRaises(ValueError):
            self.enrollment.register(self.user_token, **self.request)
        self.store.revoke_device(value["device_id"])
        with self.assertRaises(ValueError):
            self.enrollment.register(self.user_token, **self.request)
        self.assertFalse(self.store.get_device(value["device_id"])["enabled"])

    def test_credential_collision_rolls_back_device_ip_and_operation(self):
        self.enrollment.register(self.user_token, **self.request)
        user = self.store.create_user("Another family member", 1)
        token = self.credentials.issue_subscription(user["id"])["token"]
        changed = dict(self.request, public_key=key(84), client_id=secrets.token_hex(16), request_id=str(uuid.uuid4()))
        with self.store.connect() as db:
            before = db.execute("SELECT value FROM settings WHERE key='next_ip'").fetchone()[0]
        with self.assertRaises(ValueError):
            self.enrollment.register(token, **changed)
        with self.store.connect() as db:
            self.assertEqual(db.execute("SELECT value FROM settings WHERE key='next_ip'").fetchone()[0], before)
            self.assertEqual(db.execute("SELECT count(*) FROM devices WHERE user_id=?", (user["id"],)).fetchone()[0], 0)
