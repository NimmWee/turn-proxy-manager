import datetime
from concurrent.futures import ThreadPoolExecutor
import secrets
import unittest

from ftm.bootstrap import Bootstraps
from ftm.client_protocol import ClientFault
from ftm.credentials import _digest
from ftm.agent import reconcile
from tests import test_client_service
from tests.test_store import key


class BootstrapSafetyTests(unittest.TestCase):
    def setUp(self):
        test_client_service.ClientDisclosureTests.setUp(self)
        self.now = datetime.datetime.now(datetime.timezone.utc)
        self.bootstrap = Bootstraps(self.store, self.agent, clock=lambda: self.now)
        self.artifacts = []

    def issue(self, deliver=None):
        result = self.bootstrap.issue(self.user['id'], name='Temporary bootstrap', platform='android',
                                     keypair=lambda: (key(96), key(97)), deliver=deliver or self.artifacts.append)
        if reconcile(self.store, self.agent)['errors']:
            raise RuntimeError('Fixture apply failed')
        self.artifact = self.artifacts[-1]
        self.device = self.store.get_device(result['device_id'])
        return result

    def claim(self, token=None, source=None):
        return self.bootstrap.claim(self.artifact['claim_nonce'], self.device['id'], _digest(token or self.token, 'device'), source or self.device['ip'])

    def test_private_delivery_failure_rolls_back_device_nonce_and_ip_allocation(self):
        with self.store.connect() as db:
            before = '\n'.join(db.iterdump())
        def fail(value):
            raise OSError('Synthetic private delivery failure')
        with self.assertRaises(OSError):
            self.bootstrap.issue(self.user['id'], name='Failed artifact', platform='android', keypair=lambda: (key(96), key(97)), deliver=fail)
        with self.store.connect() as db:
            self.assertEqual('\n'.join(db.iterdump()), before)

    def test_source_expiry_and_replay_do_not_consume_or_reissue_credentials(self):
        self.issue()
        with self.assertRaises(ClientFault) as error:
            self.claim(source='203.0.113.5')
        self.assertEqual(error.exception.code, 'bootstrap_source_denied')
        with self.store.connect() as db:
            self.assertIsNone(db.execute('SELECT consumed_at FROM bootstraps').fetchone()[0])
            dump = '\n'.join(db.iterdump())
            self.assertNotIn(self.artifact['claim_nonce'], dump)
            self.assertNotIn(key(96), dump)
        first = self.claim()
        self.assertEqual(self.claim(), first)
        with self.assertRaises(ClientFault):
            self.claim('ftmd1_' + secrets.token_urlsafe(32))
        self.credentials.revoke_device_credential(self.device['id'])
        with self.assertRaises(ClientFault):
            self.claim()
        self.now += datetime.timedelta(hours=2)
        with self.assertRaises(ClientFault) as error:
            self.claim()
        self.assertEqual(error.exception.status, 410)

    def test_disable_enable_never_revives_unused_bootstrap(self):
        self.issue()
        self.store.set_device_enabled(self.device['id'], False)
        reconcile(self.store, self.agent)
        self.store.set_device_enabled(self.device['id'], True)
        reconcile(self.store, self.agent)
        with self.assertRaises(ClientFault) as error:
            self.claim()
        self.assertEqual(error.exception.status, 410)

    def test_competing_claims_commit_exactly_one_credential(self):
        self.issue()
        def attempt(token):
            try:
                self.claim(token)
                return True
            except ClientFault:
                return False
        with ThreadPoolExecutor(max_workers=4) as pool:
            wins = list(pool.map(attempt, ['ftmd1_' + secrets.token_urlsafe(32) for _ in range(4)]))
        self.assertEqual(sum(wins), 1)
        with self.store.connect() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM device_tokens').fetchone()[0], 1)
