import unittest

from ftm.bootstrap import Bootstraps
from ftm.agent import reconcile
from ftm.credentials import _digest
from tests import test_client_web
from tests.test_store import key


@unittest.skipUnless(test_client_web.TestClient, 'Install web development dependencies')
class BootstrapHttpBoundaryTests(unittest.TestCase):
    def test_claim_uses_actual_peer_not_body_or_forwarded_header(self):
        test_client_web.ClientHttpSafetyTests.setUp(self)
        values = []
        result = Bootstraps(self.store, self.agent).issue(self.user['id'], name='Bootstrap HTTP', platform='windows',
                    keypair=lambda: (key(96), key(97)), deliver=values.append)
        reconcile(self.store, self.agent)
        artifact = values[0]
        device = self.store.get_device(result['device_id'])
        path = self.base + 'bootstrap/claim'
        body = {'device_id': device['id'], 'device_token_hash': _digest(self.token, 'device')}
        headers = {'Authorization': 'Bearer ' + artifact['claim_nonce'], 'X-Forwarded-For': device['ip']}
        denied = self.client.post(path, json=body, headers=headers)
        self.assertEqual(denied.status_code, 403)
        self.assertNotIn(artifact['claim_nonce'], denied.text)
        self.assertEqual(self.client.post(path, json=dict(body, source_ip=device['ip']), headers=headers).status_code, 422)
        with test_client_web.TestClient(self.client.app, base_url='https://8.8.8.8', client=(device['ip'], 1234)) as internal:
            self.assertEqual(internal.post(path, json=body, headers=headers).status_code, 200)
            self.assertEqual(internal.post(path, json=body, headers=headers).status_code, 200)
            config = internal.get(self.base + 'subscription', headers={'Authorization': 'Bearer ' + self.token})
            self.assertEqual(config.status_code, 200)
            self.assertEqual(config.json()['device_id'], device['id'])
