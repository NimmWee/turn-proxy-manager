import copy
import unittest
from unittest.mock import patch

from ftm.agent import reconcile
from ftm.reference_client import ReferenceClient, ClientSyncError
from ftm.reference_client import _InternalHTTPS, _NoRedirect
import urllib.request
from unittest.mock import Mock
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


class InternalTlsIdentityTests(unittest.TestCase):
    def test_internal_dial_preserves_tls_identity_and_rejects_unsafe_destinations(self):
        context = Mock()
        with patch('ftm.reference_client.ssl.create_default_context', return_value=context):
            handler = _InternalHTTPS('https://203.0.113.7', '10.77.43.1')

        def open_connection(factory, request, **kwargs):
            connection = factory('203.0.113.7', **kwargs)
            connection.connect()

        with patch.object(handler, 'do_open', side_effect=open_connection), patch('ftm.reference_client.socket.create_connection') as dial:
            handler.https_open(urllib.request.Request('https://203.0.113.7/api/client/v1/status'))
            self.assertEqual(dial.call_args.args[0], ('10.77.43.1', 443))
            self.assertEqual(context.wrap_socket.call_args.kwargs['server_hostname'], '203.0.113.7')
        for address in ('127.0.0.1', '169.254.169.254', '8.8.8.8', '::1', 'host.example'):
            with self.assertRaises(ClientSyncError):
                _InternalHTTPS('https://203.0.113.7', address)
        with self.assertRaises(ClientSyncError):
            handler.https_open(urllib.request.Request('https://other.example/api/client/v1/status'))
        self.assertIsNone(_NoRedirect().redirect_request(None, None, 302, '', {}, 'https://other.example'))
