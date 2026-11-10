import ipaddress
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from ftm.internal_https import rule, set_rule, ensure


class InternalRuleSafetyTests(unittest.TestCase):
    def test_management_hook_failure_closes_its_permission_without_owning_vpn_lifecycle(self):
        agent = object()
        with patch('ftm.internal_https.load_agent', return_value=agent), patch('ftm.internal_https.sync', side_effect=ValueError), patch('ftm.internal_https.set_rule') as close:
            with self.assertRaisesRegex(RuntimeError, 'VPN startup may continue'):
                ensure()
            close.assert_called_once_with(agent, False)

    def test_only_owned_tcp443_rule_is_reordered_or_removed(self):
        agent = SimpleNamespace(interface='vkvpn0', subnet=ipaddress.ip_network('10.77.43.0/24'))
        expected = rule(agent)
        self.assertEqual(expected[6:], ['INPUT', '-i', 'vkvpn0', '-s', '10.77.43.0/24', '-d', '10.77.43.1',
                                       '-p', 'tcp', '--dport', '443', '-m', 'comment', '--comment', 'ftm-client-internal', '-j', 'ACCEPT'])
        with patch('ftm.internal_https.exists', side_effect=[True, False]), patch('ftm.internal_https._run') as run:
            set_rule(agent, True)
            delete = expected.copy()
            delete[5] = '-D'
            self.assertEqual(run.call_args_list, [unittest.mock.call(delete), unittest.mock.call(expected)])
        with patch('ftm.internal_https.exists', side_effect=[True, False]), patch('ftm.internal_https._run') as run:
            set_rule(agent, False)
            self.assertEqual(run.call_args_list, [unittest.mock.call(delete)])
