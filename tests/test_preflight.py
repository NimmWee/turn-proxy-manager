import unittest

from ftm.preflight import evaluate, parse_bound_ports


class PreflightTests(unittest.TestCase):
    def facts(self, **changes):
        facts = {"os_id": "ubuntu", "os_version": "24.04", "root": True, "systemd": True,
                 "cpu_count": 1, "mem_total_bytes": 1024 ** 3, "disk_free_bytes": 2 * 1024 ** 3,
                 "tcp_ports": [22], "udp_ports": [], "legacy_state_exists": False,
                 "tools": {name: True for name in ["ip", "wg", "iptables", "openssl", "systemctl"]}}
        facts.update(changes)
        return facts

    def test_ubuntu_minimum_and_ssh_are_preserved(self):
        report = evaluate(self.facts())
        self.assertFalse(report["changes_system"])
        self.assertTrue(report["preflight_ready"])
        self.assertFalse(report["installation_ready"])
        self.assertIn("dns_tls_and_vpn_e2e", report["not_checked"])

    def test_unavailable_and_insufficient_resources_do_not_claim_ready(self):
        for change in [{"os_id": "debian"}, {"os_version": "22.04"}, {"root": False},
                       {"systemd": False}, {"mem_total_bytes": None}, {"mem_total_bytes": 256 * 1024 ** 2},
                       {"disk_free_bytes": 1}, {"cpu_count": None}]:
            with self.subTest(change=change):
                self.assertFalse(evaluate(self.facts(**change))["preflight_ready"])

    def test_web_port_conflict_blocks_and_existing_vpn_is_not_reported_as_fresh(self):
        report = evaluate(self.facts(tcp_ports=[22, 443], udp_ports=[56001, 51830], legacy_state_exists=True))
        self.assertFalse(report["preflight_ready"])
        self.assertEqual(report["recommended_mode"], "migrate")
        self.assertIn("web_ports_in_use", report["blockers"])
        self.assertNotIn("unowned_vpn_ports_in_use", report["blockers"])
        self.assertIn("unowned_vpn_ports_in_use", evaluate(self.facts(udp_ports=[56001]))["blockers"])

    def test_missing_tools_reported_separately_not_installed(self):
        report = evaluate(self.facts(tools={"wg": False, "ip": True}))
        self.assertIn("wg", report["missing_tools"])
        self.assertFalse(report["installation_ready"])

    def test_proc_ports_only_counts_tcp_listeners_and_udp_bindings(self):
        lines = "sl local_address rem_address st\n 0: 00000000:01BB 00000000:0000 0A\n 1: 00000000:0016 00000000:0000 01\n"
        self.assertEqual(parse_bound_ports(lines, tcp=True), [443])
        self.assertEqual(parse_bound_ports(lines, tcp=False), [22, 443])
        self.assertEqual(parse_bound_ports("header\nmalformed\n0: invalid 0000 0A", tcp=True), [])
