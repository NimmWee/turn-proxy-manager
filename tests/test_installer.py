import copy
import json
import os
from pathlib import Path
import tempfile
import unittest

from ftm.installer import build_plan, inspect_state, load_config, validate_config
from tests.fixtures import legacy_state


def config(**overrides):
    result = {"schema_version": 1, "mode": "fresh", "web_mode": "domain",
              "web_host": "vpn.example.org", "panel_access": "public", "tls_mode": "domain"}
    result.update(overrides)
    return result


class ConfigTests(unittest.TestCase):
    def test_domain_and_defaults(self):
        value = validate_config(config(web_host="VPN.Example.org"))
        self.assertEqual(value["web_host"], "vpn.example.org")
        self.assertEqual(build_plan(value)["network"]["vpn_port"], 56001)
        self.assertEqual(build_plan(value)["network"]["backend_port"], 51830)

    def test_ip_may_only_use_trusted_tls_or_private_access(self):
        for access, tls in [("private", "private"), ("public", "ip-trusted")]:
            validate_config(config(web_mode="ip", web_host="93.184.216.34",
                                   panel_access=access, tls_mode=tls))
        for access, tls in [("public", "private"), ("public", "domain")]:
            with self.subTest(access=access, tls=tls), self.assertRaises(ValueError):
                validate_config(config(web_mode="ip", web_host="93.184.216.34",
                                       panel_access=access, tls_mode=tls))

    def test_rejects_shell_url_private_ip_and_invalid_hosts(self):
        for host in ["https://vpn.example.org", "x;reboot", "-x.example.org", "x\n.example.org",
                     "127.0.0.1", "10.0.0.1", "203.0.113.1", "example.org/path", ""]:
            with self.subTest(host=host), self.assertRaises(ValueError):
                validate_config(config(web_host=host))

    def test_strict_schema_types_and_ports(self):
        for overrides in [{"schema_version": True}, {"schema_version": 2}, {"mode": "delete"},
                          {"password": "DO-NOT-PRINT"}, {"vpn_port": True}, {"vpn_port": "56001"},
                          {"vpn_port": 51830}, {"vpn_port": 443}, {"backend_port": 65536},
                          {"subnet": "0.0.0.0/0"}, {"subnet": "10.0.0.0/30"},
                          {"tls_mode": "insecure"}, {"panel_access": "none"}]:
            with self.subTest(overrides=overrides), self.assertRaises(ValueError):
                validate_config(config(**overrides))
        for invalid in [None, [], "config", {}]:
            with self.assertRaises(ValueError):
                validate_config(invalid)

    def test_file_is_data_not_executable(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "config.json"
            path.write_text(json.dumps(config()), encoding="utf-8")
            path.chmod(0o600)
            self.assertEqual(load_config(path)["web_host"], "vpn.example.org")
            path.write_text('WEB_HOST=$(touch /tmp/pwned)', encoding="utf-8")
            with self.assertRaises(ValueError):
                load_config(path)

    def test_duplicate_json_fields_and_invalid_utf8_are_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "config.json"
            for payload in [b'{"schema_version":1,"schema_version":2}', b'\xff']:
                path.write_bytes(payload)
                path.chmod(0o600)
                with self.assertRaises(ValueError):
                    load_config(path)
            path.write_bytes(b"x" * 65537)
            with self.assertRaises(ValueError):
                load_config(path)

    @unittest.skipUnless(os.name == "posix", "POSIX permissions")
    def test_private_regular_file_required(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "config.json"
            path.write_text(json.dumps(config()), encoding="utf-8")
            for mode in [0o644, 0o640, 0o660, 0o700]:
                path.chmod(mode)
                with self.subTest(mode=mode), self.assertRaises(ValueError):
                    load_config(path)
            path.chmod(0o600)
            link = Path(folder) / "link"
            link.symlink_to(path)
            with self.assertRaises(ValueError):
                load_config(link)


class PlanTests(unittest.TestCase):
    def test_dry_run_plan_is_explicit_and_repeatable(self):
        value = config()
        before = copy.deepcopy(value)
        plan = build_plan(value)
        self.assertEqual(plan, build_plan(value))
        self.assertEqual(value, before)
        self.assertFalse(plan["changes_system"])
        self.assertFalse(plan["apply_available"])
        self.assertEqual(plan["network"]["backend_public"], False)
        self.assertIn("encrypted_offsite_backup_and_restore_check", plan["required_before_apply"])

    def test_existing_installation_requires_migration(self):
        with self.assertRaises(ValueError):
            build_plan(config(), legacy_state())
        for mode in ["migrate", "repair"]:
            with self.assertRaises(ValueError):
                build_plan(config(mode=mode))

    def test_migration_preserves_network_and_never_exposes_credentials(self):
        state = legacy_state()
        state.update(port=56002, backend_port=51831, subnet="10.78.44.0/24")
        before = copy.deepcopy(state)
        plan = build_plan(config(mode="migrate"), state)
        self.assertEqual(plan["network"]["vpn_port"], 56002)
        self.assertEqual(plan["network"]["backend_port"], 51831)
        self.assertEqual(plan["network"]["subnet"], "10.78.44.0/24")
        self.assertEqual(state, before)
        output = json.dumps(plan)
        for secret in [state["vk_link"], state["obf_key"], state["server_private"],
                       state["clients"]["iphone"]["cid"], state["clients"]["android"]["private_key"]]:
            self.assertNotIn(secret, output)
        with self.assertRaises(ValueError):
            build_plan(config(mode="migrate", vpn_port=56003), state)

    def test_sanitized_inspection_preserves_state_and_rejects_invalid_state(self):
        state = legacy_state()
        before = copy.deepcopy(state)
        report = inspect_state(state)
        self.assertEqual(report["device_count"], 2)
        self.assertEqual(report["interface"], "vkvpn0")
        self.assertEqual(report["services"], ["vps-vk", "vps-vk-network"])
        self.assertEqual(state, before)
        self.assertNotIn(state["obf_key"], json.dumps(report))
        state["clients"]["third"] = state["clients"]["android"]
        with self.assertRaises(ValueError):
            inspect_state(state)
