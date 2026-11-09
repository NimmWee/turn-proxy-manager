import json
import os
from pathlib import Path
import tempfile
import unittest

from ftm.agent import NetworkAgent, reconcile
from ftm.store import Store, Conflict, ValidationError
from tests.fixtures import legacy_state
from tests.test_store import key


class FakeWireGuard:
    def __init__(self, state):
        self.peers = {peer["public_key"] for peer in state["clients"].values()}
        self.commands = []
        self.fail = False
        self.psk_seen = False

    def __call__(self, args):
        self.commands.append(args)
        if args == ["wg", "show", "vkvpn0", "peers"]:
            return "\n".join(sorted(self.peers))
        if args == ["wg", "show", "vkvpn0", "allowed-ips"]:
            return ""
        if args[:4] == ["wg", "set", "vkvpn0", "peer"]:
            if self.fail:
                raise RuntimeError("network failure")
            if args[5] == "remove":
                self.peers.discard(args[4])
            else:
                self.assert_private_psk(Path(args[6]))
                self.peers.add(args[4])
            return ""
        raise AssertionError("Unexpected command")

    def assert_private_psk(self, path):
        self.psk_seen = bool(path.read_text().strip())
        if os.name == "posix" and path.stat().st_mode & 0o777 != 0o600:
            raise AssertionError("PSK file is not private")


class AgentTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        root = Path(self.folder.name)
        self.state = legacy_state()
        self.conf = root / "conf"
        self.conf.mkdir()
        self.registry = root / "root-agent"
        self.clients = {peer["cid"]: {"comment": name} for name, peer in self.state["clients"].items()}
        self.clients["e" * 32] = {"comment": "unknown must remain"}
        (self.conf / "clients.json").write_text(json.dumps({"clients": self.clients}))
        (self.conf / "wireguard.conf").write_text("[Interface]\nPrivateKey = synthetic-only\n" + "".join(
            f"\n[Peer]\nPublicKey = {peer['public_key']}\nAllowedIPs = 10.77.43.{n}/32\n"
            for n, peer in enumerate(self.state["clients"].values(), 2)))
        self.runner = FakeWireGuard(self.state)
        self.agent = NetworkAgent(self.state, config_dir=self.conf, state_dir=self.registry, runner=self.runner)
        self.store = Store(root / "metadata/db.sqlite3")
        self.store.initialize()
        self.store.import_legacy(self.state)
        self.user = self.store.create_user("Family")

    def device(self, n=50):
        return self.store.create_device(self.user["id"], "Phone", "other", key(n), f"request-{n}")

    def test_hot_add_revoke_and_persistence_preserve_baseline_and_unknown_cids(self):
        device = self.device()
        before = (self.conf / "wireguard.conf").read_text()
        report = reconcile(self.store, self.agent)
        self.assertEqual(report["processed"], 1)
        self.assertEqual(report["errors"], 0)
        self.assertEqual(self.store.get_device(device["id"])["state"], "active")
        self.assertEqual(len(self.runner.peers), 3)
        self.assertTrue(self.runner.psk_seen)
        self.assertIn(device["wg_public_key"], (self.conf / "wireguard.conf").read_text())
        self.assertTrue((self.conf / "wireguard.conf").read_text().startswith(before))
        self.assertIn(device["cid"], json.loads((self.conf / "clients.json").read_text())["clients"])
        self.store.revoke_device(device["id"])
        self.assertEqual(reconcile(self.store, self.agent)["errors"], 0)
        self.assertEqual(len(self.runner.peers), 2)
        self.assertEqual(self.store.get_device(device["id"])["state"], "revoked")
        self.assertEqual(json.loads((self.conf / "clients.json").read_text())["clients"], self.clients)
        self.assertEqual((self.conf / "wireguard.conf").read_text(), before)
        self.assertTrue(all(command[0] == "wg" for command in self.runner.commands))

    def test_retry_after_network_error_does_not_lose_desired_operation(self):
        device = self.device()
        before = (self.conf / "clients.json").read_bytes()
        self.runner.fail = True
        self.assertEqual(reconcile(self.store, self.agent)["errors"], 1)
        self.assertEqual((self.conf / "clients.json").read_bytes(), before)
        self.runner.fail = False
        self.assertEqual(reconcile(self.store, self.agent)["processed"], 1)
        self.assertEqual(self.store.get_device(device["id"])["state"], "active")

    def test_unknown_public_peer_is_never_adopted_or_removed(self):
        device = self.device()
        self.runner.peers.add(device["wg_public_key"])
        self.assertEqual(reconcile(self.store, self.agent)["errors"], 1)
        self.assertIn(device["wg_public_key"], self.runner.peers)

    def test_unknown_persisted_peer_is_not_overwritten_even_when_not_live(self):
        device = self.device()
        path = self.conf / "wireguard.conf"
        before = path.read_text() + f"\n[Peer]\nPublicKey = {device['wg_public_key']}\nAllowedIPs = 10.77.43.240/32\n"
        path.write_text(before)
        self.assertEqual(reconcile(self.store, self.agent)["errors"], 1)
        self.assertEqual(path.read_text(), before)

    def test_live_allowed_ip_conflict_is_rejected(self):
        self.device()
        original = self.runner
        def runner(args):
            if args[-1] == "allowed-ips":
                return key(999) + "\t10.77.43.10/32, fd77::2/128\n"
            return original(args)
        self.agent.runner = runner
        self.assertEqual(reconcile(self.store, self.agent)["errors"], 1)
        self.assertEqual(len(self.runner.peers), 2)

    def test_stale_create_operation_does_not_reenable_revoked_device(self):
        device = self.device()
        self.store.revoke_device(device["id"])
        report = reconcile(self.store, self.agent)
        self.assertEqual(report["errors"], 0)
        self.assertNotIn(device["wg_public_key"], self.runner.peers)
        self.assertEqual(self.store.get_device(device["id"])["state"], "revoked")

    def test_baseline_revocation_is_explicitly_blocked_until_managed_startup_migration(self):
        device = self.store.list_devices()[0]
        with self.assertRaises(ValidationError):
            self.store.revoke_device(device["id"])
        with self.assertRaises(ValidationError):
            self.agent.apply(self.store.get_device(device["id"]))
        self.assertEqual(len(self.runner.peers), 2)

    def test_shell_and_bad_ip_requests_are_rejected_without_commands(self):
        device = self.device()
        for changes in [{"cid": "x;reboot"}, {"ip": "127.0.0.1"}, {"ip": "10.77.43.1"},
                        {"wg_public_key": "bad"}, {"id": "../../etc/cron.d/x"}, {"preshared_key": "secret"}]:
            request = {**device, **changes}
            with self.subTest(changes=changes), self.assertRaises(ValidationError):
                self.agent.apply(request)
        self.assertEqual(self.runner.commands, [])
