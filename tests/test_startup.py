import json
import unittest

from tests import test_managed
from tests.test_store import key
from ftm.managed import adopt_legacy
from ftm.agent import NetworkAgent, reconcile
from ftm.startup import prepare_startup


class StartupTests(unittest.TestCase):
    setUp = test_managed.ManagedAdoptionTests.setUp

    def offline(self):
        def forbidden(args):
            raise AssertionError("Startup preparation must not run live commands")
        return NetworkAgent(self.state, config_dir=self.conf, state_dir=self.agent.directory,
                            runner=forbidden, offline=True)

    def test_pending_legacy_revoke_is_persisted_before_network_start(self):
        adopt_legacy(self.store, self.agent)
        android = self.store.get_device(next(d["id"] for d in self.store.list_devices() if d["platform"] == "android"))
        iphone = self.state["clients"]["iphone"]
        self.store.revoke_device(android["id"])
        result = prepare_startup(self.store, self.offline())
        self.assertEqual(result["errors"], 0)
        text = (self.conf / "wireguard.conf").read_text()
        self.assertNotIn(android["wg_public_key"], text)
        self.assertIn(iphone["public_key"], text)
        self.assertNotIn(android["cid"], json.loads((self.conf / "clients.json").read_text())["clients"])
        self.assertEqual(len(self.runner.peers), 2)
        self.assertEqual(prepare_startup(self.store, self.offline())["errors"], 0)

    def test_pending_add_preserves_unknown_persistent_peer(self):
        adopt_legacy(self.store, self.agent)
        user = self.store.create_user("Boot test")
        device = self.store.create_device(user["id"], "New phone", "other", key(88), "boot-add")
        path = self.conf / "wireguard.conf"
        unknown = f"\n[Peer]\nPublicKey = {key(99)}\nAllowedIPs = 10.77.43.200/32\n"
        path.write_bytes(path.read_bytes() + unknown.encode())
        prepare_startup(self.store, self.offline())
        self.assertIn(unknown, path.read_text())
        self.assertIn(device["wg_public_key"], path.read_text())
        self.assertEqual(len(self.runner.peers), 2)

    def test_conflict_aborts_startup_instead_of_loading_old_access(self):
        adopt_legacy(self.store, self.agent)
        user = self.store.create_user("Conflict")
        self.store.create_device(user["id"], "Phone", "other", key(88), "conflict")
        path = self.conf / "wireguard.conf"
        path.write_bytes(path.read_bytes() + f"\n[Peer]\nPublicKey = {key(99)}\nAllowedIPs = 10.77.43.10/32\n".encode())
        with self.assertRaises(RuntimeError):
            prepare_startup(self.store, self.offline())

    def test_preparation_requires_completed_adoption(self):
        with self.assertRaises(ValueError):
            prepare_startup(self.store, self.offline())
