import json
from pathlib import Path
import tempfile
import unittest

from ftm.managed import adopt_legacy
from ftm.agent import NetworkAgent, reconcile
from ftm.store import Store, ValidationError
from ftm.legacy import baseline_module
from tests.fixtures import legacy_state
from tests.test_agent import FakeWireGuard


def legacy_config(state):
    app = baseline_module()
    text = f"[Interface]\nPrivateKey = {state['server_private']}\nListenPort = {state['backend_port']}\n"
    for name, last in [("iphone", 2), ("android", 3)]:
        p = state["clients"][name]
        text += (f"\n[Peer]\nPublicKey = {p['public_key']}\nPresharedKey = {p['preshared_key']}\n"
                 f"AllowedIPs = {app.address(state,last)}/32, {app.v6prefix(state)}{last}/128\n")
    return text


class ManagedAdoptionTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        root = Path(self.folder.name)
        self.state = legacy_state()
        self.conf = root / "conf"
        self.conf.mkdir()
        (self.conf / "wireguard.conf").write_bytes(legacy_config(self.state).encode())
        (self.conf / "clients.json").write_text(json.dumps({"clients": {
            peer["cid"]: {"comment": name, "note": "preserve existing metadata"} for name, peer in self.state["clients"].items()}}))
        self.store = Store(root / "metadata/db.sqlite3")
        self.store.initialize()
        self.store.import_legacy(self.state)
        self.runner = FakeWireGuard(self.state)
        self.agent = NetworkAgent(self.state, config_dir=self.conf, state_dir=root / "agent", runner=self.runner)

    def test_adoption_changes_no_live_peers_and_is_idempotent(self):
        profiles = baseline_module().profile_links(self.state)
        result = adopt_legacy(self.store, self.agent)
        self.assertEqual(result["adopted"], 2)
        self.assertFalse(result["vpn_restarted"])
        self.assertEqual(adopt_legacy(self.store, self.agent)["adopted"], 0)
        self.assertEqual(len(self.runner.peers), 2)
        self.assertFalse(any(command[:2] == ["wg", "set"] for command in self.runner.commands))
        self.assertEqual(profiles, baseline_module().profile_links(self.state))
        for device in self.store.list_devices():
            self.assertIn("# FTM device " + device["id"], (self.conf / "wireguard.conf").read_text())

    def test_adopted_android_can_be_revoked_and_reenabled_without_touching_iphone(self):
        adopt_legacy(self.store, self.agent)
        device = next(d for d in self.store.list_devices() if d["platform"] == "android")
        phone = self.state["clients"]["iphone"]["public_key"]
        self.store.revoke_device(device["id"])
        self.assertEqual(reconcile(self.store, self.agent)["errors"], 0)
        self.assertEqual(self.runner.peers, {phone})
        self.store.set_device_enabled(device["id"], True)
        self.assertEqual(reconcile(self.store, self.agent)["errors"], 0)
        self.assertEqual(len(self.runner.peers), 2)
        content = (self.conf / "wireguard.conf").read_text()
        self.assertIn("fd77:4d:2b::3/128", content)

    def test_metadata_flag_alone_cannot_authorize_legacy_network_operation(self):
        with self.store.connect() as db:
            db.execute("INSERT INTO settings VALUES('managed_legacy_adopted','1')")
        device = self.store.list_devices()[0]
        self.store.revoke_device(device["id"])
        self.assertEqual(reconcile(self.store, self.agent)["errors"], 1)
        self.assertEqual(len(self.runner.peers), 2)

    def test_interrupted_adoption_resumes_without_duplicate_config_markers(self):
        adopt_legacy(self.store, self.agent)
        before = (self.conf / "wireguard.conf").read_bytes()
        with self.store.connect() as db:
            db.execute("DELETE FROM settings WHERE key='managed_legacy_adopted'")
        adopt_legacy(self.store, self.agent)
        self.assertEqual((self.conf / "wireguard.conf").read_bytes(), before)

    def test_wrong_persistent_configuration_aborts_without_metadata_or_registry_adoption(self):
        path = self.conf / "wireguard.conf"
        path.write_text(path.read_text().replace("ListenPort = 51830", "ListenPort = 51831"))
        before = path.read_bytes()
        with self.assertRaises(ValidationError):
            adopt_legacy(self.store, self.agent)
        self.assertEqual(path.read_bytes(), before)
        with self.store.connect() as db:
            self.assertIsNone(db.execute("SELECT value FROM settings WHERE key='managed_legacy_adopted'").fetchone())
