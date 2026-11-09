import json
import unittest

from ftm.compat import managed_status
from tests.fixtures import legacy_state
from tests.test_store import key


class CompatStatusTests(unittest.TestCase):
    def test_dynamic_peer_count_and_unknown_peer_do_not_break_health(self):
        state = legacy_state()
        records = {"devices": {"new": {"phase": "active", "spec": {"wg_public_key": key(99)}}}}
        peers = {p["public_key"] for p in state["clients"].values()} | {key(99), key(100)}
        def run(args):
            return "\n".join(peers) if args[0] == "wg" else "active\n"
        report = managed_status(state, records, run)
        self.assertTrue(report["consistent"])
        self.assertEqual(report["expected_peers"], 3)
        self.assertEqual(report["unknown_peers"], 1)
        self.assertNotIn(state["server_private"], json.dumps(report))

    def test_missing_or_revoked_live_peer_is_reported(self):
        state = legacy_state()
        phone = state["clients"]["iphone"]["public_key"]
        android = state["clients"]["android"]["public_key"]
        registry = {"devices": {"android": {"legacy": True, "enabled": False, "phase": "revoked", "spec": {"wg_public_key": android}}}}
        def run(args):
            return "\n".join([phone, android]) if args[0] == "wg" else "active"
        report = managed_status(state, registry, run)
        self.assertFalse(report["consistent"])
        self.assertEqual(report["disabled_peers_present"], 1)
        self.assertEqual(report["expected_peers"], 1)

    def test_stopped_service_is_not_reported_as_healthy(self):
        state = legacy_state()
        def run(args):
            if args[0] == "wg":
                return "\n".join(p["public_key"] for p in state["clients"].values())
            raise RuntimeError("stopped")
        self.assertFalse(managed_status(state, {"devices": {}}, run)["consistent"])
