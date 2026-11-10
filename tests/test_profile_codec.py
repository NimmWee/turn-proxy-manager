import base64
import unittest

from ftm.profile_codec import decode, encode
from ftm.legacy import baseline_module
from tests.fixtures import legacy_state


class ProfileCompatibilityTests(unittest.TestCase):
    def test_preserved_baseline_wireguard_payload_roundtrips_without_key_changes(self):
        state = legacy_state()
        link = baseline_module().profile_links(state)["android"]
        value = decode(link)
        self.assertEqual(decode(encode(value)), value)
        self.assertEqual(value["cid"], state["clients"]["android"]["cid"])
        self.assertIn(state["clients"]["android"]["private_key"], value["wg"])
        self.assertIn("Endpoint = 127.0.0.1:9000", value["wg"])
        self.assertEqual((value["provider"], value["transport"], value["mode"], value["obf"]), ("vk", "tcp", "udp", "rtpopus3"))

    def test_ambiguous_unknown_and_oversized_data_are_rejected_without_echo(self):
        marker = "synthetic-secret-marker"
        values = [dict(v=True, provider="vk", peer="localhost"),
                  dict(v=1, provider="vk", peer="localhost", unexpected=marker),
                  dict(v=1, provider="vk", peer="localhost", kcp={"mtu": 1280}),
                  dict(v=1, provider="vk", peer="localhost", wg=marker * 10000)]
        for value in values:
            with self.assertRaises(ValueError) as error:
                encode(value)
            self.assertNotIn(marker, str(error.exception))
        raw = b'{"v":1,"provider":"vk","peer":"host","peer":"synthetic-secret-marker"}'
        duplicate = "freeturn://" + base64.urlsafe_b64encode(raw).decode().rstrip("=")
        for link in (duplicate, "freeturn://invalid=", "freeturn://" + "x" * 100000):
            with self.assertRaises(ValueError) as error:
                decode(link)
            self.assertNotIn(marker, str(error.exception))
