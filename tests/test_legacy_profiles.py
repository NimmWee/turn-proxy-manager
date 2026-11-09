import base64
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from ftm.legacy import baseline_module
from tests.fixtures import legacy_state


class LegacyProfileContractTests(unittest.TestCase):
    def test_original_profile_writer_creates_private_independent_imports(self):
        app = baseline_module()
        state = legacy_state()
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            with patch.object(app, "paths", return_value=(root / "etc", root)):
                output = app.write_profiles(state)
                iphone = (output / "iphone-import.txt").read_text().strip()
                android = (output / "android-import.txt").read_text().strip()
                if os.name == "posix":
                    self.assertEqual(output.stat().st_mode & 0o777, 0o700)
                    for file in output.iterdir():
                        self.assertEqual(file.stat().st_mode & 0o777, 0o600)
                ios_data = json.loads(base64.b64decode(iphone.split("data=", 1)[1]))
                payload = android.split("://", 1)[1]
                android_data = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
                self.assertEqual(ios_data["version"], 1)
                self.assertTrue(ios_data["settings"]["useWrapS"])
                self.assertFalse(ios_data["settings"]["useUDP"])
                self.assertEqual(ios_data["settings"]["tunnelAddress"], "10.77.43.2/32")
                self.assertEqual(android_data["obf"], "rtpopus3")
                self.assertIn("10.77.43.3/32", android_data["wg"])
                self.assertNotEqual(ios_data["settings"]["clientID"], android_data["cid"])
                self.assertNotIn(ios_data["settings"]["privateKey"], android_data["wg"])
                first = {file.name: file.read_bytes() for file in output.iterdir()}
                app.write_profiles(state)
                self.assertEqual(first, {file.name: file.read_bytes() for file in output.iterdir()})
