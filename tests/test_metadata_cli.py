import base64
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from tests.fixtures import legacy_state

ROOT = Path(__file__).resolve().parents[1]


class MetadataCliTests(unittest.TestCase):
    def test_init_import_list_and_device_creation_do_not_expose_secrets(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)
            db = path / "private/db.sqlite3"
            def run(*args):
                return subprocess.run([sys.executable, "-X", "utf8", "-m", "ftm.metadata_cli", "--db", str(db), *args],
                                      cwd=ROOT, capture_output=True, text=True, encoding="utf-8", timeout=20)
            self.assertEqual(run("init").returncode, 0)
            state = legacy_state()
            state_file = path / "state.json"
            state_file.write_text(json.dumps(state))
            state_file.chmod(0o600)
            result = run("import-legacy", "--state", str(state_file))
            self.assertEqual(result.returncode, 0, result.stderr)
            users = json.loads(run("users", "list").stdout)
            public = path / "public"
            public.write_text(base64.b64encode(b"x" * 32).decode())
            result = run("devices", "add", users[0]["id"], "New phone", "--platform", "ios",
                         "--public-key-file", str(public), "--request-id", "test-create")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)["state"], "pending")
            output = result.stdout + run("devices", "list").stdout
            for secret in [state["server_private"], state["vk_link"], state["obf_key"], state["clients"]["iphone"]["cid"]]:
                self.assertNotIn(secret, output)
            self.assertNotIn("preshared_key", output)
            self.assertNotIn('"cid"', output)

    def test_read_commands_do_not_create_missing_database(self):
        with tempfile.TemporaryDirectory() as folder:
            db = Path(folder) / "private/no-db.sqlite3"
            result = subprocess.run([sys.executable, "-m", "ftm.metadata_cli", "--db", str(db), "users", "list"],
                                    cwd=ROOT, capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 2)
            self.assertFalse(db.exists())
