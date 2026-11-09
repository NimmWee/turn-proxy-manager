import base64
import copy
from contextlib import closing
from pathlib import Path
import shutil
import sqlite3
import unittest

from tests import test_managed
from ftm.managed import adopt_legacy
from ftm.checkpoint import capture, stage, seal, open_checkpoint


class CheckpointSafetyTests(unittest.TestCase):
    setUp = test_managed.ManagedAdoptionTests.setUp

    def snapshot(self):
        adopt_legacy(self.store, self.agent)
        return capture(self.store, self.agent)

    def test_staged_restore_preserves_keys_registry_and_database(self):
        snapshot = self.snapshot()
        target = Path(self.folder.name) / "restore"
        stage(snapshot, target)
        self.assertEqual((target / "wireguard.conf").read_bytes(), (self.conf / "wireguard.conf").read_bytes())
        with closing(sqlite3.connect(target / "metadata.sqlite3")) as db:
            self.assertEqual(db.execute("PRAGMA integrity_check").fetchone()[0], "ok")
            self.assertEqual(db.execute("SELECT count(*) FROM devices").fetchone()[0], 2)

    def test_extra_files_or_sql_trigger_are_rejected(self):
        snapshot = self.snapshot()
        extra = copy.deepcopy(snapshot)
        extra["files"]["../../etc/systemd/system/injected.service"] = ""
        with self.assertRaises(ValueError):
            stage(extra, Path(self.folder.name) / "extra")
        injected = Path(self.folder.name) / "injected.sqlite3"
        injected.write_bytes(base64.b64decode(snapshot["database"]))
        with closing(sqlite3.connect(injected)) as db:
            db.execute("CREATE TRIGGER unexpected AFTER INSERT ON settings BEGIN DELETE FROM users; END")
            db.commit()
        snapshot["database"] = base64.b64encode(injected.read_bytes()).decode()
        with self.assertRaises(ValueError):
            stage(snapshot, Path(self.folder.name) / "trigger")

    def test_web_settings_roundtrip_and_unknown_fields_rejected(self):
        import json
        from ftm.web_auth import make_config
        adopt_legacy(self.store, self.agent)
        config = Path(self.folder.name) / "web.json"
        config.write_text(json.dumps(make_config("admin", "synthetic admin recovery phrase")))
        config.chmod(0o600)
        snapshot = capture(self.store, self.agent, web_config_path=config)
        self.assertEqual(snapshot["version"], 2)
        target = Path(self.folder.name) / "web-restore"
        stage(snapshot, target)
        self.assertEqual((target / "web.json").read_bytes(), config.read_bytes())
        content = json.loads(config.read_text())
        content["command"] = "unexpected"
        snapshot["files"]["web.json"] = base64.b64encode(json.dumps(content).encode()).decode()
        with self.assertRaises(ValueError):
            stage(snapshot, Path(self.folder.name) / "bad-web-restore")

    @unittest.skipUnless(shutil.which("openssl"), "OpenSSL required")
    def test_wrong_password_and_modified_ciphertext_are_rejected(self):
        snapshot = self.snapshot()
        password = "synthetic recovery phrase only"
        ciphertext = seal(snapshot, password)
        self.assertEqual(open_checkpoint(ciphertext, password), snapshot)
        for value, phrase in ((ciphertext, "incorrect phrase"), (ciphertext[:-1] + bytes([ciphertext[-1] ^ 1]), password)):
            with self.assertRaises(ValueError):
                open_checkpoint(value, phrase)
