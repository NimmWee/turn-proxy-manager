import json
from pathlib import Path
import tempfile
import unittest
import sys

from scripts.verify_baseline import verify_baseline

ROOT = Path(__file__).resolve().parents[1]


class BaselineTests(unittest.TestCase):
    @unittest.skipUnless(sys.platform == "linux", "Linux runtime smoke")
    def test_binary_starts_with_actual_baseline_wire_profile(self):
        from scripts.smoke_baseline import smoke
        self.assertEqual(smoke()["wire_profile"], "rtpopus3")

    def test_real_preserved_source_and_artifacts_match_lock(self):
        self.assertGreater(verify_baseline(ROOT), 20)

    def test_mutation_missing_file_symlink_and_escape_are_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            path = root / "vendor/vps"
            path.mkdir(parents=True)
            source = path / "test.py"
            source.write_bytes(b"original")
            import hashlib
            lock = {"schema_version": 1, "baseline_files": {"test.py": hashlib.sha256(b"original").hexdigest()}}
            (root / "upstreams.lock.json").write_text(json.dumps(lock), encoding="utf-8")
            self.assertEqual(verify_baseline(root), 1)
            source.write_bytes(b"modified")
            with self.assertRaises(ValueError):
                verify_baseline(root)
            source.unlink()
            with self.assertRaises(ValueError):
                verify_baseline(root)
            outside = root / "outside.py"
            outside.write_bytes(b"original")
            try:
                source.symlink_to(outside)
            except OSError:
                pass
            else:
                with self.assertRaises(ValueError):
                    verify_baseline(root)
                source.unlink()
            for unsafe in ["../../outside.py", "/outside.py", "C:/outside.py", "..\\outside.py"]:
                lock["baseline_files"] = {unsafe: hashlib.sha256(b"original").hexdigest()}
                (root / "upstreams.lock.json").write_text(json.dumps(lock), encoding="utf-8")
                with self.subTest(path=unsafe), self.assertRaises(ValueError):
                    verify_baseline(root)

    def test_lock_schema_and_empty_allowlist_are_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for invalid in [{}, {"schema_version": 1, "baseline_files": {}},
                            {"schema_version": True, "baseline_files": {"a": "bad"}}]:
                (root / "upstreams.lock.json").write_text(json.dumps(invalid), encoding="utf-8")
                with self.assertRaises(ValueError):
                    verify_baseline(root)
