import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from tests.fixtures import legacy_state
from tests.test_installer import config
from ftm.cli import main, wizard
from unittest.mock import patch
import contextlib
import io

ROOT = Path(__file__).resolve().parents[1]


def cli(*args, input=""):
    return subprocess.run([sys.executable, "-m", "ftm", *args], cwd=ROOT,
                          input=input, capture_output=True, text=True, encoding="utf-8", timeout=10,
                          env={**os.environ, "PYTHONUTF8": "1"})


class CliTests(unittest.TestCase):
    def test_help_and_invalid_command(self):
        self.assertEqual(cli("--help").returncode, 0)
        self.assertNotEqual(cli("uninstall").returncode, 0)

    def test_noninteractive_requires_config(self):
        result = cli("install", "--non-interactive", "--dry-run")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("Traceback", result.stderr)

    def test_config_dry_run_and_apply_refusal(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "config.json"
            path.write_text(json.dumps(config()), encoding="utf-8")
            path.chmod(0o600)
            original = path.read_bytes()
            result = cli("install", "--manager", "--non-interactive", "--config", str(path), "--dry-run")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(json.loads(result.stdout)["changes_system"])
            self.assertEqual(path.read_bytes(), original)
            result = cli("install", "--non-interactive", "--config", str(path))
            self.assertEqual(result.returncode, 3)
            self.assertNotIn("Traceback", result.stderr)
            self.assertEqual(path.read_bytes(), original)

    def test_inspection_sanitizes_output_and_does_not_rewrite_state(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "state.json"
            state = legacy_state()
            path.write_text(json.dumps(state), encoding="utf-8")
            path.chmod(0o600)
            original = path.read_bytes()
            result = cli("inspect", "--state", str(path))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)["device_count"], 2)
            for secret in [state["vk_link"], state["obf_key"], state["server_private"], state["clients"]["iphone"]["cid"]]:
                self.assertNotIn(secret, result.stdout + result.stderr)
            self.assertEqual(path.read_bytes(), original)

    def test_invalid_files_never_echo_contents(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "config.json"
            path.write_text('{"SECRET-DO-NOT-PRINT":', encoding="utf-8")
            path.chmod(0o600)
            result = cli("install", "--config", str(path), "--dry-run")
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn("SECRET-DO-NOT-PRINT", result.stdout + result.stderr)
            self.assertNotIn("Traceback", result.stderr)

    def test_non_tty_without_config_fails_instead_of_hanging(self):
        result = cli("install", "--dry-run")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("Traceback", result.stderr)

    @unittest.skipUnless(sys.platform == "linux", "Linux host inventory")
    def test_preflight_reports_real_host_without_claiming_installation_ready(self):
        result = cli("preflight")
        self.assertIn(result.returncode, (0, 2), result.stderr)
        report = json.loads(result.stdout)
        self.assertFalse(report["changes_system"])
        self.assertFalse(report["installation_ready"])
        self.assertIsInstance(report["facts"]["disk_free_bytes"], int)

    def test_wizard_domain_ip_migration_and_cancel(self):
        for replies, has_state, expected in [
            (["", "", "vpn.example.org", ""], False, ("fresh", "domain", "public")),
            (["", "2", "93.184.216.34", ""], False, ("fresh", "ip", "private")),
            (["", "", "vpn.example.org", "2"], True, ("migrate", "domain", "private")),
        ]:
            answers = iter(replies)
            result = wizard(input_fn=lambda _: next(answers), output_fn=lambda _: None, has_state=has_state)
            self.assertEqual((result["mode"], result["web_mode"], result["panel_access"]), expected)
        for replies in [["4"], ["1", "3"], ["1", "1", "vpn.example.org", "3"]]:
            answers = iter(replies)
            with self.assertRaises(ValueError):
                wizard(input_fn=lambda _: next(answers), output_fn=lambda _: None)

    def test_wizard_eof_and_interrupt_exit_without_traceback(self):
        for error in [EOFError, KeyboardInterrupt]:
            with patch("sys.stdin.isatty", return_value=True), patch("ftm.cli.wizard", side_effect=error), \
                 contextlib.redirect_stderr(io.StringIO()) as output:
                self.assertEqual(main(["install", "--dry-run"]), 130)
                self.assertNotIn("Traceback", output.getvalue())

    @unittest.skipUnless(os.name == "posix", "POSIX pseudo terminal")
    def test_real_terminal_wizard_needs_no_domain_flag(self):
        import pty
        master, slave = pty.openpty()
        try:
            process = subprocess.Popen([sys.executable, "-m", "ftm", "install", "--dry-run"],
                                       cwd=ROOT, stdin=slave, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       text=True, encoding="utf-8", env={**os.environ, "PYTHONUTF8": "1"})
            try:
                os.write(master, b"\n\nvpn.example.org\n\n\n")
                stdout, stderr = process.communicate(timeout=10)
                self.assertEqual(process.returncode, 0, stderr)
                self.assertIn('"changes_system": false', stdout)
                self.assertIn('"web_host": "vpn.example.org"', stdout)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=5)
        finally:
            os.close(master)
            os.close(slave)
