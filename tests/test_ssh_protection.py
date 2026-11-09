import configparser
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from ftm.ssh_protection import BANTIME, DB_RETENTION, render_jail, update_daemon_config, configure


class SshProtectionTests(unittest.TestCase):
    def test_three_failures_ten_minutes_one_year_and_ssh_ports(self):
        parser = configparser.ConfigParser(interpolation=None)
        parser.read_string(render_jail([2222, 22, 2222]))
        jail = parser["sshd"]
        self.assertEqual(jail.getint("maxretry"), 3)
        self.assertEqual(jail.getint("findtime"), 600)
        self.assertEqual(jail.getint("bantime"), 365 * 86400)
        self.assertFalse(jail.getboolean("bantime.increment"))
        self.assertEqual(jail.getint("bantime.rndtime"), 0)
        self.assertEqual(jail["port"], "22,2222")
        self.assertEqual(jail["backend"], "systemd")
        self.assertEqual(jail["ignoreip"], "127.0.0.1/8 ::1")
        self.assertEqual(jail["banaction"], "nftables-multiport")

    def test_bad_ports_are_rejected(self):
        for ports in [[], [True], ["22"], [0], [65536], ["22; reboot"]]:
            with self.subTest(ports=ports), self.assertRaises(ValueError):
                render_jail(ports)

    def test_persistence_retention_exceeds_ban_and_preserves_other_settings(self):
        text = update_daemon_config("[Definition]\nloglevel = WARNING\ndbpurgeage = 1d\n")
        parser = configparser.ConfigParser(interpolation=None)
        parser.read_string(text)
        self.assertGreater(parser.getint("Definition", "dbpurgeage"), BANTIME)
        self.assertEqual(parser["Definition"]["loglevel"], "WARNING")
        self.assertEqual(parser["Definition"]["dbfile"], "/var/lib/fail2ban/fail2ban.sqlite3")
        self.assertEqual(DB_RETENTION, 366 * 86400)

    def test_configure_checks_effective_policy_and_does_not_restart_ssh(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "jail.d").mkdir()
            commands = []

            def run(args):
                commands.append(args)
                if args[:2] == ["/usr/sbin/sshd", "-T"]:
                    return "port 22\nport 2222\n"
                if args[:3] == ["fail2ban-client", "get", "sshd"]:
                    return {"maxretry": "3", "findtime": "600", "bantime": str(BANTIME)}[args[3]]
                if args == ["fail2ban-client", "get", "dbpurgeage"]:
                    return f"Current database purge age is:\n`- {DB_RETENTION}seconds\n"
                if args[:2] == ["systemctl", "is-active"]:
                    return "active\n"
                return "Server replied: pong\n"

            report = configure(config_root=root, runner=run)
            self.assertEqual(report["bantime_seconds"], BANTIME)
            self.assertEqual(report["ssh_ports"], [22, 2222])
            self.assertTrue((root / "jail.d/zzzz-ftm-sshd.local").exists())
            self.assertNotIn(["systemctl", "restart", "ssh"], commands)
            self.assertNotIn(["systemctl", "restart", "sshd"], commands)

    def test_invalid_or_ineffective_configuration_restores_original_files(self):
        for fail_on in ["validation", "effective_policy"]:
            with tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                (root / "jail.d").mkdir()
                jail = root / "jail.d/zzzz-ftm-sshd.local"
                daemon = root / "fail2ban.local"
                jail.write_bytes(b"# original jail\n")
                daemon.write_bytes(b"[Definition]\nloglevel = WARNING\n")
                jail.chmod(0o600)
                daemon.chmod(0o600)
                originals = {file: file.read_bytes() for file in (jail, daemon)}
                original_modes = {file: file.stat().st_mode & 0o777 for file in originals}

                def run(args):
                    if args[:2] == ["/usr/sbin/sshd", "-T"]:
                        return "port 22\n"
                    if fail_on == "validation" and args == ["fail2ban-client", "-t"]:
                        raise RuntimeError("invalid configuration")
                    if args[:3] == ["fail2ban-client", "get", "sshd"]:
                        return "5"
                    return "active\n"

                with self.assertRaises(RuntimeError):
                    configure(config_root=root, runner=run)
                for file, original in originals.items():
                    self.assertEqual(file.read_bytes(), original)
                    self.assertEqual(file.stat().st_mode & 0o777, original_modes[file])
                self.assertTrue(list((root / "ftm-backups").iterdir()))

    def test_configure_refuses_symlink_target(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "jail.d").mkdir()
            target = root / "target"
            target.write_text("original")
            try:
                (root / "jail.d/zzzz-ftm-sshd.local").symlink_to(target)
            except OSError:
                self.skipTest("symlink unavailable")
            with self.assertRaises(ValueError):
                configure(config_root=root, runner=lambda args: "port 22\n")
            self.assertEqual(target.read_text(), "original")
