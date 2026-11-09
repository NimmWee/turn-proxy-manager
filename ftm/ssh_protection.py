"""Explicit SSH protection operation, separate from the unfinished VPN installer."""

import configparser
import datetime
import io
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import time

from .legacy import baseline_module

BANTIME = 365 * 86400
DB_RETENTION = 366 * 86400
JAIL_FILE = "zzzz-ftm-sshd.local"


def render_jail(ports):
    if not ports or any(type(port) is not int or not 1 <= port <= 65535 for port in ports):
        raise ValueError("Invalid SSH ports")
    port_list = ",".join(str(port) for port in sorted(set(ports)))
    return ("# Managed by FreeTurn Manager. Three failures in ten minutes; ban for 365 days.\n"
            "[sshd]\nenabled = true\nbackend = systemd\nfilter = sshd[mode=normal]\n"
            f"port = {port_list}\nprotocol = tcp\nbanaction = nftables-multiport\n"
            "ignoreip = 127.0.0.1/8 ::1\nusedns = no\nmaxretry = 3\nfindtime = 600\n"
            f"bantime = {BANTIME}\nbantime.increment = false\nbantime.rndtime = 0\n")


def update_daemon_config(existing):
    parser = configparser.ConfigParser(interpolation=None)
    if existing:
        parser.read_string(existing)
    if not parser.has_section("Definition"):
        parser.add_section("Definition")
    parser.set("Definition", "dbpurgeage", str(DB_RETENTION))
    parser.set("Definition", "dbfile", "/var/lib/fail2ban/fail2ban.sqlite3")
    output = io.StringIO()
    parser.write(output)
    return output.getvalue()


def _run(args):
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=60)
    except subprocess.TimeoutExpired:
        raise RuntimeError("SSH protection command timed out") from None
    if result.returncode:
        raise RuntimeError("SSH protection command failed; captured output withheld")
    return result.stdout


def configure(*, config_root=Path("/etc/fail2ban"), runner=None):
    """Apply only Fail2ban settings. Keep sshd configuration and process untouched.

    runner injection is for isolated tests; the public CLI never accepts it.
    Package installation is intentionally external to this function.
    """
    if runner is None:
        if sys.platform != "linux" or os.geteuid() != 0:
            raise ValueError("SSH protection must be applied as root on Linux")
        runner = _run
    root = Path(config_root)
    jail_dir = root / "jail.d"
    backups = root / "ftm-backups"
    targets = [jail_dir / JAIL_FILE, root / "fail2ban.local"]
    if any(path.is_symlink() for path in [root, jail_dir, backups, *targets]):
        raise ValueError("Refusing symlink in Fail2ban configuration")
    if not root.is_dir() or not jail_dir.is_dir():
        raise ValueError("Install Fail2ban before applying its policy")
    ports = [int(port) for port in re.findall(r"^port (\d+)$", runner(["/usr/sbin/sshd", "-T"]), re.MULTILINE)]
    jail_text = render_jail(ports)
    before = {path: path.read_bytes() if path.exists() else None for path in targets}
    modes = {path: path.stat().st_mode & 0o777 if path.exists() else 0o644 for path in targets}
    daemon_text = update_daemon_config(before[targets[1]].decode("utf-8") if before[targets[1]] else "")
    after = {targets[0]: jail_text.encode(), targets[1]: daemon_text.encode()}
    changed = before != after
    try:
        was_active = runner(["systemctl", "is-active", "fail2ban"]).strip() == "active"
    except RuntimeError:
        was_active = False
    try:
        was_enabled = runner(["systemctl", "is-enabled", "fail2ban"]).strip() == "enabled"
    except RuntimeError:
        was_enabled = False
    backups.mkdir(mode=0o700, exist_ok=True)
    backups.chmod(0o700)
    name = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + secrets.token_hex(4)
    backup = backups / name
    backup.mkdir(mode=0o700)
    atomic_write = baseline_module().atomic_write
    for path, data in before.items():
        if data is not None:
            atomic_write(backup / path.name, data, 0o600)
    try:
        for path, data in after.items():
            atomic_write(path, data, modes[path])
        runner(["fail2ban-client", "-t"])
        runner(["systemctl", "enable", "fail2ban"])
        if changed or not was_active:
            runner(["systemctl", "restart", "fail2ban"])
        for attempt in range(50):
            try:
                runner(["fail2ban-client", "ping"])
                break
            except RuntimeError:
                if attempt == 49:
                    raise
                time.sleep(0.1)
        if runner(["systemctl", "is-active", "fail2ban"]).strip() != "active":
            raise RuntimeError("Fail2ban is not active")
        for key, wanted in [("maxretry", 3), ("findtime", 600), ("bantime", BANTIME)]:
            if runner(["fail2ban-client", "get", "sshd", key]).strip() != str(wanted):
                raise RuntimeError("Effective SSH ban policy differs from requested policy")
        retention = runner(["fail2ban-client", "get", "dbpurgeage"]).strip()
        parsed = re.fullmatch(r"(?:Current database purge age is:\s*`-\s*)?(\d+)(?:seconds)?", retention)
        if parsed is None or int(parsed.group(1)) != DB_RETENTION:
            raise RuntimeError("Effective Fail2ban persistence retention differs")
    except Exception:
        for path, data in before.items():
            if data is None:
                path.unlink(missing_ok=True)
            else:
                atomic_write(path, data, modes[path])
        try:
            runner(["systemctl", "restart" if was_active else "stop", "fail2ban"])
            if not was_enabled:
                runner(["systemctl", "disable", "fail2ban"])
        except RuntimeError:
            pass
        raise
    return {"result": "configured", "maxretry": 3, "findtime_seconds": 600,
            "bantime_seconds": BANTIME, "db_retention_seconds": DB_RETENTION,
            "ssh_ports": sorted(set(ports)), "ssh_restarted": False, "changed": changed,
            "backup_directory": str(backup), "ban_enforcement_tested": False}
