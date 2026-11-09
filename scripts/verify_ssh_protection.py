"""Explicit integration test for the test VPS. Uses only a reserved TEST-NET IP.

This notifies Fail2ban of synthetic failures; it does not deliberately fail an
actual administrator login. The OpenSSH password-failure filter is tested separately.
"""

import argparse
import datetime
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import time

TEST_IP = "192.0.2.123"
BANTIME = 31536000


def run(*args):
    result = subprocess.run(args, capture_output=True, text=True, timeout=30)
    if result.returncode:
        raise RuntimeError("SSH protection verification command failed; output withheld")
    return result.stdout


def banned():
    return TEST_IP in run("fail2ban-client", "get", "sshd", "banip").split()


def wait_for_ban():
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        try:
            if banned() and TEST_IP in run("nft", "list", "table", "inet", "f2b-table"):
                return
        except RuntimeError:
            pass
        time.sleep(0.1)
    raise RuntimeError("Expected synthetic ban was not observed")


def verify():
    expected = {"maxretry": "3", "findtime": "600", "bantime": str(BANTIME)}
    for option, value in expected.items():
        if run("fail2ban-client", "get", "sshd", option).strip() != value:
            raise RuntimeError("Effective SSH policy does not match")
    if banned():
        raise RuntimeError("Reserved test IP is already banned; refusing to alter pre-existing state")
    # Test actual installed password-failure regex, independently of journal ingestion.
    stamp = datetime.datetime.now().strftime("%b %d %H:%M:%S")
    with tempfile.TemporaryDirectory(prefix="ftm-ssh-filter-") as folder:
        log = Path(folder) / "synthetic-auth.log"
        log.write_text("".join(f"{stamp} test sshd[12345]: Failed password for root from {TEST_IP} port {53000+i} ssh2\n"
                               for i in range(3)))
        output = run("fail2ban-regex", str(log), "sshd")
        if "3 matched" not in output:
            raise RuntimeError("Installed sshd filter did not match all three synthetic password failures")
    started = False
    try:
        for attempt in range(2):
            run("fail2ban-client", "set", "sshd", "attempt", TEST_IP, "ftm synthetic password failure")
            started = True
            time.sleep(0.2)
            if banned():
                raise RuntimeError("IP was banned before the third failure")
        run("fail2ban-client", "set", "sshd", "attempt", TEST_IP, "ftm synthetic password failure")
        wait_for_ban()
        if TEST_IP not in run("nft", "list", "table", "inet", "f2b-table"):
            raise RuntimeError("Synthetic ban is missing from nftables")
        database = sqlite3.connect("file:/var/lib/fail2ban/fail2ban.sqlite3?mode=ro", uri=True)
        try:
            row = database.execute("SELECT bantime FROM bans WHERE jail = ? AND ip = ? ORDER BY timeofban DESC LIMIT 1",
                                   ("sshd", TEST_IP)).fetchone()
            if row is None or int(row[0]) != BANTIME:
                raise RuntimeError("One-year ban not recorded in persistent database")
        finally:
            database.close()
        run("systemctl", "restart", "fail2ban")
        wait_for_ban()
        if TEST_IP not in run("nft", "list", "table", "inet", "f2b-table"):
            raise RuntimeError("Firewall ban not restored after Fail2ban restart")
    finally:
        if started:
            run("fail2ban-client", "set", "sshd", "unbanip", TEST_IP)
    if banned():
        raise RuntimeError("Synthetic test ban was not removed")
    return {"result": "PASS", "failure_threshold": 3, "findtime_seconds": 600,
            "bantime_seconds": BANTIME, "filter_password_failures_matched": 3,
            "not_banned_after_two_failures": True, "banned_after_third_failure": True,
            "nftables_enforcement": True, "database_bantime_verified": True,
            "service_restart_preserves_ban": True, "synthetic_ban_removed": True,
            "real_incorrect_password_connections_tested": False, "ssh_restarted": False}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exercise-restart", action="store_true", help="Allow synthetic ban test and Fail2ban restart")
    args = parser.parse_args()
    if not args.exercise_restart or sys.platform != "linux" or os.geteuid() != 0:
        parser.error("Requires root on Linux and explicit --exercise-restart; use only on the test VPS")
    try:
        print(json.dumps(verify(), indent=2))
    except (RuntimeError, OSError, sqlite3.Error, subprocess.TimeoutExpired) as error:
        print("FAIL: " + type(error).__name__ + ": " + str(error), file=sys.stderr)
        raise SystemExit(1)
