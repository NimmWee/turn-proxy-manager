"""Explicit real-WG durable-queue check on the already authorized test VPS."""

import argparse
from contextlib import contextmanager
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import time

sys.path.insert(0, "/opt/ftm/current")
from ftm.agent import _run, NetworkAgent, reconcile
from ftm.control import request
from ftm.legacy import baseline_module
from ftm.store import Store


@contextmanager
def lifecycle():
    import fcntl
    fd = os.open("/run/lock/vps-vk.lock", os.O_RDWR | os.O_NOFOLLOW)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def wait_for(predicate):
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(1)
    raise RuntimeError("Scheduled reconciliation did not converge")


def verify():
    app = baseline_module()
    baseline = app.load_state("main")
    conf, directory = app.paths("main")
    agent = NetworkAgent(baseline, config_dir=conf, state_dir="/var/lib/ftm-agent")
    store = Store("/var/lib/ftm/manager.sqlite3")
    saved = {path: path.read_bytes() for path in (conf / "wireguard.conf", conf / "clients.json", agent.registry,
                                                 conf / "obf.key", directory / "state.json", directory / "profiles/iphone-import.txt")}
    pids = {service: _run(["systemctl", "show", service, "-p", "MainPID", "--value"])
            for service in ("vps-vk", "ssh")}
    original_peers = set(_run(["wg", "show", agent.interface, "peers"]).split())
    private = subprocess.check_output(["wg", "genkey"])
    public = subprocess.check_output(["wg", "pubkey"], input=private).decode().strip()
    del private
    user = device = None
    try:
        with lifecycle():
            user = store.create_user("Scheduled recovery verification", 1)
            device = store.create_device(user["id"], "Durable temporary peer", "other", public, secrets.token_hex(12))
            started = time.monotonic()
            try:
                request("users.list", timeout=2)
            except RuntimeError:
                pass
            else:
                raise RuntimeError("IPC ignored the maintenance lock")
            if time.monotonic() - started > 1.5:
                raise RuntimeError("Maintenance rejection blocked the control worker")
            # Let at least one scheduled 30-second tick encounter our lock.
            time.sleep(35)
            if public in _run(["wg", "show", agent.interface, "peers"]).split():
                raise RuntimeError("Scheduled apply ignored the maintenance lock")
        wait_for(lambda: store.get_device(device["id"])["state"] == "active")
        if set(_run(["wg", "show", agent.interface, "peers"]).split()) != original_peers | {public}:
            raise RuntimeError("Durable add changed unrelated peers")
        print("Durable add and maintenance lock: PASS", flush=True)
        with lifecycle():
            store.set_device_enabled(device["id"], False)
            with store.transaction() as db:
                db.execute("UPDATE operations SET state='applying' WHERE device_id=? AND state='pending'", (device["id"],))
        wait_for(lambda: store.get_device(device["id"])["state"] == "revoked")
        if set(_run(["wg", "show", agent.interface, "peers"]).split()) != original_peers:
            raise RuntimeError("Interrupted revoke did not converge")
        with lifecycle():
            store.set_device_enabled(device["id"], True)
            store.set_device_enabled(device["id"], False)
        wait_for(lambda: store.get_device(device["id"])["state"] == "revoked")
        with store.connect() as db:
            if not db.execute("SELECT count(*) FROM operations WHERE device_id=? AND state='cancelled'", (device["id"],)).fetchone()[0]:
                raise RuntimeError("Obsolete enable was not cancelled")
    finally:
        with lifecycle():
            if user:
                store.set_user_enabled(user["id"], False)
            if reconcile(store, agent)["errors"]:
                raise RuntimeError("Verification cleanup failed")
    if any(path.read_bytes() != data for path, data in saved.items()):
        raise RuntimeError("Original keys, config or iPhone profile changed")
    if any(_run(["systemctl", "show", service, "-p", "MainPID", "--value"]) != pid for service, pid in pids.items()):
        raise RuntimeError("VPN or SSH restarted")
    return {"result": "PASS", "scheduled_real_peer_add": True, "interrupted_applying_revoke_recovered": True,
            "obsolete_enable_cancelled": True, "maintenance_lock_respected": True,
            "original_profiles_config_and_pids_unchanged": True, "original_peers": len(original_peers)}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--test-vps-apply", action="store_true")
    args = parser.parse_args()
    if not args.test_vps_apply or os.name != "posix" or os.geteuid() != 0:
        parser.error("Requires root and --test-vps-apply on the agreed test VPS")
    try:
        result = verify()
        Path("/root/ftm-reconcile-report.json").write_text(json.dumps(result, indent=2))
        Path("/root/ftm-reconcile-report.json").chmod(0o600)
        print(json.dumps(result))
    except Exception:
        print("Scheduled recovery verification failed; private data withheld", file=sys.stderr)
        raise SystemExit(1)
