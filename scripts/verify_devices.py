"""Explicit test-VPS integration for metadata import and hot peer add/revoke."""

import argparse
import fcntl
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from ftm.agent import NetworkAgent, reconcile, _atomic
from ftm.legacy import baseline_module
from ftm.store import Store


def public_key():
    private = subprocess.check_output(["wg", "genkey"])
    return subprocess.check_output(["wg", "pubkey"], input=private).decode().strip()


def verify():
    app = baseline_module()
    state = app.load_state("main")
    app.check_keypairs(state)
    conf, state_dir = app.paths("main")
    baseline_bytes = (state_dir / "state.json").read_bytes()
    profile_bytes = (state_dir / "profiles/iphone-import.txt").read_bytes()
    config_bytes = (conf / "wireguard.conf").read_bytes()
    clients_bytes = (conf / "clients.json").read_bytes()
    interface = app.iface(state)
    def peers():
        return set(app.run(["wg", "show", interface, "peers"]).stdout.split())
    original_peers = peers()
    if original_peers != {peer["public_key"] for peer in state["clients"].values()}:
        raise RuntimeError("Unexpected live peers; refusing isolated integration test")
    service_pid = app.run(["systemctl", "show", "vps-vk", "-p", "MainPID", "--value"]).stdout.strip()
    ssh_pid = app.run(["systemctl", "show", "ssh", "-p", "MainPID", "--value"]).stdout.strip()
    store = Store("/var/lib/ftm/manager.sqlite3")
    store.initialize()
    imported = store.import_legacy(state)
    if store.import_legacy(state)["imported_devices"]:
        raise RuntimeError("Legacy import was not idempotent")
    agent = NetworkAgent(state, config_dir=conf, state_dir="/var/lib/ftm-agent")
    user = store.create_user("FTM synthetic integration")
    device = store.create_device(user["id"], "Synthetic WG peer", "other", public_key(), str(uuid.uuid4()))
    unknown = public_key()
    unknown_added = sentinel_added = namespace_created = False
    sentinel = secrets.token_hex(16)
    try:
        report = reconcile(store, agent)
        if report["errors"] or device["wg_public_key"] not in peers() or len(peers()) != 3:
            raise RuntimeError("New peer was not hot-applied")
        if device["cid"] not in json.loads((conf / "clients.json").read_text())["clients"]:
            raise RuntimeError("Device CID missing")
        # Replay the exact persistent configuration in an isolated network namespace.
        # No host route/interface restart and no externally reachable duplicate WG socket.
        namespace = "ftm-verify"
        if namespace in [line.split()[0] for line in app.run(["ip", "netns", "list"]).stdout.splitlines()]:
            raise RuntimeError("Test namespace already exists")
        app.run(["ip", "netns", "add", namespace])
        namespace_created = True
        app.run(["ip", "-n", namespace, "link", "add", "dev", "ftmcheck0", "type", "wireguard"])
        app.run(["ip", "netns", "exec", namespace, "wg", "setconf", "ftmcheck0", conf / "wireguard.conf"])
        if len(app.run(["ip", "netns", "exec", namespace, "wg", "show", "ftmcheck0", "peers"]).stdout.split()) != 3:
            raise RuntimeError("Persisted configuration could not be replayed")
        app.run(["ip", "netns", "delete", namespace])
        namespace_created = False
        # Ownership sentinel: the agent must retain peers/CIDs it does not own.
        app.run(["wg", "set", interface, "peer", unknown, "allowed-ips", str(agent.subnet.network_address + 200) + "/32"])
        unknown_added = True
        clients = json.loads((conf / "clients.json").read_text())
        clients["clients"][sentinel] = {"comment": "FTM integration ownership sentinel"}
        _atomic(conf / "clients.json", json.dumps(clients))
        sentinel_added = True
        store.revoke_device(device["id"])
        report = reconcile(store, agent)
        if report["errors"] or device["wg_public_key"] in peers() or unknown not in peers():
            raise RuntimeError("Revocation failed or removed an unknown peer")
        if sentinel not in json.loads((conf / "clients.json").read_text())["clients"]:
            raise RuntimeError("Revocation removed an unknown CID")
    finally:
        store.revoke_device(device["id"])
        reconcile(store, agent)
        if namespace_created:
            app.run(["ip", "netns", "delete", "ftm-verify"], check=False)
        if unknown_added:
            app.run(["wg", "set", interface, "peer", unknown, "remove"])
        if sentinel_added:
            clients = json.loads((conf / "clients.json").read_text())
            if clients["clients"].get(sentinel) == {"comment": "FTM integration ownership sentinel"}:
                clients["clients"].pop(sentinel)
                _atomic(conf / "clients.json", json.dumps(clients))
        store.set_user_enabled(user["id"], False)
    if peers() != original_peers or (state_dir / "state.json").read_bytes() != baseline_bytes:
        raise RuntimeError("Baseline state or peers changed")
    if (state_dir / "profiles/iphone-import.txt").read_bytes() != profile_bytes:
        raise RuntimeError("Issued iPhone profile changed")
    if (conf / "wireguard.conf").read_bytes() != config_bytes or (conf / "clients.json").read_bytes() != clients_bytes:
        raise RuntimeError("Network config did not return to its original content")
    if app.run(["systemctl", "show", "vps-vk", "-p", "MainPID", "--value"]).stdout.strip() != service_pid:
        raise RuntimeError("FreeTurn process restarted during hot device operation")
    if app.run(["systemctl", "show", "ssh", "-p", "MainPID", "--value"]).stdout.strip() != ssh_pid:
        raise RuntimeError("SSH process changed")
    with store.connect() as db:
        if db.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise RuntimeError("Database integrity failed")
    return {"result": "PASS", "legacy_import": imported["imported_devices"],
            "legacy_import_idempotent": True, "new_peer_hot_added": True, "new_peer_revoked": True,
            "persisted_config_replayed_in_network_namespace": True,
            "unknown_peer_and_cid_preserved": True, "baseline_and_profile_unchanged": True,
            "freeturn_and_ssh_pids_unchanged": True, "database_integrity": "ok",
            "three_real_client_connections_tested": False, "cid_live_authorization_tested": False}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--test-vps-apply", action="store_true")
    args = parser.parse_args()
    if not args.test_vps_apply or os.geteuid() != 0:
        parser.error("Requires explicit --test-vps-apply and root on the test VPS")
    try:
        with Path("/run/lock/vps-vk.lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            print(json.dumps(verify(), indent=2))
    except BaseException as error:
        print("Device verification failed: " + type(error).__name__ + "; details withheld", file=sys.stderr)
        raise SystemExit(1)
