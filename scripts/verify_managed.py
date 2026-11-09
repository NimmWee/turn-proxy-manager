"""Adopt baseline and test inactive Android peer revoke/enable on the test VPS."""

import argparse
import fcntl
import json
import os
from pathlib import Path
import secrets
import sqlite3
import subprocess
import sys
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from ftm.agent import NetworkAgent, reconcile, _atomic
from ftm.compat import managed_status, enabled_legacy_profiles
from ftm.legacy import baseline_module
from ftm.managed import adopt_legacy
from ftm.store import Store


def verify():
    app = baseline_module()
    state = app.load_state("main")
    app.check_keypairs(state)
    conf, state_dir = app.paths("main")
    store = Store("/var/lib/ftm/manager.sqlite3")
    agent = NetworkAgent(state, config_dir=conf, state_dir="/var/lib/ftm-agent")
    before_profile = (state_dir / "profiles/iphone-import.txt").read_bytes()
    before_state = (state_dir / "state.json").read_bytes()
    before_peers = set(agent.runner(["wg", "show", agent.interface, "peers"]).split())
    if before_peers != {peer["public_key"] for peer in state["clients"].values()}:
        raise RuntimeError("Expected only the two baseline peers")
    pids = {name: app.run(["systemctl", "show", name, "-p", "MainPID", "--value"]).stdout.strip()
            for name in ("ssh", "vps-vk")}
    checkpoint = Path("/root") / ("ftm-pre-adoption-" + secrets.token_hex(6))
    checkpoint.mkdir(mode=0o700)
    store.backup(checkpoint / "metadata.sqlite3")
    saved = {conf / "wireguard.conf": (conf / "wireguard.conf").read_bytes(),
             conf / "clients.json": (conf / "clients.json").read_bytes(),
             agent.registry: agent.registry.read_bytes() if agent.registry.exists() else None}
    for i, data in enumerate(saved.values()):
        if data is not None:
            app.atomic_write(checkpoint / f"config-{i}.bin", data)
    try:
        report = adopt_legacy(store, agent)
        if adopt_legacy(store, agent)["adopted"] != 0:
            raise RuntimeError("Adoption was not idempotent")
        android = next(device for device in store.list_devices() if device["origin"] == "legacy" and device["platform"] == "android")
        store.revoke_device(android["id"])
        if reconcile(store, agent)["errors"]:
            raise RuntimeError("Legacy Android revoke failed")
        status = managed_status(state, agent._registry())
        if not status["consistent"] or status["expected_peers"] != 1:
            raise RuntimeError("Dynamic status did not accept one enabled peer")
        if set(enabled_legacy_profiles(state, agent._registry())) != {"iphone"}:
            raise RuntimeError("Revoked profile is still offered")
        store.set_device_enabled(android["id"], True)
        if reconcile(store, agent)["errors"]:
            raise RuntimeError("Legacy Android enable failed")
        user = store.create_user("FTM managed status integration")
        private = subprocess.check_output(["wg", "genkey"])
        public = subprocess.check_output(["wg", "pubkey"], input=private).decode().strip()
        device = store.create_device(user["id"], "Synthetic third device", "other", public, str(uuid.uuid4()))
        if reconcile(store, agent)["errors"]:
            raise RuntimeError("Third peer add failed")
        dynamic = managed_status(state, agent._registry())
        if not dynamic["consistent"] or dynamic["expected_peers"] != 3 or dynamic["peers"] != 3:
            raise RuntimeError("Dynamic status still assumes two peers")
        store.revoke_device(device["id"])
        if reconcile(store, agent)["errors"]:
            raise RuntimeError("Third peer cleanup failed")
        store.set_user_enabled(user["id"], False)
        if (state_dir / "profiles/iphone-import.txt").read_bytes() != before_profile or (state_dir / "state.json").read_bytes() != before_state:
            raise RuntimeError("Issued iPhone profile or baseline state changed")
        if set(agent.runner(["wg", "show", agent.interface, "peers"]).split()) != before_peers:
            raise RuntimeError("Baseline peers did not return")
        for name, previous in pids.items():
            if app.run(["systemctl", "show", name, "-p", "MainPID", "--value"]).stdout.strip() != previous:
                raise RuntimeError("Service process restarted")
        return {"result": "PASS", "adopted": report["adopted"], "android_peer_revoke_enable": True,
                "dynamic_status_one_two_three_peers": True, "revoked_profile_filtered": True,
                "iphone_profile_and_state_unchanged": True, "freeturn_and_ssh_not_restarted": True,
                "android_client_e2e_tested": False, "checkpoint": str(checkpoint)}
    except BaseException:
        for path, data in saved.items():
            if data is None:
                path.unlink(missing_ok=True)
            else:
                _atomic(path, data)
        source = sqlite3.connect(checkpoint / "metadata.sqlite3")
        target = sqlite3.connect(store.path)
        try:
            source.backup(target)
        finally:
            source.close()
            target.close()
        app.run(["wg", "syncconf", agent.interface, conf / "wireguard.conf"])
        raise


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--test-vps-apply", action="store_true")
    args = parser.parse_args()
    if not args.test_vps_apply or os.geteuid() != 0:
        parser.error("Requires root and --test-vps-apply")
    try:
        with Path("/run/lock/vps-vk.lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            print(json.dumps(verify(), indent=2))
    except BaseException as error:
        print("Managed verification failed: " + type(error).__name__ + "; details withheld", file=sys.stderr)
        raise SystemExit(1)
