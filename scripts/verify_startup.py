"""Exercise pending managed operations on copied state in an isolated netns."""

import argparse
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ftm.agent import NetworkAgent
from ftm.legacy import baseline_module
from ftm.startup import prepare_startup
from ftm.store import Store


def run(args, **kwargs):
    result = subprocess.run(args, capture_output=True, timeout=30, **kwargs)
    if result.returncode:
        raise RuntimeError("Isolated network operation failed; details withheld")
    return result.stdout


def verify():
    app = baseline_module()
    state = app.load_state("main")
    conf, state_dir = app.paths("main")
    originals = {p: p.read_bytes() for p in (conf / "wireguard.conf", conf / "clients.json",
                    state_dir / "profiles/iphone-import.txt", Path("/var/lib/ftm-agent/managed.json"))}
    pids = {n: run(["systemctl", "show", n, "-p", "MainPID", "--value"]) for n in ("ssh", "vps-vk")}
    namespace = "ftm-boot-" + secrets.token_hex(4)
    with tempfile.TemporaryDirectory(prefix="ftm-startup-", dir="/root") as folder:
        root = Path(folder)
        copied_conf, copied_agent = root / "conf", root / "agent"
        copied_conf.mkdir(mode=0o700)
        copied_agent.mkdir(mode=0o700)
        for source, data in originals.items():
            if source.name in ("wireguard.conf", "clients.json", "managed.json"):
                target = (copied_agent if source.name == "managed.json" else copied_conf) / source.name
                target.write_bytes(data)
                target.chmod(0o600)
        store = Store(root / "db/metadata.sqlite3")
        store.path.parent.mkdir(mode=0o700)
        Store("/var/lib/ftm/manager.sqlite3").backup(store.path)
        agent = NetworkAgent(state, config_dir=copied_conf, state_dir=copied_agent, offline=True)
        android = store.get_device(next(d["id"] for d in store.list_devices() if d["platform"] == "android" and d["origin"] == "legacy"))
        phone_public = state["clients"]["iphone"]["public_key"]
        created = False
        try:
            run(["ip", "netns", "add", namespace])
            created = True
            run(["ip", "-n", namespace, "link", "add", "ftmboot0", "type", "wireguard"])

            def load_expected(expected):
                run(["ip", "netns", "exec", namespace, "wg", "setconf", "ftmboot0", str(copied_conf / "wireguard.conf")])
                actual = set(run(["ip", "netns", "exec", namespace, "wg", "show", "ftmboot0", "peers"]).decode().split())
                if actual != expected:
                    raise RuntimeError("Isolated startup loaded unexpected access")

            store.revoke_device(android["id"])
            prepare_startup(store, agent)
            load_expected({phone_public})
            store.set_device_enabled(android["id"], True)
            user = store.create_user("Copied startup test")
            private = run(["wg", "genkey"])
            public = run(["wg", "pubkey"], input=private).decode().strip()
            device = store.create_device(user["id"], "Copied pending peer", "other", public, "isolated-startup")
            prepare_startup(store, agent)
            load_expected({phone_public, android["wg_public_key"], public})
            store.revoke_device(device["id"])
            prepare_startup(store, agent)
            load_expected({phone_public, android["wg_public_key"]})
        finally:
            if created:
                run(["ip", "netns", "del", namespace])
    if any(p.read_bytes() != data for p, data in originals.items()):
        raise RuntimeError("Live host files changed")
    if any(run(["systemctl", "show", n, "-p", "MainPID", "--value"]) != pid for n, pid in pids.items()):
        raise RuntimeError("Host service restarted")
    return {"result": "PASS", "pending_revoke_add_reenable_replayed": True,
            "kernel_namespace_loaded_one_three_two_peers": True,
            "live_configuration_and_profiles_unchanged": True,
            "ssh_and_freeturn_not_restarted": True, "host_reboot_tested": False}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--test-vps", action="store_true")
    args = parser.parse_args()
    if not args.test_vps or os.geteuid() != 0:
        parser.error("Requires root on the agreed test VPS and --test-vps")
    import fcntl
    try:
        with Path("/run/lock/vps-vk.lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            print(json.dumps(verify(), indent=2))
    except (ValueError, RuntimeError, OSError):
        print("Isolated startup verification failed; private data withheld", file=sys.stderr)
        raise SystemExit(1)
