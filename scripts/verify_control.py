"""Real restricted-UID IPC add/revoke and access-boundary check on the test VPS."""

import argparse
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys

sys.path.insert(0, "/opt/ftm/current")
from ftm.agent import _run, NetworkAgent, reconcile
from ftm.legacy import baseline_module
from ftm.store import Store

CLIENT = """import sys,json
sys.path.insert(0,'/opt/ftm/current')
from ftm.control import request
value=json.load(sys.stdin)
try:
 result=request(value['op'],value['args'])
 print(json.dumps({'ok':True,'result':result}))
except Exception:
 print(json.dumps({'ok':False}))
 sys.exit(2)
"""


def call(operation, args=None, *, user="ftm-api", group=None, expected=True):
    argv = ["runuser", "-u", user]
    if group:
        argv += ["-g", group]
    argv += ["--", "/usr/bin/python3", "-I", "-c", CLIENT]
    result = subprocess.run(argv, input=json.dumps({"op": operation, "args": args or {}}), capture_output=True, text=True, timeout=40)
    if expected and result.returncode:
        raise RuntimeError("Authorized control operation failed")
    if not expected:
        if result.returncode == 0:
            raise RuntimeError("Unauthorized control operation succeeded")
        return None
    return json.loads(result.stdout)["result"]


def verify():
    app = baseline_module()
    state = app.load_state("main")
    conf, state_dir = app.paths("main")
    agent = NetworkAgent(state, config_dir=conf, state_dir="/var/lib/ftm-agent")
    store = Store("/var/lib/ftm/manager.sqlite3")
    before = {path: path.read_bytes() for path in (conf / "wireguard.conf", conf / "clients.json", agent.registry,
                                                state_dir / "profiles/iphone-import.txt", state_dir / "state.json")}
    pids = {name: _run(["systemctl", "show", name, "-p", "MainPID", "--value"]) for name in ("vps-vk", "ssh")}
    call("users.list", user="nobody", group="ftm-api", expected=False)
    call("shell", {"command": "id"}, expected=False)
    call("users.list", {"path": "/etc/shadow"}, expected=False)
    for path in ("/var/lib/ftm/manager.sqlite3", "/var/lib/ftm-agent/managed.json", "/etc/vps-vk/main/obf.key"):
        if subprocess.run(["runuser", "-u", "ftm-api", "--", "test", "-r", path], capture_output=True).returncode == 0:
            raise RuntimeError("API can directly read privileged data")
    device = user = None
    try:
        user = call("users.create", {"name": "IPC integration verification", "device_limit": 2})
        private = subprocess.check_output(["wg", "genkey"])
        public = subprocess.check_output(["wg", "pubkey"], input=private).decode().strip()
        args = {"user_id": user["id"], "name": "Temporary IPC peer", "platform": "other",
                "public_key": public, "request_id": secrets.token_hex(12)}
        device = call("devices.add", args)
        repeated = call("devices.add", args)
        if (device["id"] != repeated["id"] or device["apply"]["errors"] or device["state"] != "active"
                or public not in _run(["wg", "show", agent.interface, "peers"]).split()):
            raise RuntimeError("IPC peer add/idempotency failed")
        for entry in call("devices.list"):
            if set(entry) & {"cid", "preshared_key", "private_key", "wg_public_key"}:
                raise RuntimeError("IPC list disclosed device credentials")
        status = call("status")
        if not status["consistent"] or status["peers"] != 3:
            raise RuntimeError("IPC status is inconsistent")
        revoked = call("devices.set_enabled", {"id": device["id"], "enabled": False})
        if revoked["apply"]["errors"] or public in _run(["wg", "show", agent.interface, "peers"]).split():
            raise RuntimeError("IPC revoke failed")
        call("users.set_enabled", {"id": user["id"], "enabled": False})
    finally:
        if device:
            store.revoke_device(device["id"])
        if user:
            store.set_user_enabled(user["id"], False)
        if reconcile(store, agent)["errors"]:
            raise RuntimeError("Verification cleanup failed")
    if any(path.read_bytes() != data for path, data in before.items()):
        raise RuntimeError("Persistent peer config or issued profile changed after cleanup")
    if any(_run(["systemctl", "show", name, "-p", "MainPID", "--value"]) != pid for name, pid in pids.items()):
        raise RuntimeError("VPN or SSH restarted")
    return {"result": "PASS", "real_api_uid_peer_add_repeat_revoke": True,
            "other_uid_in_api_group_rejected": True, "unknown_command_and_path_fields_rejected": True,
            "api_cannot_read_sqlite_registry_or_obfuscation_key": True,
            "credential_lists_redacted": True, "profiles_config_and_service_pids_unchanged": True,
            "public_web_api_started": False}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--test-vps-apply", action="store_true")
    args = parser.parse_args()
    if not args.test_vps_apply or os.geteuid() != 0:
        parser.error("Requires root and --test-vps-apply on the agreed test VPS")
    try:
        print(json.dumps(verify(), indent=2))
    except (ValueError, RuntimeError, OSError):
        print("Control verification failed; private data withheld", file=sys.stderr)
        raise SystemExit(1)
