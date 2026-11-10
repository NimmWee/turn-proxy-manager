"""Real temporary-peer credential lifecycle verification on the test VPS."""

import argparse
from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile

sys.path.insert(0, "/opt/ftm/current")
from ftm.agent import NetworkAgent, _run, reconcile
from ftm.control import request
from ftm.credentials import Credentials
from ftm.legacy import baseline_module
from ftm.store import Store


@contextmanager
def lifecycle():
    fd = os.open("/run/lock/vps-vk.lock", os.O_RDWR | os.O_NOFOLLOW)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def verify():
    app = baseline_module()
    baseline = app.load_state("main")
    conf, directory = app.paths("main")
    agent = NetworkAgent(baseline, config_dir=conf, state_dir="/var/lib/ftm-agent")
    store = Store("/var/lib/ftm/manager.sqlite3")
    credentials = Credentials(store)
    paths = [conf / name for name in ("wireguard.conf", "clients.json", "obf.key")]
    paths += [agent.registry, directory / "state.json", directory / "profiles/iphone-import.txt"]
    before = {path: path.read_bytes() for path in paths}
    pids = {service: _run(["systemctl", "show", service, "-p", "MainPID", "--value"]) for service in ("vps-vk", "ssh", "ftm-api", "ftm-caddy")}
    initial_peers = set(_run(["wg", "show", agent.interface, "peers"]).split())
    tokens = []
    user = device = None
    try:
        with lifecycle():
            user = store.create_user("Credential lifecycle verification", 1)
            private = subprocess.check_output(["wg", "genkey"])
            public = subprocess.check_output(["wg", "pubkey"], input=private).decode().strip()
            del private
            device = store.create_device(user["id"], "Credential temporary peer", "android", public, secrets.token_hex(12))
            if reconcile(store, agent)["errors"]:
                raise RuntimeError("Temporary peer could not be applied")
            active_config = {path: path.read_bytes() for path in paths}
            first = credentials.issue_subscription(user["id"])
            access = credentials.issue_device(device["id"])
            second = credentials.issue_subscription(user["id"])
            tokens += [first["token"], access["token"], second["token"]]
            if (credentials.subscription(first["token"]) is not None or credentials.subscription(second["token"]) is None
                    or credentials.device(access["token"]) is None or first["id"] != second["id"]):
                raise RuntimeError("User-link rotation affected device access")
            credentials.revoke_subscription(user["id"])
            if credentials.subscription(second["token"]) is not None or credentials.device(access["token"]) is None:
                raise RuntimeError("URL revoke affected registered device access")
            if any(path.read_bytes() != data for path, data in active_config.items()):
                raise RuntimeError("Credential rotation changed WG/CID/profile data")
        with tempfile.TemporaryDirectory(prefix="ftm-credential-qa-", dir="/root") as folder:
            output = Path(folder) / "device-access.json"
            argv = ["/usr/bin/python3", "-I", "-c",
                    "import runpy,sys;sys.path.insert(0,'/opt/ftm/current');runpy.run_module('ftm.credentials',run_name='__main__')",
                    "device-access", "issue", "--id", device["id"], "--output", str(output)]
            cli = subprocess.run(argv, capture_output=True, text=True, timeout=30)
            if cli.returncode:
                raise RuntimeError("Root credential CLI failed")
            value = json.loads(output.read_bytes())
            tokens.append(value["token"])
            if (output.stat().st_mode & 0o777 != 0o600 or output.stat().st_uid != 0
                    or value["token"] in cli.stdout or value["token"] in cli.stderr
                    or credentials.device(value["token"]) is None):
                raise RuntimeError("Root CLI credential delivery is unsafe")
            repeated = subprocess.run(argv, capture_output=True, text=True, timeout=30)
            if repeated.returncode == 0 or credentials.device(value["token"]) is None:
                raise RuntimeError("Existing output was overwritten or rotated")
            revoked = request("devices.set_enabled", {"id": device["id"], "enabled": False})
            if revoked["apply"]["errors"] or credentials.device(value["token"]) is not None:
                raise RuntimeError("Control revoke retained a device credential")
            request("devices.set_enabled", {"id": device["id"], "enabled": True})
            if credentials.device(value["token"]) is not None:
                raise RuntimeError("Enable revived a revoked credential")
            with lifecycle():
                fresh = credentials.issue_device(device["id"])
                tokens.append(fresh["token"])
            request("users.set_enabled", {"id": user["id"], "enabled": False})
            if credentials.device(fresh["token"]) is not None:
                raise RuntimeError("User disable retained device credentials")
            copy = Path(folder) / "metadata.sqlite3"
            store.backup(copy)
            if any(token.encode() in copy.read_bytes() for token in tokens):
                raise RuntimeError("SQLite persisted a plaintext token")
    finally:
        if user:
            with lifecycle():
                store.set_user_enabled(user["id"], False)
                with store.connect() as db:
                    has_subscription = db.execute("SELECT 1 FROM subscriptions WHERE user_id=?", (user["id"],)).fetchone()
                if has_subscription:
                    credentials.revoke_subscription(user["id"])
                if reconcile(store, agent)["errors"]:
                    raise RuntimeError("Credential verification cleanup failed")
    if (set(_run(["wg", "show", agent.interface, "peers"]).split()) != initial_peers
            or any(path.read_bytes() != data for path, data in before.items())):
        raise RuntimeError("Credential verification changed original peers/profile")
    if any(_run(["systemctl", "show", service, "-p", "MainPID", "--value"]) != pid for service, pid in pids.items()):
        raise RuntimeError("Credential verification restarted a service")
    return {"result": "PASS", "real_peer_preserved_during_url_rotation": True,
            "user_url_revoke_keeps_device_access": True, "control_revoke_and_enable_does_not_revive_token": True,
            "user_disable_revokes_device_tokens": True, "root_cli_new_private_file_only": True,
            "database_contains_hashes_not_plaintext": True, "original_profiles_keys_peers_and_pids_unchanged": True,
            "client_subscription_e2e_tested": False}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--test-vps-apply", action="store_true")
    args = parser.parse_args()
    if not args.test_vps_apply or os.name != "posix" or os.geteuid() != 0:
        parser.error("Requires root and --test-vps-apply on the agreed test VPS")
    try:
        result = verify()
        report = Path("/root/ftm-credentials-report.json")
        report.write_text(json.dumps(result, indent=2))
        report.chmod(0o600)
        print(json.dumps(result))
    except Exception as error:
        print("Credential scenario failed: " + type(error).__name__ + "; private data withheld", file=sys.stderr)
        raise SystemExit(1)
