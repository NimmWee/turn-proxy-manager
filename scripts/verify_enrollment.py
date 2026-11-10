"""Real client-held credential enrollment/retry and scheduled apply on test VPS."""

import argparse
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import time
import uuid

sys.path.insert(0, "/opt/ftm/current")
from ftm.agent import NetworkAgent, _run, reconcile
from ftm.control import request
from ftm.credentials import Credentials, _digest
from ftm.enrollment import Enrollment
from ftm.legacy import baseline_module
from ftm.store import Store
from verify_credentials import lifecycle


def verify():
    app = baseline_module()
    state = app.load_state("main")
    conf, directory = app.paths("main")
    agent = NetworkAgent(state, config_dir=conf, state_dir="/var/lib/ftm-agent")
    store = Store("/var/lib/ftm/manager.sqlite3")
    credentials, enrollment = Credentials(store), Enrollment(store)
    paths = [conf / name for name in ("wireguard.conf", "clients.json", "obf.key")]
    paths += [agent.registry, directory / "state.json", directory / "profiles/iphone-import.txt"]
    before = {path: path.read_bytes() for path in paths}
    pids = {service: _run(["systemctl", "show", service, "-p", "MainPID", "--value"])
            for service in ("vps-vk", "ssh", "ftm-api", "ftm-caddy")}
    peers = set(_run(["wg", "show", agent.interface, "peers"]).split())
    # Synthetic client's private values stay in this process, never in register().
    private_key = subprocess.check_output(["wg", "genkey"])
    public_key = subprocess.check_output(["wg", "pubkey"], input=private_key).decode().strip()
    client_token = "ftmd1_" + secrets.token_urlsafe(32)
    client_cid = secrets.token_hex(16)
    value = {"name": "Enrolled temporary peer", "platform": "android", "public_key": public_key,
             "client_id": client_cid, "device_token_hash": _digest(client_token, "device"), "request_id": str(uuid.uuid4())}
    user = None
    try:
        with lifecycle():
            user = store.create_user("Atomic enrollment verification", 1)
            user_token = credentials.issue_subscription(user["id"])["token"]
            first = enrollment.register(user_token, **value)
            retry = enrollment.register(user_token, **value)
            if first["device_id"] != retry["device_id"] or first["ip"] != retry["ip"]:
                raise RuntimeError("Enrollment retry allocated another device")
            if set(first) & {"token", "private_key", "cid", "preshared_key"}:
                raise RuntimeError("Enrollment metadata disclosed secrets")
        # Simulate a lost server response: authenticate using only the token
        # already held by the synthetic client, after the scheduled worker acts.
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline and credentials.device(client_token) is None:
            time.sleep(1)
        authenticated = credentials.device(client_token)
        if authenticated is None or authenticated["device_id"] != first["device_id"]:
            raise RuntimeError("Client-held credential did not recover after scheduled apply")
        if set(_run(["wg", "show", agent.interface, "peers"]).split()) != peers | {public_key}:
            raise RuntimeError("Enrollment did not reach the real kernel peer")
        with lifecycle():
            if store.get_device(first["device_id"])["cid"] != client_cid:
                raise RuntimeError("Enrollment changed the client-generated CID")
            new_token = credentials.issue_subscription(user["id"])["token"]
            if enrollment.register(new_token, **value)["device_id"] != first["device_id"]:
                raise RuntimeError("URL rotation changed the enrolled identity")
            if credentials.device(client_token) is None:
                raise RuntimeError("URL rotation invalidated the client credential")
        request("devices.set_enabled", {"id": first["device_id"], "enabled": False})
        if credentials.device(client_token) is not None:
            raise RuntimeError("Revoke retained an enrolled credential")
        with lifecycle():
            try:
                enrollment.register(new_token, **value)
            except ValueError:
                pass
            else:
                raise RuntimeError("A retried enrollment revived a revoked device")
            with tempfile.TemporaryDirectory(prefix="ftm-enrollment-copy-", dir="/root") as folder:
                copy = Path(folder) / "metadata.sqlite3"
                store.backup(copy)
                raw = copy.read_bytes()
                if client_token.encode() in raw or private_key.strip() in raw:
                    raise RuntimeError("Server persisted a client private value")
    finally:
        if user:
            with lifecycle():
                store.set_user_enabled(user["id"], False)
                credentials.revoke_subscription(user["id"])
                if reconcile(store, agent)["errors"]:
                    raise RuntimeError("Enrollment verification cleanup failed")
    if set(_run(["wg", "show", agent.interface, "peers"]).split()) != peers:
        raise RuntimeError("Enrollment left a temporary peer")
    if any(path.read_bytes() != data for path, data in before.items()):
        raise RuntimeError("Enrollment changed original keys/config/profile")
    if any(_run(["systemctl", "show", service, "-p", "MainPID", "--value"]) != pid for service, pid in pids.items()):
        raise RuntimeError("Enrollment restarted an existing service")
    return {"result": "PASS", "atomic_repeat_one_device": True, "client_generated_cid_preserved": True,
            "client_held_credential_after_lost_response": True, "scheduled_real_wg_apply": True,
            "url_rotation_keeps_device_identity": True, "retry_cannot_revive_revoked_device": True,
            "client_private_key_and_plaintext_token_not_in_database": True,
            "original_profiles_keys_peers_and_pids_unchanged": True, "public_enrollment_api_enabled": False}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--test-vps-apply", action="store_true")
    args = parser.parse_args()
    if not args.test_vps_apply or os.name != "posix" or os.geteuid() != 0:
        parser.error("Requires root and --test-vps-apply on the agreed test VPS")
    try:
        result = verify()
        report = Path("/root/ftm-enrollment-report.json")
        report.write_text(json.dumps(result, indent=2))
        report.chmod(0o600)
        print(json.dumps(result))
    except Exception as error:
        print("Enrollment scenario failed: " + type(error).__name__ + "; private data withheld", file=sys.stderr)
        raise SystemExit(1)
