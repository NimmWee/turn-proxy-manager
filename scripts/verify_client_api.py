"""Real HTTPS/IPC/kernel-peer contract check; not a native VPN-client E2E."""

import argparse
import hashlib
import http.cookiejar
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid

sys.path.insert(0, "/opt/ftm/current")
from ftm.agent import NetworkAgent, _run, reconcile
from ftm.control import request
from ftm.credentials import Credentials
from ftm.installer import read_private_json
from ftm.legacy import baseline_module
from ftm.profile_codec import decode
from ftm.reference_client import ReferenceClient, ClientSyncError
from ftm.store import Store
from verify_credentials import lifecycle


def verify():
    app = baseline_module()
    baseline = app.load_state("main")
    conf, _ = app.paths("main")
    agent = NetworkAgent(baseline, config_dir=conf, state_dir="/var/lib/ftm-agent")
    store, credentials = Store("/var/lib/ftm/manager.sqlite3"), None
    credentials = Credentials(store)
    before = read_private_json("/root/ftm-client-api-before.json")
    original_peers = set(_run(["wg", "show", agent.interface, "peers"]).split())
    origin = "https://" + baseline["endpoint"]
    note = read_private_json("/root/ftm-web-login.json")
    clients, requests = [], []
    user = None
    try:
        with lifecycle():
            user = store.create_user("HTTPS client API verification", 2)
            link = credentials.issue_subscription(user["id"])["token"]
        for index in range(2):
            private = subprocess.check_output(["wg", "genkey"]).decode().strip()
            public = subprocess.check_output(["wg", "pubkey"], input=private.encode()).decode().strip()
            client = ReferenceClient(origin, private_key=private, public_key=public,
                                     device_token="ftmd1_" + secrets.token_urlsafe(32), client_id=secrets.token_hex(16))
            identifier = str(uuid.uuid4())
            value = client.enroll(link, name="HTTPS temporary client " + str(index + 1), platform="android", request_id=identifier)
            repeat = client.enroll(link, name="HTTPS temporary client " + str(index + 1), platform="android", request_id=identifier)
            if value["device_id"] != repeat["device_id"] or value["ip"] != repeat["ip"]:
                raise RuntimeError("HTTPS enrollment retry allocated another device")
            clients.append(client)
            requests.append(value)
        deadline = time.monotonic() + 50
        while time.monotonic() < deadline:
            if all(client.status()["ready"] for client in clients):
                break
            time.sleep(5)
        else:
            raise RuntimeError("Scheduled apply did not complete")
        for client in clients:
            if not client.refresh() or client.state != "MANAGED":
                raise RuntimeError("Managed config was not delivered")
            share = decode(client.last_share)
            if (share["cid"] != client.client_id or client.private_key not in share["wg"]
                    or "private_key" in json.dumps(client.last_good) or "PrivateKey" in json.dumps(client.last_good)):
                raise RuntimeError("Client/server private-key ownership changed")
            if client.refresh():
                raise RuntimeError("Unchanged configuration did not return304")
        if (clients[0].last_good["device_id"] == clients[1].last_good["device_id"]
                or clients[0].last_good["wireguard"]["preshared_key"] == clients[1].last_good["wireguard"]["preshared_key"]
                or clients[0].last_good["wireguard"]["addresses"] == clients[1].last_good["wireguard"]["addresses"]):
            raise RuntimeError("Two devices received shared identities")
        if len(_run(["wg", "show", agent.interface, "peers"]).split()) != len(original_peers) + 2:
            raise RuntimeError("HTTPS enrollments did not reach kernel peers")
        etags = [client.etag for client in clients]
        with lifecycle():
            credentials.issue_subscription(user["id"])
        for index, client in enumerate(clients):
            if client.refresh() or client.etag != etags[index]:
                raise RuntimeError("User-link rotation changed a registered device")
        saved_share = clients[0].last_share
        request("devices.set_enabled", {"id": requests[0]["device_id"], "enabled": False})
        try:
            clients[0].refresh()
        except ClientSyncError as error:
            if error.status != 403 or clients[0].state != "REVOKED" or clients[0].last_share != saved_share:
                raise RuntimeError("Conditional request ignored revocation") from None
        else:
            raise RuntimeError("Revoked device retained config access")
        if clients[1].refresh():
            raise RuntimeError("Other device config unexpectedly changed")
        # A real admin cookie must not authorize the native client API.
        jar = http.cookiejar.CookieJar()
        admin = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
        base = origin + note["panel_path"] + "api"
        login = admin.open(urllib.request.Request(base + "/auth/login", data=json.dumps({"username": note["username"], "password": note["password"]}).encode(),
                          headers={"Content-Type": "application/json", "Origin": origin}), timeout=15)
        csrf = json.loads(login.read())["csrf"]
        cookie = next(cookie.value for cookie in jar if cookie.name == "ftm_session")
        try:
            admin.open(urllib.request.Request(origin + "/api/client/v1/subscription", headers={"Cookie": "ftm_session=" + cookie}), timeout=15)
        except urllib.error.HTTPError as error:
            if error.code != 401:
                raise RuntimeError("Admin cookie bypassed device authentication") from None
        else:
            raise RuntimeError("Admin cookie authorized device configuration")
        admin.open(urllib.request.Request(base + "/auth/logout", data=b"{}", headers={"Content-Type": "application/json", "Origin": origin, "X-CSRF-Token": csrf}), timeout=15).read()
        logs = _run(["journalctl", "-u", "ftm-api", "-u", "ftm-control", "-u", "ftm-caddy", "--since", "10 minutes ago", "--no-pager", "-o", "cat"])
        sensitive = [link, note["password"], baseline["vk_link"], baseline["obf_key"]]
        sensitive += [value for client in clients for value in (client.token, client.private_key, client.client_id)]
        if any(value in logs for value in sensitive):
            raise RuntimeError("Service journal disclosed a private value")
    finally:
        if user:
            with lifecycle():
                store.set_user_enabled(user["id"], False)
                credentials.revoke_subscription(user["id"])
                if reconcile(store, agent)["errors"]:
                    raise RuntimeError("Client API verification cleanup failed")
    if set(_run(["wg", "show", agent.interface, "peers"]).split()) != original_peers:
        raise RuntimeError("Temporary client peer was not revoked")
    if any(hashlib.sha256(Path(path).read_bytes()).hexdigest() != digest for path, digest in before["hashes"].items()):
        raise RuntimeError("Existing configuration or iPhone profile changed")
    if any(_run(["systemctl", "show", name, "-p", "MainPID", "--value"]).strip() != pid for name, pid in before["pids"].items()):
        raise RuntimeError("VPN or SSH restarted")
    return {"result": "PASS", "real_https_enroll_repeat_two_devices": True, "scheduled_real_kernel_apply": True,
            "per_device_keys_ips_cids": True, "private_key_only_in_reference_client": True,
            "conditional304_and_user_rotation_stability": True, "revoke_precedes304": True,
            "admin_cookie_not_device_auth": True, "journals_do_not_contain_private_values": True,
            "original_profile_config_peers_vpn_ssh_pids_preserved": True, "native_vpn_client_e2e_tested": False}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--test-vps-apply", action="store_true")
    args = parser.parse_args()
    if not args.test_vps_apply or os.name != "posix" or os.geteuid() != 0:
        parser.error("Requires root and --test-vps-apply on the agreed test VPS")
    try:
        result = verify()
        report = Path("/root/ftm-client-api-report.json")
        report.write_text(json.dumps(result, indent=2))
        report.chmod(0o600)
        print(json.dumps(result))
    except Exception as error:
        print("Client API verification failed: " + type(error).__name__ + "; private data withheld", file=sys.stderr)
        raise SystemExit(1)
