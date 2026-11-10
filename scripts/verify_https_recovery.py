"""Exercise real private/public checkpoint transitions and edge rollback."""

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import urllib.error
import urllib.request

sys.path.insert(0, "/opt/ftm/current")
from ftm.agent import NetworkAgent, _run
from ftm.checkpoint import _read_encrypted, capture_live, open_checkpoint, stage, restore_same_host
from ftm.compat import managed_status
from ftm.https_probe import trusted_certificate
from ftm.installer import read_private_json
from ftm.legacy import baseline_module
from ftm.store import Store


def verify(args):
    app = baseline_module()
    state = app.load_state("main")
    conf, directory = app.paths("main")
    agent = NetworkAgent(state, config_dir=conf, state_dir="/var/lib/ftm-agent")
    store = Store("/var/lib/ftm/manager.sqlite3")
    phrase = Path("/root/ftm-test-backup.pass").read_text().strip()
    snapshots = {}
    for name in ("private", "public"):
        raw = _read_encrypted(getattr(args, name + "_checkpoint"))
        if hashlib.sha256(raw).hexdigest() != getattr(args, name + "_sha256"):
            raise RuntimeError("Matching offsite checkpoints required")
        snapshots[name] = open_checkpoint(raw, phrase)
    del phrase
    profile = (directory / "profiles/iphone-import.txt").read_bytes()
    ssh_pid = _run(["systemctl", "show", "ssh", "-p", "MainPID", "--value"])
    note = read_private_json("/root/ftm-web-login.json")
    url = "https://" + state["endpoint"] + note["panel_path"] + "api/status"

    def private_only():
        if read_private_json("/etc/ftm/web.json")["version"] != 1 or read_private_json("/etc/ftm/https.json")["mode"] != "probe":
            raise RuntimeError("Private restore retained a public proxy")
        with urllib.request.urlopen(url, timeout=10) as response:
            if "Сервис готовится".encode() not in response.read():
                raise RuntimeError("Private restore exposed an API route")

    with tempfile.TemporaryDirectory(prefix="ftm-https-recovery-", dir="/root") as folder:
        root = Path(folder)
        for name, snapshot in snapshots.items():
            stage(snapshot, root / name)
        if capture_live(store, agent) != snapshots["public"]:
            raise RuntimeError("Take a fresh public checkpoint before recovery verification")
        completed = False
        try:
            restore_same_host(root / "private", store, agent)
            private_only()

            def injected_failure():
                raise RuntimeError("Injected edge recovery failure")

            try:
                restore_same_host(root / "public", store, agent, after_write=injected_failure)
            except RuntimeError as error:
                if str(error) != "Restore failed; previous checkpoint recovered":
                    raise
            else:
                raise RuntimeError("Injected restore failure was not detected")
            private_only()
            if capture_live(store, agent) != snapshots["private"]:
                raise RuntimeError("Rollback did not return the complete private snapshot")
            restore_same_host(root / "public", store, agent)
            if capture_live(store, agent) != snapshots["public"]:
                raise RuntimeError("Public recovery changed the saved identity")
            if read_private_json("/etc/ftm/https.json")["mode"] != "public":
                raise RuntimeError("Public Caddy route was not regenerated")
            try:
                urllib.request.urlopen(url, timeout=10)
            except urllib.error.HTTPError as error:
                if error.code != 401:
                    raise RuntimeError("Restored public API authentication failed") from None
            else:
                raise RuntimeError("Restored public API accepted an anonymous request")
            trusted_certificate(state["endpoint"])
            if not managed_status(state, agent._registry())["consistent"]:
                raise RuntimeError("VPN is inconsistent after HTTPS recovery")
            completed = True
        finally:
            if not completed:
                restore_same_host(root / "public", store, agent)
    if (directory / "profiles/iphone-import.txt").read_bytes() != profile:
        raise RuntimeError("Recovery changed the working iPhone profile")
    if _run(["systemctl", "show", "ssh", "-p", "MainPID", "--value"]) != ssh_pid:
        raise RuntimeError("Recovery restarted SSH")
    return {"result": "PASS", "private_restore_removes_public_api": True,
            "injected_public_restore_rolls_back_to_private": True, "public_https_config_regenerated": True,
            "complete_public_snapshot_restored": True, "trusted_tls_and_anonymous_401": True,
            "iphone_profile_and_ssh_pid_unchanged": True, "vpn_api_edge_restarted_for_maintenance": True}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--test-vps-apply", action="store_true")
    for name in ("private", "public"):
        parser.add_argument("--" + name + "-checkpoint", required=True, type=Path)
        parser.add_argument("--" + name + "-sha256", required=True)
    args = parser.parse_args()
    if not args.test_vps_apply or os.geteuid() != 0:
        parser.error("Requires root and --test-vps-apply on the agreed test VPS")
    try:
        with Path("/run/lock/vps-vk.lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            result = verify(args)
        report = Path("/root/ftm-https-recovery-report.json")
        report.write_text(json.dumps(result, indent=2))
        report.chmod(0o600)
        print(json.dumps(result))
    except Exception as error:
        print("HTTPS recovery scenario failed: " + type(error).__name__ + "; private data withheld", file=sys.stderr)
        raise SystemExit(1)
