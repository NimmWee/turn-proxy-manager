"""Capture first, then exercise same-host restore only after offsite verification."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ftm.agent import NetworkAgent, reconcile, _atomic, _run
from ftm.checkpoint import capture_live as capture, seal, open_checkpoint, stage, restore_same_host, _restore_database, _read_encrypted
from ftm.compat import managed_status
from ftm.legacy import baseline_module
from ftm.store import Store


def verify(args):
    app = baseline_module()
    state = app.load_state("main")
    app.check_keypairs(state)
    conf, state_dir = app.paths("main")
    store = Store("/var/lib/ftm/manager.sqlite3")
    agent = NetworkAgent(state, config_dir=conf, state_dir="/var/lib/ftm-agent")
    password_path = Path("/root/ftm-test-backup.pass")
    if password_path.is_symlink() or password_path.stat().st_mode & 0o077:
        raise ValueError("Private recovery phrase required")
    password = password_path.read_text().strip()
    if args.capture_only:
        snapshot = capture(store, agent)
        data = seal(snapshot, password)
        output = Path("/root/ftm-managed-" + secrets.token_hex(5) + ".vpnbackup")
        _atomic(output, data)
        return {"encrypted_checkpoint": str(output), "sha256": hashlib.sha256(data).hexdigest(),
                "offsite_verification_required": True, "live_vpn_changed": False,
                "format_version": snapshot["version"], "web_settings_included": "web.json" in snapshot["files"]}
    data = _read_encrypted(args.checkpoint)
    if not args.offsite_sha256 or hashlib.sha256(data).hexdigest() != args.offsite_sha256:
        raise ValueError("A matching offsite-verified ciphertext hash is required")
    snapshot = open_checkpoint(data, password)
    del password
    before_profile = (state_dir / "profiles/iphone-import.txt").read_bytes()
    before_state = (state_dir / "state.json").read_bytes()
    ssh_pid = _run(["systemctl", "show", "ssh", "-p", "MainPID", "--value"])
    api_was_active = subprocess.run(["systemctl", "is-active", "--quiet", "ftm-api"], capture_output=True).returncode == 0
    checkpoint_dir = Path("/root") / ("ftm-managed-recovery-" + secrets.token_hex(5))
    stage(snapshot, checkpoint_dir)
    if capture(store, agent) != snapshot:
        raise RuntimeError("Live source changed since offsite capture; take a fresh checkpoint")

    def add_temporary_peer():
        user = store.create_user("Checkpoint recovery verification")
        private = subprocess.check_output(["wg", "genkey"])
        public = subprocess.check_output(["wg", "pubkey"], input=private).decode().strip()
        device = store.create_device(user["id"], "Temporary recovery peer", "other", public, secrets.token_hex(12))
        if reconcile(store, agent)["errors"]:
            raise RuntimeError("Could not apply verification peer")
        return device

    def change_web_identity():
        path = checkpoint_dir / "web.json"
        if path.is_file():
            value = json.loads(path.read_bytes())
            value["username"] = "checkpoint-verification-admin"
            _atomic(Path("/etc/ftm/web.json"), json.dumps(value))

    try:
        device = add_temporary_peer()
        change_web_identity()
        restore_same_host(checkpoint_dir, store, agent)
        if device["wg_public_key"] in _run(["wg", "show", agent.interface, "peers"]).split():
            raise RuntimeError("Restore retained a later peer")
        device = add_temporary_peer()
        change_web_identity()

        def failure():
            raise RuntimeError("Intentional post-write verification failure")

        try:
            restore_same_host(checkpoint_dir, store, agent, after_write=failure)
        except RuntimeError as error:
            if str(error) != "Restore failed; previous checkpoint recovered":
                raise
        else:
            raise RuntimeError("Injected restore failure was not observed")
        if (device["wg_public_key"] not in _run(["wg", "show", agent.interface, "peers"]).split()
                or store.get_device(device["id"])["state"] != "active"):
            raise RuntimeError("Rollback did not recover the previous managed peer")
        if (checkpoint_dir / "web.json").is_file() and json.loads(Path("/etc/ftm/web.json").read_bytes())["username"] != "checkpoint-verification-admin":
            raise RuntimeError("Rollback did not recover the previous web settings")
        restore_same_host(checkpoint_dir, store, agent)
        if not managed_status(state, agent._registry())["consistent"]:
            raise RuntimeError("Final VPN health check failed")
        if ((state_dir / "profiles/iphone-import.txt").read_bytes() != before_profile
                or (state_dir / "state.json").read_bytes() != before_state
                or _run(["systemctl", "show", "ssh", "-p", "MainPID", "--value"]) != ssh_pid):
            raise RuntimeError("Issued profile, baseline identity or SSH changed")
        if capture(store, agent) != snapshot:
            raise RuntimeError("Final managed snapshot differs from original")
        return {"result": "PASS", "same_host_restore": True, "injected_failure_rollback": True,
                "later_peer_and_metadata_removed_by_restore": True, "original_snapshot_restored": True,
                "web_settings_restore_and_rollback": (checkpoint_dir / "web.json").is_file(),
                "iphone_profile_and_ssh_unchanged": True, "firewall_not_changed": True,
                "clean_host_restore_tested": False, "host_reboot_tested": False,
                "root_recovery_directory": str(checkpoint_dir)}
    except BaseException:
        # Last-resort exact recovery from the prevalidated private staging copy.
        _run(["systemctl", "stop", "vps-vk"])
        for name, target in (("wireguard.conf", conf / "wireguard.conf"),
                             ("clients.json", conf / "clients.json"), ("managed.json", agent.registry)):
            _atomic(target, (checkpoint_dir / name).read_bytes())
        if (checkpoint_dir / "web.json").is_file():
            _atomic(Path("/etc/ftm/web.json"), (checkpoint_dir / "web.json").read_bytes())
        _restore_database(checkpoint_dir / "metadata.sqlite3", store.path)
        _run(["wg", "syncconf", agent.interface, str(conf / "wireguard.conf")])
        _run(["systemctl", "reset-failed", "vps-vk"])
        _run(["systemctl", "start", "vps-vk"])
        if api_was_active:
            _run(["systemctl", "reset-failed", "ftm-api"])
            _run(["systemctl", "start", "ftm-api"])
        raise


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture-only", action="store_true")
    parser.add_argument("--test-vps-apply", action="store_true")
    parser.add_argument("--checkpoint", type=Path)
    parser.add_argument("--offsite-sha256")
    args = parser.parse_args()
    if os.geteuid() != 0 or args.capture_only == args.test_vps_apply or (args.test_vps_apply and not args.checkpoint):
        parser.error("Requires root and either --capture-only or --test-vps-apply with checkpoint/hash")
    import fcntl
    try:
        with Path("/run/lock/vps-vk.lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            print(json.dumps(verify(args), indent=2))
    except BaseException as error:
        print("Checkpoint verification failed: " + type(error).__name__ + "; private data withheld", file=sys.stderr)
        raise SystemExit(1)
