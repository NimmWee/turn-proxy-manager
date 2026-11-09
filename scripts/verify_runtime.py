"""Verify the installed managed startup hook on the agreed test VPS."""

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ftm.agent import NetworkAgent, _run, _atomic
from ftm.checkpoint import capture, stage, _restore_database
from ftm.compat import managed_status
from ftm.legacy import baseline_module
from ftm.store import Store


def verify():
    app = baseline_module()
    state = app.load_state("main")
    conf, state_dir = app.paths("main")
    store = Store("/var/lib/ftm/manager.sqlite3")
    agent = NetworkAgent(state, config_dir=conf, state_dir="/var/lib/ftm-agent")
    original = capture(store, agent)
    profile = (state_dir / "profiles/iphone-import.txt").read_bytes()
    ssh_pid = _run(["systemctl", "show", "ssh", "-p", "MainPID", "--value"])
    android = store.get_device(next(d["id"] for d in store.list_devices() if d["platform"] == "android" and d["origin"] == "legacy"))
    for argv in (("/usr/local/bin/ftm-startup", "--prepare"), ("/usr/local/bin/vps-vk", "install")):
        if subprocess.run(argv, capture_output=True, timeout=30).returncode == 0:
            raise RuntimeError("Unsafe live preparation or legacy mutation was accepted")
    with tempfile.TemporaryDirectory(prefix="ftm-runtime-verify-", dir="/root") as folder:
        staged = Path(folder) / "restore"
        stage(original, staged)

        def restart_network():
            _run(["systemctl", "stop", "vps-vk"])
            _run(["systemctl", "restart", "vps-vk-network"])
            _run(["systemctl", "reset-failed", "vps-vk"])
            _run(["systemctl", "start", "vps-vk"])

        try:
            store.revoke_device(android["id"])
            restart_network()
            one = managed_status(state, agent._registry())
            if not one["consistent"] or one["peers"] != 1:
                raise RuntimeError("Pending revoke did not survive real service startup")
            _run(["/usr/local/bin/vps-vk", "profiles"])
            if (state_dir / "profiles/android-import.txt").exists():
                raise RuntimeError("Revoked Android profile was offered by the system CLI")
            store.set_device_enabled(android["id"], True)
            restart_network()
            two = managed_status(state, agent._registry())
            if not two["consistent"] or two["peers"] != 2:
                raise RuntimeError("Pending enable did not survive real service startup")
            _run(["/usr/local/bin/vps-vk", "profiles", "--qr"])
            if ((state_dir / "profiles/iphone-import.txt").read_bytes() != profile
                    or _run(["systemctl", "show", "ssh", "-p", "MainPID", "--value"]) != ssh_pid):
                raise RuntimeError("Issued profile or SSH process changed")
        except BaseException:
            _run(["systemctl", "stop", "vps-vk"])
            for name, target in (("wireguard.conf", conf / "wireguard.conf"),
                                 ("clients.json", conf / "clients.json"), ("managed.json", agent.registry)):
                _atomic(target, (staged / name).read_bytes())
            _restore_database(staged / "metadata.sqlite3", store.path)
            restart_network()
            raise
    return {"result": "PASS", "real_network_service_pending_revoke_enable": True,
            "dynamic_system_vps_vk_status": True, "unsafe_legacy_install_blocked": True,
            "revoked_profile_removed_and_enabled_profiles_regenerated": True,
            "live_offline_prepare_blocked": True, "iphone_profile_and_ssh_unchanged": True,
            "host_reboot_tested": False}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--test-vps-apply", action="store_true")
    args = parser.parse_args()
    if not args.test_vps_apply or os.geteuid() != 0:
        parser.error("Requires root and --test-vps-apply on the agreed test VPS")
    # Do not hold the lifecycle lock across systemctl: ExecStartPre takes it.
    try:
        print(json.dumps(verify(), indent=2))
    except (ValueError, RuntimeError, OSError):
        print("Installed runtime verification failed; private data withheld", file=sys.stderr)
        raise SystemExit(1)
