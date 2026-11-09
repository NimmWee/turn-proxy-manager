"""Save and verify a private manifest across an explicitly authorized test reboot."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, "/opt/ftm/current")
from ftm.agent import _atomic, _run, NetworkAgent
from ftm.compat import managed_status
from ftm.installer import read_private_json
from ftm.legacy import baseline_module
from ftm.store import Store

MANIFEST = Path("/root/ftm-preboot-manifest.json")


def current():
    app = baseline_module()
    state = app.load_state("main")
    conf, state_dir = app.paths("main")
    agent = NetworkAgent(state, config_dir=conf, state_dir="/var/lib/ftm-agent")
    paths = (conf / "wireguard.conf", conf / "clients.json", conf / "obf.key", agent.registry,
             state_dir / "state.json", state_dir / "profiles/iphone-import.txt", state_dir / "profiles/android-import.txt")
    if any(path.is_symlink() or not path.is_file() for path in paths):
        raise ValueError("Unsafe verification source")
    status = managed_status(state, agent._registry())
    if not status["consistent"] or status["peers"] != 2:
        raise RuntimeError("Managed VPN is not healthy")
    store = Store("/var/lib/ftm/manager.sqlite3")
    with store.connect() as db:
        if db.execute("PRAGMA integrity_check").fetchone()[0] != "ok" or db.execute("SELECT count(*) FROM operations WHERE state IN ('pending','applying','error')").fetchone()[0]:
            raise RuntimeError("Metadata integrity/pending check failed")
        metadata = [tuple(row) for row in db.execute("SELECT * FROM devices ORDER BY id")]
    if not all(app.rule_exists(rule) for rule in app.network_rules(state)):
        raise RuntimeError("Scoped firewall rules are missing")
    for name, expected in (("maxretry", 3), ("findtime", 600), ("bantime", 31536000)):
        if _run(["fail2ban-client", "get", "sshd", name]).strip() != str(expected):
            raise RuntimeError("SSH protection policy changed")
    if _run(["systemctl", "is-active", "ssh"]).strip() != "active":
        raise RuntimeError("SSH is not active")
    return {"boot": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
            "files": {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in paths},
            "metadata": hashlib.sha256(json.dumps(metadata).encode()).hexdigest(),
            "peers": hashlib.sha256("\n".join(sorted(_run(["wg", "show", agent.interface, "peers"]).split())).encode()).hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--save-before", action="store_true")
    parser.add_argument("--verify-after", action="store_true")
    args = parser.parse_args()
    if os.geteuid() != 0 or args.save_before == args.verify_after:
        parser.error("Requires root and exactly one verification mode")
    found = current()
    if args.save_before:
        _atomic(MANIFEST, json.dumps(found))
        return {"preboot_manifest_saved": True, "vpn_ssh_firewall_fail2ban_healthy": True}
    previous = read_private_json(MANIFEST)
    if found["boot"] == previous["boot"]:
        raise RuntimeError("The host has not rebooted")
    if any(found[key] != previous[key] for key in ("files", "metadata", "peers")):
        raise RuntimeError("Configuration, peers or metadata changed across reboot")
    return {"result": "PASS", "actual_host_reboot": True, "automatic_vpn_start": True,
            "profiles_keys_registry_metadata_unchanged": True, "ssh_available": True,
            "scoped_firewall_and_yearly_fail2ban_verified": True, "phone_e2e_after_reboot_tested": False}


if __name__ == "__main__":
    try:
        print(json.dumps(main(), indent=2))
    except (ValueError, RuntimeError, OSError):
        print("Reboot verification failed; private data withheld", file=sys.stderr)
        raise SystemExit(1)
