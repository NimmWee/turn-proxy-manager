"""Persist pending root-owned desired state before the kernel interface starts.

The SQLite store remains root-owned. This entrypoint must not be reused after
giving an unprivileged API write access to that store.
"""

import argparse
import json
import os
from pathlib import Path

from .agent import NetworkAgent, reconcile
from .installer import read_private_json
from .store import Store, ValidationError


def prepare_startup(store, agent):
    if not agent.offline:
        raise ValidationError("Startup preparation requires offline mode")
    with store.connect() as db:
        flag = db.execute("SELECT value FROM settings WHERE key='managed_legacy_adopted'").fetchone()
        subnet = db.execute("SELECT value FROM settings WHERE key='subnet'").fetchone()
    if not flag or flag[0] != "1" or not subnet or subnet[0] != agent.baseline["subnet"]:
        raise ValidationError("Managed adoption and matching subnet required")
    report = reconcile(store, agent)
    if report["errors"]:
        raise RuntimeError("Pending operations could not be persisted; network startup denied")
    # Recover interrupted root operations even if a previous DB commit succeeded.
    for identifier in list(agent._registry()["devices"]):
        agent.apply(store.get_device(identifier))
    return {**report, "offline": True, "network_commands_executed": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prepare", action="store_true")
    args = parser.parse_args()
    if not args.prepare or os.name != "posix" or os.geteuid() != 0:
        parser.error("Requires root and --prepare")
    import fcntl
    fd = os.open("/run/lock/vps-vk.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        state = read_private_json("/var/lib/vps-vk/main/state.json", 1048576)
        for name in ("/var/lib/ftm", "/var/lib/ftm/manager.sqlite3", "/var/lib/ftm-agent"):
            path = Path(name)
            if path.is_symlink() or path.stat().st_uid != 0 or path.stat().st_mode & 0o077:
                raise ValidationError("Startup store must remain root-owned and private")
        # Reject a manual invocation against a running tunnel. The systemd hook
        # runs before network-up creates it.
        import subprocess
        exists = subprocess.run(["ip", "link", "show", "dev", "vkvpn0"], capture_output=True, timeout=10)
        if exists.returncode == 0:
            raise ValidationError("Interface already exists; offline preparation refused")
        agent = NetworkAgent(state, config_dir="/etc/vps-vk/main", state_dir="/var/lib/ftm-agent", offline=True)
        print(json.dumps(prepare_startup(Store("/var/lib/ftm/manager.sqlite3"), agent)))
        return 0
    finally:
        os.close(fd)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, RuntimeError, OSError, KeyError):
        print("Managed startup preparation failed; network not started; private data withheld", file=__import__("sys").stderr)
        raise SystemExit(1)
