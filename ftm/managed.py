"""Explicit adoption of trusted legacy identities; never adopts arbitrary live peers."""

import json
import re
import argparse
import os

from .agent import _atomic
from .store import Conflict, ValidationError


def adopt_legacy(store, agent):
    clients_path = agent.config / "clients.json"
    wg_path = agent.config / "wireguard.conf"
    if any(path.is_symlink() or not path.is_file() for path in (clients_path, wg_path)):
        raise ValidationError("Unsafe baseline configuration")
    old_clients, old_wg = clients_path.read_bytes(), wg_path.read_bytes()
    registry = agent._registry()
    previous_registry = agent.registry.read_bytes() if agent.registry.exists() else None
    with store.transaction() as db:
        devices = [dict(row) for row in db.execute("SELECT * FROM devices WHERE origin='legacy'")]
        if len(devices) != 2:
            raise ValidationError("Expected the two imported baseline identities")
        specs = [agent.legacy_spec(device) for device in devices]
        flag = db.execute("SELECT value FROM settings WHERE key='managed_legacy_adopted'").fetchone()
        if flag and flag[0] == "1":
            for spec in specs:
                record = registry["devices"].get(spec["id"])
                if not record or not record.get("legacy") or record["spec"] != spec:
                    raise Conflict("Legacy metadata and root ownership disagree")
            return {"adopted": 0, "vpn_restarted": False}
        if any(not device["enabled"] or device["state"] != "active" for device in devices):
            raise ValidationError("Legacy devices are not in their original active state")
        live_peers = set(agent.runner(["wg", "show", agent.interface, "peers"]).split())
        psks = {row.split()[0]: row.split()[1] for row in agent.runner(["wg", "show", agent.interface, "preshared-keys"]).splitlines()}
        allowed = {}
        for line in agent.runner(["wg", "show", agent.interface, "allowed-ips"]).splitlines():
            fields = line.split()
            if len(fields) >= 2:
                allowed[fields[0]] = set(re.split(r"[,\s]+", " ".join(fields[1:])))
        text = old_wg.decode()
        header = dict((match.group(1), match.group(2).strip()) for match in re.finditer(
            r"(?m)^(\w+)\s*=\s*(.+)$", text.split("[Peer]", 1)[0]))
        if header.get("PrivateKey") != agent.baseline["server_private"] or header.get("ListenPort") != str(agent.baseline["backend_port"]):
            raise ValidationError("Backend identity or port differs from baseline")
        clients = json.loads(old_clients)
        if not isinstance(clients.get("clients"), dict):
            raise ValidationError("Invalid CID configuration")
        for spec in specs:
            if (spec["wg_public_key"] not in live_peers or psks.get(spec["wg_public_key"]) != spec["preshared_key"]
                    or allowed.get(spec["wg_public_key"]) != set(spec["allowed_ips"])):
                raise Conflict("Live legacy peer differs from the trusted baseline")
            block = agent._block(spec)
            original_block = block.replace("\n# FTM device " + spec["id"], "", 1)
            if text.count(block) == 1:
                pass
            elif text.count(original_block) == 1:
                text = text.replace(original_block, block, 1)
            else:
                raise Conflict("Persistent legacy peer differs from the trusted baseline")
            current = clients["clients"].get(spec["cid"])
            if not isinstance(current, dict):
                raise Conflict("Legacy CID is missing")
            clients["clients"][spec["cid"]] = {**current, "comment": "FTM:" + spec["id"]}
            existing = registry["devices"].get(spec["id"])
            if existing and (not existing.get("legacy") or existing["spec"] != spec):
                raise Conflict("Conflicting root ownership record")
            registry["devices"][spec["id"]] = {"legacy": True, "enabled": True, "phase": "active", "spec": spec}
        try:
            _atomic(agent.registry, json.dumps(registry))
            _atomic(wg_path, text)
            _atomic(clients_path, json.dumps(clients))
            db.execute("INSERT OR REPLACE INTO settings VALUES('managed_legacy_adopted','1')")
            store._audit(db, "legacy.adopt", "instance", agent.baseline["instance"])
        except BaseException:
            _atomic(wg_path, old_wg)
            _atomic(clients_path, old_clients)
            if previous_registry is None:
                agent.registry.unlink(missing_ok=True)
            else:
                _atomic(agent.registry, previous_registry)
            raise
    return {"adopted": 2, "vpn_restarted": False, "issued_profiles_changed": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--adopt-legacy", action="store_true")
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    if not args.adopt_legacy or not args.apply or os.name != "posix" or os.geteuid() != 0:
        parser.error("Requires root, --adopt-legacy and --apply")
    import fcntl
    from pathlib import Path
    from .agent import NetworkAgent
    from .store import Store
    from .installer import read_private_json
    from .legacy import baseline_module
    fd = os.open("/run/lock/vps-vk.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        state = read_private_json("/var/lib/vps-vk/main/state.json", 1048576)
        baseline_module().check_keypairs(state)
        store = Store("/var/lib/ftm/manager.sqlite3")
        agent = NetworkAgent(state, config_dir="/etc/vps-vk/main", state_dir="/var/lib/ftm-agent")
        print(json.dumps(adopt_legacy(store, agent)))
        return 0
    finally:
        os.close(fd)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, RuntimeError, OSError):
        print("Legacy adoption failed; private data withheld", file=__import__("sys").stderr)
        raise SystemExit(1)
