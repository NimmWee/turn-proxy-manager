"""Root-only, fixed-path network reconciliation. No shell or arbitrary command endpoint."""

import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time
import uuid

from .installer import read_private_json
from .legacy import baseline_module, validate_legacy_state
from .store import Store, Conflict, ValidationError, valid_key, _now


def _run(args):
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.TimeoutExpired):
        raise RuntimeError("Network operation failed") from None
    if result.returncode:
        raise RuntimeError("Network operation failed")
    return result.stdout


def _atomic(path, data, mode=0o600):
    path = Path(path)
    if path.is_symlink() or path.parent.is_symlink():
        raise ValidationError("Symlink rejected")
    previous = path.stat() if path.exists() else None
    fd, temporary = tempfile.mkstemp(prefix=".ftm-", dir=path.parent)
    try:
        os.chmod(temporary, (previous.st_mode & 0o777) if previous else mode)
        if os.name == "posix" and previous:
            os.fchown(fd, previous.st_uid, previous.st_gid)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data if isinstance(data, bytes) else data.encode())
            stream.flush()
            os.fsync(stream.fileno())
        stamp = max(time.time_ns(), previous.st_mtime_ns + 1000000 if previous else 0)
        os.utime(temporary, ns=(stamp, stamp))
        os.replace(temporary, path)
        if os.name == "posix":
            directory_fd = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


class NetworkAgent:
    def __init__(self, baseline, *, config_dir, state_dir, runner=_run, offline=False):
        validate_legacy_state(baseline)
        self.baseline = baseline
        self.interface = baseline_module().iface(baseline)
        self.subnet = ipaddress.ip_network(baseline["subnet"])
        self.config = Path(config_dir)
        self.directory = Path(state_dir)
        if any(path.is_symlink() for path in (self.config, self.directory)):
            raise ValidationError("Agent directory symlink rejected")
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        if os.name == "posix" and self.directory.stat().st_mode & 0o077:
            raise ValidationError("Agent directory must be private")
        self.registry = self.directory / "managed.json"
        self.runner = runner
        self.offline = offline

    def _registry(self):
        if not self.registry.exists():
            return {"devices": {}}
        if self.registry.is_symlink() or self.registry.stat().st_size > 2 * 1024 ** 2:
            raise ValidationError("Invalid agent registry")
        value = json.loads(self.registry.read_text())
        if not isinstance(value, dict) or set(value) != {"devices"} or not isinstance(value["devices"], dict):
            raise ValidationError("Invalid agent registry")
        return value

    @staticmethod
    def _block(spec):
        return (f"\n# FTM device {spec['id']}\n[Peer]\nPublicKey = {spec['wg_public_key']}\n"
                f"PresharedKey = {spec['preshared_key']}\nAllowedIPs = {', '.join(spec['allowed_ips'])}\n")

    def _set_peer(self, spec):
        fd, name = tempfile.mkstemp(prefix="psk-", dir=self.directory)
        try:
            os.chmod(name, 0o600)
            with os.fdopen(fd, "w") as stream:
                stream.write(spec["preshared_key"] + "\n")
            self.runner(["wg", "set", self.interface, "peer", spec["wg_public_key"],
                         "preshared-key", name, "allowed-ips", ",".join(spec["allowed_ips"])])
        finally:
            os.unlink(name)

    def _validate(self, device):
        try:
            if str(uuid.UUID(device["id"])) != device["id"]:
                raise ValueError()
            ip = ipaddress.ip_address(device["ip"])
            if ip.version != 4 or ip not in self.subnet:
                raise ValueError()
            if not valid_key(device["wg_public_key"]) or not valid_key(device["preshared_key"]):
                raise ValueError()
            if not isinstance(device["cid"], str) or not re.fullmatch(r"[0-9a-f]{32}", device["cid"]):
                raise ValueError()
            if device["vpn_type"] != "wg" or device["enabled"] not in (0, 1):
                raise ValueError()
            if device["origin"] == "legacy":
                spec = self.legacy_spec(device)
                owned = self._registry()["devices"].get(device["id"])
                if not owned or not owned.get("legacy") or owned["spec"] != spec:
                    raise ValueError()
                return spec
            if device["origin"] != "manager" or not 10 <= int(ip) - int(self.subnet.network_address) <= 254:
                raise ValueError()
        except (ValueError, TypeError, KeyError):
            raise ValidationError("Invalid peer or protected legacy device") from None
        return {**{key: device[key] for key in ("id", "wg_public_key", "preshared_key", "cid", "ip")},
                "allowed_ips": [device["ip"] + "/32"]}

    def legacy_spec(self, device):
        app = baseline_module()
        for name, last in [("iphone", 2), ("android", 3)]:
            peer = self.baseline["clients"][name]
            if device.get("wg_public_key") != peer["public_key"]:
                continue
            expected_id = str(uuid.uuid5(uuid.NAMESPACE_URL, "ftm/legacy/" + self.baseline["instance"] + "/" + name))
            if (device.get("id") != expected_id or device.get("origin") != "legacy" or
                    device.get("cid") != peer["cid"] or device.get("preshared_key") != peer["preshared_key"] or
                    device.get("ip") != app.address(self.baseline, last)):
                raise ValidationError("Legacy identity differs from the trusted baseline")
            return {**{key: device[key] for key in ("id", "wg_public_key", "preshared_key", "cid", "ip")},
                    "allowed_ips": [device["ip"] + "/32", app.v6prefix(self.baseline) + str(last) + "/128"]}
        raise ValidationError("Unknown legacy identity")

    def apply(self, device):
        spec = self._validate(device)
        clients_path, wg_path = self.config / "clients.json", self.config / "wireguard.conf"
        if any(path.is_symlink() or not path.is_file() or path.stat().st_size > 2 * 1024 ** 2 for path in (clients_path, wg_path)):
            raise ValidationError("Unsafe network configuration files")
        original_clients, original_wg = clients_path.read_bytes(), wg_path.read_bytes()
        clients = json.loads(original_clients)
        if not isinstance(clients, dict) or not isinstance(clients.get("clients"), dict):
            raise ValidationError("Invalid CID file")
        registry = self._registry()
        previous_registry = json.dumps(registry)
        old = registry["devices"].get(spec["id"])
        if old and old["spec"] != spec:
            raise Conflict("Managed peer identity changed")
        persisted = []
        for section in original_wg.decode().split("[Peer]")[1:]:
            fields = {}
            for line in section.splitlines():
                line = line.split("#", 1)[0]
                if "=" in line:
                    name, value = line.split("=", 1)
                    fields[name.strip()] = value.strip()
            persisted.append(fields)
        if self.offline:
            peers = {fields.get("PublicKey") for fields in persisted}
            allowed_lines = [fields.get("PublicKey", "") + "\t" + fields.get("AllowedIPs", "") for fields in persisted]
        else:
            peers = set(self.runner(["wg", "show", self.interface, "peers"]).split())
            allowed_lines = self.runner(["wg", "show", self.interface, "allowed-ips"]).splitlines()
        if spec["wg_public_key"] in peers and not old:
            raise Conflict("Refusing to adopt an unknown WireGuard peer")
        comment = {"comment": "FTM:" + spec["id"]}
        current_cid = clients["clients"].get(spec["cid"])
        cid_owned = isinstance(current_cid, dict) and current_cid.get("comment") == comment["comment"]
        if current_cid is not None and (not old or not cid_owned):
            raise Conflict("Refusing to replace an unknown Client ID")
        for line in allowed_lines:
            fields = line.split()
            if len(fields) < 2 or fields[0] == spec["wg_public_key"]:
                continue
            for value in re.split(r"[,\s]+", " ".join(fields[1:])):
                if value == "(none)":
                    continue
                if ipaddress.ip_address(spec["ip"]) in ipaddress.ip_network(value, strict=False):
                    raise Conflict("Address overlaps an unknown WireGuard peer")
        wg_text = original_wg.decode()
        block = self._block(spec)
        if "# FTM device " + spec["id"] in wg_text and block not in wg_text:
            raise Conflict("Managed config block was edited externally")
        for section in wg_text.replace(block, "").split("[Peer]")[1:]:
            fields = {}
            for line in section.splitlines():
                line = line.split("#", 1)[0]
                if "=" in line:
                    name, value = line.split("=", 1)
                    fields[name.strip()] = value.strip()
            if fields.get("PublicKey") == spec["wg_public_key"]:
                raise Conflict("Refusing to overwrite an unknown persisted peer")
            for value in re.split(r"[,\s]+", fields.get("AllowedIPs", "").strip()):
                if value and ipaddress.ip_address(spec["ip"]) in ipaddress.ip_network(value, strict=False):
                    raise Conflict("Address overlaps an unknown persisted peer")
        was_present = spec["wg_public_key"] in peers
        if device["enabled"] and old and old.get("phase") == "active" and was_present and cid_owned and block in wg_text:
            return False
        registry["devices"][spec["id"]] = {"phase": "preparing", "spec": spec,
                                           "legacy": device["origin"] == "legacy", "enabled": bool(device["enabled"])}
        _atomic(self.registry, json.dumps(registry))
        try:
            if device["enabled"]:
                if block not in wg_text:
                    wg_text += block
                _atomic(wg_path, wg_text)
                if not self.offline:
                    self._set_peer(spec)
                clients["clients"][spec["cid"]] = {**(current_cid or {}), **comment}
                _atomic(clients_path, json.dumps(clients))
                registry["devices"][spec["id"]]["phase"] = "active"
            else:
                if cid_owned:
                    clients["clients"].pop(spec["cid"])
                _atomic(clients_path, json.dumps(clients))
                if was_present and not self.offline:
                    self.runner(["wg", "set", self.interface, "peer", spec["wg_public_key"], "remove"])
                _atomic(wg_path, wg_text.replace(block, "", 1))
                if device["origin"] == "legacy":
                    registry["devices"][spec["id"]]["phase"] = "revoked"
                else:
                    registry["devices"].pop(spec["id"], None)
            _atomic(self.registry, json.dumps(registry))
            return True
        except BaseException:
            _atomic(clients_path, original_clients)
            _atomic(wg_path, original_wg)
            try:
                if was_present and old and not self.offline:
                    self._set_peer(old["spec"])
                elif not was_present and not self.offline:
                    self.runner(["wg", "set", self.interface, "peer", spec["wg_public_key"], "remove"])
                _atomic(self.registry, previous_registry)
            except RuntimeError:
                registry["devices"][spec["id"]]["phase"] = "error"
                _atomic(self.registry, json.dumps(registry))
            raise


def reconcile(store, agent):
    processed = errors = cancelled = 0
    with store.connect() as db:
        ids = [row[0] for row in db.execute("SELECT id FROM operations WHERE state IN ('pending','applying','error') ORDER BY created_at,id")]
    for operation_id in ids:
        with store.transaction() as db:
            operation = db.execute("SELECT * FROM operations WHERE id=?", (operation_id,)).fetchone()
            if operation["state"] not in ("pending", "applying", "error"):
                continue
            device = dict(db.execute("SELECT * FROM devices WHERE id=?", (operation["device_id"],)).fetchone())
            if device["revision"] != operation["revision"]:
                db.execute("UPDATE operations SET state='cancelled',updated_at=? WHERE id=?", (_now(), operation_id))
                cancelled += 1
                continue
            db.execute("UPDATE operations SET state='applying',updated_at=? WHERE id=?", (_now(), operation_id))
            try:
                agent.apply(device)
            except (ValueError, RuntimeError, OSError):
                db.execute("UPDATE operations SET state='error',updated_at=? WHERE id=?", (_now(), operation_id))
                db.execute("UPDATE devices SET state='error' WHERE id=?", (device["id"],))
                errors += 1
            else:
                db.execute("UPDATE operations SET state='done',updated_at=? WHERE id=?", (_now(), operation_id))
                db.execute("UPDATE devices SET state=? WHERE id=?", ("active" if device["enabled"] else "revoked", device["id"]))
                store._audit(db, "device.applied" if device["enabled"] else "device.revoked", "device", device["id"])
                processed += 1
    return {"processed": processed, "errors": errors, "cancelled": cancelled, "vpn_restarted": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    if not args.apply or os.name != "posix" or os.geteuid() != 0:
        parser.error("Requires root on Linux and explicit --apply")
    import fcntl
    fd = os.open("/run/lock/vps-vk.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        state = read_private_json("/var/lib/vps-vk/main/state.json", 1048576)
        store = Store("/var/lib/ftm/manager.sqlite3")
        with store.connect() as db:
            subnet = db.execute("SELECT value FROM settings WHERE key='subnet'").fetchone()[0]
        if subnet != state["subnet"]:
            raise ValidationError("Database subnet differs from the active VPN")
        report = reconcile(store, NetworkAgent(state, config_dir="/etc/vps-vk/main", state_dir="/var/lib/ftm-agent"))
        print(json.dumps(report))
        return 1 if report["errors"] else 0
    finally:
        os.close(fd)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, RuntimeError, OSError):
        print("Agent could not apply desired state; secrets withheld", file=__import__("sys").stderr)
        raise SystemExit(1)
