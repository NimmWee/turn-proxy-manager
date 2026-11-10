"""Authenticated data-only checkpoint of the managed VPN on a single host.

No archived shell scripts, systemd units, paths or firewall commands are accepted.
Live restore is restricted to the existing host identity; fresh-host restore
requires the later installer and is deliberately unavailable here.
"""

import argparse
import base64
import getpass
import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import secrets
import sqlite3
import tempfile

from .agent import NetworkAgent, _atomic, _run
from .installer import _unique_object, read_private_json
from .legacy import baseline_module, validate_legacy_state
from .store import Store, ValidationError, valid_key

MAGIC = b"FTMCP1\n"
MAX_RAW = 12 * 1024 ** 2
MAX_CIPHER = MAX_RAW + 4096
FILES = {"state.json", "wireguard.conf", "clients.json", "managed.json"}
WEB_CONFIG = Path("/etc/ftm/web.json")


def _json(raw):
    try:
        return json.loads(raw, object_pairs_hook=_unique_object)
    except (ValueError, UnicodeError, RecursionError):
        raise ValidationError("Invalid checkpoint data") from None


def seal(snapshot, password):
    if not isinstance(password, str) or len(password) < 12:
        raise ValidationError("Recovery phrase must contain at least 12 characters")
    raw = json.dumps(snapshot, separators=(",", ":")).encode()
    if len(raw) > MAX_RAW:
        raise ValidationError("Checkpoint exceeds size limit")
    salt = secrets.token_bytes(16)
    cipher = baseline_module().openssl(raw, password)
    key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200000, 32)
    body = MAGIC + salt + cipher
    return MAGIC + salt + hmac.new(key, body, hashlib.sha256).digest() + cipher


def open_checkpoint(data, password):
    if not isinstance(data, bytes) or not len(MAGIC) + 64 <= len(data) <= MAX_CIPHER or not data.startswith(MAGIC):
        raise ValidationError("Invalid encrypted checkpoint")
    offset = len(MAGIC)
    salt, tag, cipher = data[offset:offset+16], data[offset+16:offset+48], data[offset+48:]
    key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200000, 32)
    expected = hmac.new(key, MAGIC + salt + cipher, hashlib.sha256).digest()
    if not hmac.compare_digest(tag, expected):
        raise ValidationError("Incorrect recovery phrase or damaged checkpoint")
    # Authentication always precedes decryption and JSON/SQLite processing.
    raw = baseline_module().openssl(cipher, password, True)
    if len(raw) > MAX_RAW:
        raise ValidationError("Checkpoint exceeds size limit")
    return _json(raw)


def _schema(db):
    return list(db.execute("SELECT type,name,tbl_name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name"))


def _check_database(path):
    reference = sqlite3.connect(":memory:")
    db = sqlite3.connect(path.as_uri() + "?mode=ro&immutable=1", uri=True)
    try:
        db.execute("PRAGMA trusted_schema=OFF")
        db.execute("PRAGMA query_only=ON")
        reference.executescript((Path(__file__).parent / "migrations/001_initial.sql").read_text(encoding="utf-8"))
        if _schema(db) != _schema(reference):
            raise ValidationError("Checkpoint database schema differs from the trusted migration")
        if (db.execute("PRAGMA application_id").fetchone()[0] != 1179934001
                or db.execute("SELECT max(version) FROM migration_versions").fetchone()[0] != 1
                or db.execute("PRAGMA integrity_check").fetchone()[0] != "ok"
                or db.execute("PRAGMA foreign_key_check").fetchone() is not None):
            raise ValidationError("Checkpoint database integrity/version check failed")
        if db.execute("SELECT count(*) FROM operations WHERE state IN ('pending','applying','error')").fetchone()[0]:
            raise ValidationError("Reconcile pending operations before taking a checkpoint")
    except sqlite3.Error:
        raise ValidationError("Checkpoint database rejected") from None
    finally:
        db.close()
        reference.close()


def _wg_peers(raw, state):
    interface, peers, current = {}, {}, None
    for source in raw.decode().splitlines():
        line = source.split("#", 1)[0].strip()
        if not line:
            continue
        if line == "[Interface]":
            if current is not None:
                raise ValidationError("Duplicate WireGuard interface section")
            current = interface
        elif line == "[Peer]":
            current = {}
            peers[id(current)] = current
        elif current is None or "=" not in line:
            raise ValidationError("Invalid WireGuard checkpoint")
        else:
            name, value = (part.strip() for part in line.split("=", 1))
            allowed = {"PrivateKey", "ListenPort"} if current is interface else {"PublicKey", "PresharedKey", "AllowedIPs", "Endpoint", "PersistentKeepalive"}
            if name not in allowed or name in current:
                raise ValidationError("Unsupported WireGuard checkpoint field")
            current[name] = value
    if interface != {"PrivateKey": state["server_private"], "ListenPort": str(state["backend_port"])}:
        raise ValidationError("Checkpoint backend identity differs")
    by_key = {}
    for peer in peers.values():
        public = peer.get("PublicKey")
        if not valid_key(public) or public in by_key or not peer.get("AllowedIPs"):
            raise ValidationError("Invalid or duplicate persisted peer")
        if "PresharedKey" in peer and not valid_key(peer["PresharedKey"]):
            raise ValidationError("Invalid persisted preshared key")
        for network in peer["AllowedIPs"].split(","):
            ipaddress.ip_network(network.strip(), strict=True)
        by_key[public] = peer
    return by_key


def _decode(snapshot):
    if (not isinstance(snapshot, dict) or set(snapshot) != {"format", "version", "files", "database"}
            or snapshot["format"] != "ftm-checkpoint" or type(snapshot["version"]) is not int or snapshot["version"] not in (1, 2)
            or not isinstance(snapshot["files"], dict)
            or set(snapshot["files"]) != (FILES | {"web.json"} if snapshot["version"] == 2 else FILES)):
        raise ValidationError("Unsupported checkpoint format or file section")
    try:
        files = {name: base64.b64decode(value, validate=True) for name, value in snapshot["files"].items()}
        database = base64.b64decode(snapshot["database"], validate=True)
    except (ValueError, TypeError):
        raise ValidationError("Invalid checkpoint encoding") from None
    if any(len(raw) > 2 * 1024 ** 2 for raw in files.values()) or len(database) > 8 * 1024 ** 2:
        raise ValidationError("Checkpoint section exceeds size limit")
    return files, database


def stage(snapshot, destination):
    files, database = _decode(snapshot)
    state = validate_legacy_state(_json(files["state.json"]))
    if "web.json" in files:
        from .web_auth import validate_config
        web = validate_config(_json(files["web.json"]))
        if web.get("public_origin") and web["public_origin"] != "https://" + state["endpoint"]:
            raise ValidationError("Checkpoint public HTTPS origin differs from its host")
    if state["instance"] != "main":
        raise ValidationError("Only the managed main instance is supported")
    peers = _wg_peers(files["wireguard.conf"], state)
    registry, clients = _json(files["managed.json"]), _json(files["clients.json"])
    if (not isinstance(registry, dict) or set(registry) != {"devices"} or not isinstance(registry["devices"], dict)
            or not isinstance(clients, dict) or set(clients) != {"clients"} or not isinstance(clients["clients"], dict)):
        raise ValidationError("Invalid ownership or CID checkpoint")
    destination = Path(destination).absolute()
    if destination.is_symlink() or destination.exists() or destination.parent.is_symlink():
        raise ValidationError("Restore staging directory must be new")
    destination.mkdir(mode=0o700)
    try:
        for name, raw in files.items():
            _atomic(destination / name, raw)
        db_path = destination / "metadata.sqlite3"
        _atomic(db_path, database)
        _check_database(db_path)
        store = Store(db_path)
        agent = NetworkAgent(state, config_dir=destination, state_dir=destination, offline=True)
        with store.connect() as db:
            settings = dict(db.execute("SELECT key,value FROM settings"))
            devices = [dict(row) for row in db.execute("SELECT * FROM devices")]
        if settings.get("subnet") != state["subnet"] or settings.get("managed_legacy_adopted") != "1":
            raise ValidationError("Checkpoint metadata is not adopted or has a different subnet")
        by_id = {device["id"]: device for device in devices}
        for identifier, record in registry["devices"].items():
            device = by_id.get(identifier)
            if (device is None or set(record) != {"phase", "spec", "legacy", "enabled"}
                    or type(record["enabled"]) is not bool or type(record["legacy"]) is not bool
                    or record["legacy"] != (device["origin"] == "legacy")
                    or record["phase"] != ("active" if record["enabled"] else "revoked")
                    or record["enabled"] != bool(device["enabled"]) or record["spec"] != agent._validate(device)):
                raise ValidationError("Checkpoint root ownership and metadata disagree")
        for device in devices:
            record = registry["devices"].get(device["id"])
            peer = peers.get(device["wg_public_key"])
            cid = clients["clients"].get(device["cid"])
            if device["enabled"]:
                if not record or not peer or not isinstance(cid, dict) or cid.get("comment") != "FTM:" + device["id"]:
                    raise ValidationError("Enabled device is absent from the checkpoint")
                if (peer.get("PresharedKey") != device["preshared_key"]
                        or set(part.strip() for part in peer["AllowedIPs"].split(",")) != set(record["spec"]["allowed_ips"])):
                    raise ValidationError("Persisted peer credentials differ from metadata")
            elif peer is not None or cid is not None:
                raise ValidationError("Revoked device retains checkpoint access")
        # Metadata rows may have no registry only after successful manager revoke.
        return {"format": "ftm-checkpoint", "devices": len(devices), "owned_peers": len(registry["devices"]),
                "staged": True, "live_system_changed": False}
    except BaseException:
        # Only delete exact files we created in this new private directory.
        for name in (*files, "metadata.sqlite3", "metadata.sqlite3-wal", "metadata.sqlite3-shm"):
            (destination / name).unlink(missing_ok=True)
        destination.rmdir()
        raise


def capture(store, agent, *, web_config_path=None):
    paths = {"wireguard.conf": agent.config / "wireguard.conf", "clients.json": agent.config / "clients.json", "managed.json": agent.registry}
    if any(path.is_symlink() or not path.is_file() or path.stat().st_size > 2 * 1024 ** 2 for path in paths.values()):
        raise ValidationError("Unsafe checkpoint source file")
    # Caller holds the root lifecycle lock; BEGIN IMMEDIATE freezes metadata
    # writers while a separate read connection uses SQLite Backup API.
    with store.transaction(), tempfile.TemporaryDirectory(prefix="ftm-checkpoint-") as temporary:
        database = Path(temporary) / "metadata.sqlite3"
        store.backup(database)
        files = {name: path.read_bytes() for name, path in paths.items()}
        files["state.json"] = json.dumps(agent.baseline).encode()
        if web_config_path is not None and Path(web_config_path).exists():
            from .web_auth import validate_config
            validate_config(read_private_json(web_config_path, 16384))
            files["web.json"] = Path(web_config_path).read_bytes()
        snapshot = {"format": "ftm-checkpoint", "version": 2 if "web.json" in files else 1,
                    "files": {name: base64.b64encode(raw).decode() for name, raw in files.items()},
                    "database": base64.b64encode(database.read_bytes()).decode()}
        stage(snapshot, Path(temporary) / "check")
        return snapshot


def capture_live(store, agent):
    return capture(store, agent, web_config_path=WEB_CONFIG)


def _restore_database(source, destination):
    source_db = sqlite3.connect(source.as_uri() + "?mode=ro&immutable=1", uri=True)
    target_db = sqlite3.connect(destination)
    try:
        source_db.backup(target_db)
        if target_db.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise ValidationError("Restored database failed integrity check")
    finally:
        target_db.close()
        source_db.close()


def restore_same_host(staged, store, agent, *, runner=_run, after_write=None):
    """Called only under lifecycle flock, after a validated staged restore."""
    staged = Path(staged)
    restored_state = read_private_json(staged / "state.json", 2 * 1024 ** 2)
    if restored_state != agent.baseline:
        raise ValidationError("Same-host restore must preserve the complete baseline identity")
    includes_web = (staged / "web.json").is_file()
    if includes_web != WEB_CONFIG.is_file():
        raise ValidationError("Same-host restore must include the currently provisioned web settings")
    edge_path = Path("/etc/ftm/https.json")
    includes_edge = includes_web and (edge_path.exists() or edge_path.is_symlink())
    if includes_edge:
        from .https_edge import planned_config
        planned_config(agent.baseline, read_private_json(staged / "web.json", 16384))
    # Revalidate even when called independently of the CLI.
    with tempfile.TemporaryDirectory(prefix="ftm-restore-") as temporary:
        root = Path(temporary)
        names = FILES | {"web.json"} if includes_web else FILES
        candidate = {"format": "ftm-checkpoint", "version": 2 if includes_web else 1,
                     "files": {name: base64.b64encode((staged / name).read_bytes()).decode() for name in names},
                     "database": base64.b64encode((staged / "metadata.sqlite3").read_bytes()).decode()}
        stage(candidate, root / "validated")
        previous = capture_live(store, agent)
        stage(previous, root / "rollback")
        api_was_active = False
        caddy_was_active = False
        if includes_web:
            try:
                api_was_active = runner(["systemctl", "is-active", "ftm-api"]).strip() == "active"
            except RuntimeError:
                pass
        if includes_edge:
            try:
                caddy_was_active = runner(["systemctl", "is-active", "ftm-caddy"]).strip() == "active"
            except RuntimeError:
                pass

        def write(source):
            _atomic(agent.config / "wireguard.conf", (source / "wireguard.conf").read_bytes())
            _atomic(agent.config / "clients.json", (source / "clients.json").read_bytes())
            _atomic(agent.config / "obf.key", agent.baseline["obf_key"] + "\n", mode=0o640)
            _atomic(agent.registry, (source / "managed.json").read_bytes())
            if includes_web:
                _atomic(WEB_CONFIG, (source / "web.json").read_bytes())
            if includes_edge:
                from .https_edge import sync_config
                sync_config(agent.baseline)
            _restore_database(source / "metadata.sqlite3", store.path)
            runner(["wg", "syncconf", agent.interface, str(agent.config / "wireguard.conf")])

        def start_vpn():
            # Explicit maintenance can legitimately exceed the unchanged
            # four-starts/five-minutes crash-loop limit.
            runner(["systemctl", "reset-failed", "vps-vk"])
            runner(["systemctl", "start", "vps-vk"])
            if api_was_active:
                runner(["systemctl", "reset-failed", "ftm-api"])
                runner(["systemctl", "start", "ftm-api"])
                import time
                import urllib.request
                for attempt in range(20):
                    try:
                        with urllib.request.urlopen("http://127.0.0.1:8080/", timeout=2) as response:
                            if response.status != 200:
                                raise RuntimeError("API recovery health check failed")
                        break
                    except (OSError, RuntimeError):
                        if attempt == 19:
                            raise RuntimeError("API recovery health check failed") from None
                        time.sleep(0.2)
            if caddy_was_active:
                runner(["systemctl", "reset-failed", "ftm-caddy"])
                runner(["systemctl", "start", "ftm-caddy"])
                from .https_edge import wait_ready
                wait_ready(agent.baseline["endpoint"], tls=True)

        try:
            if caddy_was_active:
                runner(["systemctl", "stop", "ftm-caddy"])
            if api_was_active:
                runner(["systemctl", "stop", "ftm-api"])
            runner(["systemctl", "stop", "vps-vk"])
            write(root / "validated")
            if after_write:
                after_write()
            start_vpn()
            from .compat import managed_status
            if not managed_status(agent.baseline, agent._registry(), runner)["consistent"]:
                raise RuntimeError("Restored VPN health check failed")
        except BaseException:
            try:
                if caddy_was_active:
                    runner(["systemctl", "stop", "ftm-caddy"])
                if api_was_active:
                    runner(["systemctl", "stop", "ftm-api"])
                write(root / "rollback")
                start_vpn()
            except BaseException:
                raise RuntimeError("Restore failed and recovery needs root attention") from None
            raise RuntimeError("Restore failed; previous checkpoint recovered") from None
    return {"restored": True, "same_host_only": True, "ssh_and_firewall_changed": False,
            "web_settings_restored": includes_web, "api_sessions_reset": api_was_active,
            "https_config_regenerated": includes_edge}


def _read_encrypted(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_CIPHER:
        raise ValidationError("Invalid encrypted checkpoint file")
    if os.name == "posix" and (path.stat().st_uid != 0 or path.stat().st_mode & 0o077):
        raise ValidationError("Encrypted checkpoint must be root-owned and private")
    return path.read_bytes()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("backup", "restore"))
    parser.add_argument("file", type=Path)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args(argv)
    if os.name != "posix" or os.geteuid() != 0:
        parser.error("Requires root on Linux")
    if args.apply and args.dry_run:
        parser.error("Choose --apply or --dry-run")
    import fcntl
    fd = os.open("/run/lock/vps-vk.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        state = read_private_json("/var/lib/vps-vk/main/state.json", 1048576)
        baseline_module().check_keypairs(state)
        store = Store("/var/lib/ftm/manager.sqlite3")
        agent = NetworkAgent(state, config_dir="/etc/vps-vk/main", state_dir="/var/lib/ftm-agent")
        password = getpass.getpass("Recovery phrase (12+ characters): ")
        if args.command == "backup":
            if args.dry_run or args.apply:
                parser.error("backup writes only an encrypted file; no apply/dry-run flags")
            if password != getpass.getpass("Repeat recovery phrase: "):
                raise ValidationError("Recovery phrases differ")
            data = seal(capture_live(store, agent), password)
            output_fd = os.open(args.file, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(output_fd, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            print(json.dumps({"encrypted_checkpoint_created": True, "offsite_copy_required": True}))
        else:
            snapshot = open_checkpoint(_read_encrypted(args.file), password)
            del password
            with tempfile.TemporaryDirectory(prefix="ftm-restore-stage-") as temporary:
                target = Path(temporary) / "restore"
                report = stage(snapshot, target)
                baseline_module().check_keypairs(read_private_json(target / "state.json", 2 * 1024 ** 2))
                if args.apply:
                    report = restore_same_host(target, store, agent)
                print(json.dumps(report))
        return 0
    finally:
        os.close(fd)


def safe_main(argv=None):
    try:
        return main(argv)
    except (ValueError, RuntimeError, OSError, sqlite3.Error):
        print("Checkpoint operation failed; private data withheld", file=__import__("sys").stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(safe_main())
