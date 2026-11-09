"""Transactional metadata store. No WireGuard/systemd commands and no VPN private keys."""

import base64
import contextlib
import datetime
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import secrets
import sqlite3
import stat
import uuid

from .legacy import validate_legacy_state


class ValidationError(ValueError):
    pass


class Conflict(ValidationError):
    pass


def valid_key(value):
    try:
        raw = base64.b64decode(value, validate=True)
        return isinstance(value, str) and len(raw) == 32 and any(raw) and base64.b64encode(raw).decode() == value
    except (ValueError, TypeError):
        return False


def _name(value):
    if not isinstance(value, str) or not 1 <= len(value.strip()) <= 128 or any(ord(char) < 32 for char in value):
        raise ValidationError("Invalid name")
    return value.strip()


def _now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _hash(value):
    return hashlib.sha256(value.encode()).hexdigest()


class Store:
    def __init__(self, path):
        self.path = Path(path).absolute()

    def _prepare(self):
        if self.path.is_symlink() or self.path.parent.is_symlink():
            raise ValidationError("Database symlinks are not allowed")
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if os.name == "posix" and self.path.parent.stat().st_mode & 0o077:
            raise ValidationError("Database directory must have private permissions")
        fd = os.open(self.path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ValidationError("Database must be a regular private file")
            if os.name == "posix" and stat.S_IMODE(info.st_mode) != 0o600:
                raise ValidationError("Database file must have mode 0600")
        finally:
            os.close(fd)

    @contextlib.contextmanager
    def connect(self):
        self._prepare()
        db = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        db.row_factory = sqlite3.Row
        try:
            db.execute("PRAGMA busy_timeout=30000")
            db.execute("PRAGMA foreign_keys=ON")
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("PRAGMA synchronous=FULL")
            yield db
        finally:
            db.close()

    @contextlib.contextmanager
    def transaction(self):
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                yield db
                db.execute("COMMIT")
            except BaseException as error:
                db.execute("ROLLBACK")
                if isinstance(error, sqlite3.IntegrityError):
                    raise Conflict("Conflicting device or metadata operation") from None
                raise

    def initialize(self):
        with self.connect() as db:
            tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if tables and "migration_versions" not in tables:
                raise ValidationError("Refusing unrecognized database")
            if "migration_versions" in tables:
                version = db.execute("SELECT max(version) FROM migration_versions").fetchone()[0]
                if version != 1 or db.execute("PRAGMA application_id").fetchone()[0] != 1179934001:
                    raise ValidationError("Unsupported database version")
            db.executescript((Path(__file__).parent / "migrations/001_initial.sql").read_text(encoding="utf-8"))

    @staticmethod
    def _audit(db, action, kind, identifier):
        db.execute("INSERT INTO audit_events(actor,action,subject_type,subject_id,ts) VALUES('local',?,?,?,?)",
                   (action, kind, identifier, _now()))

    @staticmethod
    def _queue(db, device_id, revision):
        now = _now()
        db.execute("INSERT INTO operations VALUES(?,?,?,'pending',?,?)", (str(uuid.uuid4()), device_id, revision, now, now))

    def create_user(self, name, device_limit=None):
        name = _name(name)
        if device_limit is not None and (type(device_limit) is not int or device_limit < 1):
            raise ValidationError("Invalid device limit")
        identifier, now = str(uuid.uuid4()), _now()
        with self.transaction() as db:
            db.execute("INSERT INTO users VALUES(?,?,1,?,?,?)", (identifier, name, device_limit, now, now))
            self._audit(db, "user.create", "user", identifier)
        return {"id": identifier, "name": name, "enabled": True, "device_limit": device_limit}

    def list_users(self):
        with self.connect() as db:
            return [dict(row) for row in db.execute("SELECT * FROM users ORDER BY created_at,id")]

    def list_devices(self, user_id=None):
        fields = "id,user_id,name,platform,vpn_type,ip,enabled,state,origin,revision,last_handshake_at,created_at"
        with self.connect() as db:
            rows = db.execute(f"SELECT {fields} FROM devices" + (" WHERE user_id=?" if user_id else "") + " ORDER BY created_at,id",
                              (user_id,) if user_id else ())
            return [dict(row) for row in rows]

    def get_device(self, identifier):
        """Internal credential-bearing result; ordinary CLI output must use list_devices."""
        with self.connect() as db:
            row = db.execute("SELECT * FROM devices WHERE id=?", (identifier,)).fetchone()
            if row is None:
                raise ValidationError("Device not found")
            return dict(row)

    def create_device(self, user_id, name, platform, public_key, request_id, *, vpn_type="wg"):
        name = _name(name)
        if platform not in ("android", "windows", "ios", "other") or vpn_type != "wg":
            raise ValidationError("Unsupported platform or unverified VPN backend")
        if not valid_key(public_key):
            raise ValidationError("Invalid WireGuard public key")
        if not isinstance(request_id, str) or not 1 <= len(request_id) <= 200:
            raise ValidationError("Invalid idempotency key")
        request_hash = _hash(request_id)
        fingerprint = _hash(json.dumps([user_id, name, platform, public_key, vpn_type], separators=(",", ":")))
        with self.transaction() as db:
            user = db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
            if user is None or not user["enabled"]:
                raise ValidationError("User is missing or disabled")
            existing = db.execute("SELECT * FROM devices WHERE user_id=? AND request_hash=?", (user_id, request_hash)).fetchone()
            if existing:
                if existing["request_fingerprint"] != fingerprint:
                    raise Conflict("Idempotency key was already used for a different request")
                return dict(existing)
            active = db.execute("SELECT count(*) FROM devices WHERE user_id=? AND enabled=1", (user_id,)).fetchone()[0]
            if user["device_limit"] is not None and active >= user["device_limit"]:
                raise ValidationError("Device limit reached")
            subnet = ipaddress.ip_network(db.execute("SELECT value FROM settings WHERE key='subnet'").fetchone()[0])
            next_ip = int(db.execute("SELECT value FROM settings WHERE key='next_ip'").fetchone()[0])
            next_ip = max(10, next_ip)
            occupied = {row[0] for row in db.execute("SELECT ip FROM devices")}
            while next_ip <= 254 and str(subnet.network_address + next_ip) in occupied:
                next_ip += 1
            if next_ip > 254:
                raise ValidationError("VPN address pool exhausted")
            identifier = str(uuid.uuid4())
            psk = base64.b64encode(secrets.token_bytes(32)).decode()
            db.execute("""INSERT INTO devices(id,user_id,name,platform,vpn_type,wg_public_key,preshared_key,cid,ip,
                       enabled,state,origin,revision,request_hash,request_fingerprint,created_at)
                       VALUES(?,?,?,?,?,?,?,?,?,1,'pending','manager',1,?,?,?)""",
                       (identifier, user_id, name, platform, vpn_type, public_key, psk, secrets.token_hex(16),
                        str(subnet.network_address + next_ip), request_hash, fingerprint, _now()))
            db.execute("UPDATE settings SET value=? WHERE key='next_ip'", (str(next_ip + 1),))
            self._queue(db, identifier, 1)
            self._audit(db, "device.create", "device", identifier)
            return dict(db.execute("SELECT * FROM devices WHERE id=?", (identifier,)).fetchone())

    def revoke_device(self, identifier):
        with self.transaction() as db:
            device = db.execute("SELECT * FROM devices WHERE id=?", (identifier,)).fetchone()
            if device is None:
                raise ValidationError("Device not found")
            if device["origin"] == "legacy":
                raise ValidationError("Legacy revocation requires managed startup migration")
            if not device["enabled"]:
                return
            revision = device["revision"] + 1
            db.execute("UPDATE devices SET enabled=0,state='revoking',revision=? WHERE id=?", (revision, identifier))
            self._queue(db, identifier, revision)
            self._audit(db, "device.revoke", "device", identifier)

    def set_user_enabled(self, identifier, enabled):
        if type(enabled) is not bool:
            raise ValidationError("Invalid enabled flag")
        with self.transaction() as db:
            if db.execute("SELECT id FROM users WHERE id=?", (identifier,)).fetchone() is None:
                raise ValidationError("User not found")
            if not enabled and db.execute("SELECT id FROM devices WHERE user_id=? AND origin='legacy' AND enabled=1", (identifier,)).fetchone():
                raise ValidationError("Legacy user disable requires managed startup migration")
            db.execute("UPDATE users SET enabled=?,updated_at=? WHERE id=?", (int(enabled), _now(), identifier))
            if not enabled:
                for device in db.execute("SELECT id,revision FROM devices WHERE user_id=? AND enabled=1", (identifier,)).fetchall():
                    revision = device["revision"] + 1
                    db.execute("UPDATE devices SET enabled=0,state='revoking',revision=? WHERE id=?", (revision, device["id"]))
                    self._queue(db, device["id"], revision)
            self._audit(db, "user.enable" if enabled else "user.disable", "user", identifier)

    def import_legacy(self, state):
        validate_legacy_state(state)
        identity = {"instance": state["instance"], "subnet": state["subnet"],
                    "server_public": state["server_public"], "clients": {
                        name: {key: value for key, value in peer.items() if key != "private_key"}
                        for name, peer in state["clients"].items()}}
        fingerprint = _hash(json.dumps(identity, sort_keys=True, separators=(",", ":")))
        marker = "legacy_import_" + state["instance"]
        user_id = str(uuid.uuid5(uuid.NAMESPACE_URL, "ftm/legacy/" + state["instance"]))
        with self.transaction() as db:
            existing = db.execute("SELECT value FROM settings WHERE key=?", (marker,)).fetchone()
            if existing:
                if existing[0] != fingerprint:
                    raise Conflict("Legacy metadata differs from the imported baseline")
                return {"imported_devices": 0, "user_id": user_id}
            subnet = db.execute("SELECT value FROM settings WHERE key='subnet'").fetchone()[0]
            if subnet != state["subnet"] and db.execute("SELECT count(*) FROM devices").fetchone()[0]:
                raise Conflict("Existing devices use another subnet")
            now = _now()
            db.execute("INSERT INTO users VALUES(?,?,1,NULL,?,?)", (user_id, "Исходные устройства", now, now))
            network = ipaddress.ip_network(state["subnet"])
            for name, offset, platform in [("iphone", 2, "ios"), ("android", 3, "android")]:
                peer = state["clients"][name]
                identifier = str(uuid.uuid5(uuid.NAMESPACE_URL, "ftm/legacy/" + state["instance"] + "/" + name))
                db.execute("""INSERT INTO devices(id,user_id,name,platform,vpn_type,wg_public_key,preshared_key,cid,ip,
                           enabled,state,origin,revision,request_hash,request_fingerprint,created_at)
                           VALUES(?,?,?,?,'wg',?,?,?,?,1,'active','legacy',1,?,?,?)""",
                           (identifier, user_id, name, platform, peer["public_key"], peer["preshared_key"], peer["cid"],
                            str(network.network_address + offset), _hash("legacy/" + name), fingerprint, now))
            for name, value in [("subnet", state["subnet"]), (marker, fingerprint)]:
                db.execute("INSERT OR REPLACE INTO settings VALUES(?,?)", (name, value))
            self._audit(db, "legacy.import", "user", user_id)
            return {"imported_devices": 2, "user_id": user_id}

    def backup(self, destination):
        destination = Path(destination)
        if destination.parent.is_symlink():
            raise ValidationError("Backup directory symlink rejected")
        fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(fd)
        try:
            target = sqlite3.connect(destination)
            try:
                with self.connect() as source:
                    source.backup(target)
                if target.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                    raise ValidationError("Database backup integrity check failed")
            finally:
                target.close()
        except BaseException:
            destination.unlink(missing_ok=True)
            raise
