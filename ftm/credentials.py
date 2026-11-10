"""Hash-only subscription/device credential lifecycle. No public endpoints yet."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import uuid

from .store import Store, ValidationError, _now


def _identifier(value):
    try:
        return str(uuid.UUID(value))
    except (ValueError, TypeError, AttributeError):
        raise ValidationError("Invalid credential subject") from None


def _digest(token, kind):
    prefix = {"user": "ftmu1_", "device": "ftmd1_", "bootstrap": "ftmb1_"}[kind]
    if not isinstance(token, str) or not re.fullmatch(prefix + r"[A-Za-z0-9_-]{43}", token):
        return None
    return hashlib.sha256(("ftm/credential/" + kind + "/" + token).encode()).hexdigest()


class Credentials:
    def __init__(self, store):
        self.store = store

    def issue_subscription(self, user_id, *, deliver=None, request_id=None):
        user_id = _identifier(user_id)
        request_id = _identifier(request_id) if request_id is not None else None
        token = "ftmu1_" + secrets.token_urlsafe(32)
        with self.store.transaction() as db:
            if not db.execute("SELECT 1 FROM users WHERE id=? AND enabled=1", (user_id,)).fetchone():
                raise ValidationError("Enabled user required")
            previous = db.execute("SELECT id,version FROM subscriptions WHERE user_id=?", (user_id,)).fetchone()
            identifier, version = (previous["id"], previous["version"] + 1) if previous else (str(uuid.uuid4()), 1)
            db.execute("""INSERT INTO subscriptions(id,user_id,token_hash,version,revoked_at) VALUES(?,?,?,?,NULL)
                       ON CONFLICT(user_id) DO UPDATE SET token_hash=excluded.token_hash,version=excluded.version,revoked_at=NULL""",
                       (identifier, user_id, _digest(token, "user"), version))
            if request_id is not None:
                db.execute('INSERT INTO settings VALUES(?,?)', ('admin_export/' + request_id,
                           json.dumps({'kind': 'subscription', 'user_id': user_id})))
            self.store._audit(db, "subscription.rotate" if previous else "subscription.issue", "subscription", identifier)
            value = {"id": identifier, "user_id": user_id, "version": version, "token": token}
            if deliver:
                deliver(value)
        # The caller must deliver privately. No list or audit stores plaintext.
        return value

    def revoke_subscription(self, user_id):
        user_id = _identifier(user_id)
        with self.store.transaction() as db:
            previous = db.execute("SELECT id,revoked_at FROM subscriptions WHERE user_id=?", (user_id,)).fetchone()
            if previous is None:
                raise ValidationError("Subscription not found")
            if previous["revoked_at"] is None:
                db.execute("UPDATE subscriptions SET revoked_at=?,version=version+1 WHERE user_id=?", (_now(), user_id))
                self.store._audit(db, "subscription.revoke", "subscription", previous["id"])

    def subscription(self, token):
        digest = _digest(token, "user")
        if digest is None:
            return None
        with self.store.connect() as db:
            value = db.execute("""SELECT s.id,s.user_id,s.version FROM subscriptions s JOIN users u ON u.id=s.user_id
                               WHERE s.token_hash=? AND s.revoked_at IS NULL AND u.enabled=1""", (digest,)).fetchone()
            return dict(value) if value else None

    def issue_device(self, device_id, *, deliver=None):
        device_id = _identifier(device_id)
        token = "ftmd1_" + secrets.token_urlsafe(32)
        with self.store.transaction() as db:
            device = db.execute("""SELECT d.id FROM devices d JOIN users u ON u.id=d.user_id
                                WHERE d.id=? AND d.enabled=1 AND d.state='active' AND u.enabled=1 AND d.platform!='ios'""",
                                (device_id,)).fetchone()
            if device is None:
                raise ValidationError("Active non-iOS device and enabled user required")
            now, identifier = _now(), str(uuid.uuid4())
            db.execute("UPDATE device_tokens SET revoked_at=? WHERE device_id=? AND revoked_at IS NULL", (now, device_id))
            db.execute("INSERT INTO device_tokens VALUES(?,?,?,?,NULL)", (identifier, device_id, _digest(token, "device"), now))
            self.store._audit(db, "credential.issue", "device", device_id)
            value = {"id": identifier, "device_id": device_id, "token": token}
            if deliver:
                deliver(value)
        return value

    def revoke_device_credential(self, device_id):
        device_id = _identifier(device_id)
        with self.store.transaction() as db:
            if not db.execute("SELECT 1 FROM devices WHERE id=?", (device_id,)).fetchone():
                raise ValidationError("Device not found")
            db.execute("UPDATE device_tokens SET revoked_at=? WHERE device_id=? AND revoked_at IS NULL", (_now(), device_id))
            self.store._audit(db, "credential.revoke", "device", device_id)

    def device(self, token):
        digest = _digest(token, "device")
        if digest is None:
            return None
        with self.store.connect() as db:
            value = db.execute("""SELECT t.id,d.id AS device_id,d.user_id,d.revision FROM device_tokens t
                               JOIN devices d ON d.id=t.device_id JOIN users u ON u.id=d.user_id
                               WHERE t.token_hash=? AND t.revoked_at IS NULL AND d.enabled=1 AND d.state='active'
                               AND u.enabled=1 AND d.platform!='ios'""", (digest,)).fetchone()
            return dict(value) if value else None


def main():
    parser = argparse.ArgumentParser(description=__doc__ + " Revoking tokens leaves VPN peers unchanged.")
    parser.add_argument("subject", choices=("user-link", "device-access"))
    parser.add_argument("action", choices=("issue", "revoke"))
    parser.add_argument("--id", required=True)
    parser.add_argument("--output", type=Path, help="Issue only: NEW private0600 artifact, never stdout")
    args = parser.parse_args()
    if os.name != "posix" or os.geteuid() != 0:
        parser.error("Requires root on Linux; no API credential export is enabled")
    if (args.action == "issue") != (args.output is not None):
        parser.error("Issue requires --output; revoke accepts no output")
    db_path = Path("/var/lib/ftm/manager.sqlite3")
    if db_path.is_symlink() or db_path.stat().st_uid != 0 or db_path.stat().st_mode & 0o077:
        raise ValidationError("Root-owned private metadata required")
    import fcntl
    lock = os.open("/run/lock/vps-vk.lock", os.O_RDWR | os.O_NOFOLLOW)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX)
        credentials = Credentials(Store(db_path))
        if args.action == "revoke":
            operation = credentials.revoke_subscription if args.subject == "user-link" else credentials.revoke_device_credential
            operation(args.id)
        else:
            parent = args.output.absolute().parent
            if parent.is_symlink() or parent.stat().st_uid != 0 or parent.stat().st_mode & 0o077:
                raise ValidationError("Credential output requires a private root directory")
            # Refuse an existing/symlink output before rotating any credential.
            fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as output:
                    operation = credentials.issue_subscription if args.subject == "user-link" else credentials.issue_device
                    def deliver(value):
                        output.write(json.dumps(value))
                        output.flush()
                        os.fsync(output.fileno())
                        parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
                        try:
                            os.fsync(parent_fd)
                        finally:
                            os.close(parent_fd)
                    operation(args.id, deliver=deliver)
            except BaseException:
                args.output.unlink(missing_ok=True)
                raise
        print(json.dumps({"credential_operation_completed": True, "action": args.action,
                          "plaintext_printed": False, "vpn_peers_changed": False}))
    finally:
        os.close(lock)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("Credential operation failed; private data withheld", file=__import__("sys").stderr)
        raise SystemExit(1)
