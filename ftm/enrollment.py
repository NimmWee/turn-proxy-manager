"""Atomic enrollment core; no HTTP/IPC endpoint or client-private-key handling."""

import re
import uuid

from .credentials import _digest, _identifier
from .store import Conflict, ValidationError, _now


class Enrollment:
    def __init__(self, store):
        self.store = store

    def register(self, user_token, *, name, platform, public_key, client_id, device_token_hash, request_id):
        user_hash = _digest(user_token, "user")
        if user_hash is None:
            raise ValidationError("Enrollment authorization failed")
        if platform not in ("android", "windows", "other"):
            raise ValidationError("This platform requires manual profile delivery")
        if not isinstance(device_token_hash, str) or not re.fullmatch(r"[a-f0-9]{64}", device_token_hash):
            raise ValidationError("Invalid client credential digest")
        request_id = _identifier(request_id)
        with self.store.transaction() as db:
            subscription = db.execute("""SELECT s.id,s.user_id,s.version FROM subscriptions s
                                      JOIN users u ON u.id=s.user_id
                                      WHERE s.token_hash=? AND s.revoked_at IS NULL AND u.enabled=1""", (user_hash,)).fetchone()
            if subscription is None:
                raise ValidationError("Enrollment authorization failed")
            device = self.store._create_device(db, subscription["user_id"], name, platform, public_key, request_id,
                                               client_id=client_id, credential_hash=device_token_hash)
            if not device["enabled"] or device["state"] in ("revoking", "revoked"):
                raise Conflict("An enrollment retry cannot enable a revoked device")
            known = db.execute("SELECT token_hash,revoked_at FROM device_tokens WHERE device_id=?", (device["id"],)).fetchall()
            if known:
                if not any(row["token_hash"] == device_token_hash and row["revoked_at"] is None for row in known):
                    raise Conflict("An enrollment retry cannot reissue a rotated or revoked credential")
            else:
                db.execute("INSERT INTO device_tokens VALUES(?,?,?,?,NULL)",
                           (str(uuid.uuid4()), device["id"], device_token_hash, _now()))
                self.store._audit(db, "device.enroll", "device", device["id"])
            return {"device_id": device["id"], "subscription_id": subscription["id"],
                    "subscription_version": subscription["version"], "revision": device["revision"],
                    "state": device["state"], "ip": device["ip"]}
