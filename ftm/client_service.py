"""Root-owned client operations; authenticated per-device secrets, no private key."""

import hashlib
import json
import re
import uuid

from .client_protocol import ClientFault
from .credentials import _digest
from .enrollment import Enrollment, EnrollmentAuthorization
from .store import Conflict, ValidationError, valid_key


class ClientService:
    def __init__(self, store, agent):
        self.store, self.agent = store, agent

    def enroll(self, token, value):
        try:
            if (not isinstance(value, dict) or set(value) != {"name", "platform", "public_key", "client_id", "device_token_hash", "request_id"}
                    or not all(isinstance(item, str) for item in value.values())
                    or not 1 <= len(value["name"].strip()) <= 128 or any(ord(c) < 32 for c in value["name"])
                    or value["platform"] not in ("android", "windows", "other") or not valid_key(value["public_key"])
                    or not re.fullmatch(r"[a-f0-9]{32}", value["client_id"])
                    or not re.fullmatch(r"[a-f0-9]{64}", value["device_token_hash"])):
                raise ValueError()
            uuid.UUID(value["request_id"])
        except (ValueError, TypeError, KeyError):
            raise ClientFault("invalid_request") from None
        try:
            return Enrollment(self.store).register(token, **value)
        except EnrollmentAuthorization:
            raise ClientFault("credential_invalid") from None
        except Conflict:
            raise ClientFault("enrollment_conflict") from None
        except ValidationError:
            raise ClientFault("enrollment_denied") from None

    def _device(self, token):
        digest = _digest(token, "device")
        if digest is None:
            raise ClientFault("credential_invalid")
        with self.store.connect() as db:
            row = db.execute("""SELECT d.*,t.revoked_at AS token_revoked,u.enabled AS user_enabled
                                FROM device_tokens t JOIN devices d ON d.id=t.device_id JOIN users u ON u.id=d.user_id
                                WHERE t.token_hash=?""", (digest,)).fetchone()
        if row is None:
            raise ClientFault("credential_invalid")
        if not row["enabled"] or not row["user_enabled"] or row["platform"] == "ios":
            raise ClientFault("device_disabled")
        if row["token_revoked"] is not None:
            raise ClientFault("credential_invalid")
        return dict(row)

    @staticmethod
    def _status(device):
        return {"device_id": device["id"], "state": device["state"], "revision": device["revision"],
                "ready": device["state"] == "active", "retry_after_seconds": 0 if device["state"] == "active" else 5}

    def _spec(self, device):
        try:
            spec = self.agent._validate(device)
            record = self.agent._registry()["devices"].get(device["id"])
            if not record or record["enabled"] is not True or record["phase"] != "active" or record["spec"] != spec:
                raise ValueError()
            return spec
        except (ValueError, KeyError, TypeError, OSError):
            raise ClientFault("service_unavailable") from None

    def status(self, token):
        device = self._device(token)
        if device["state"] == "active":
            self._spec(device)
        return self._status(device)

    def subscription(self, token, if_none_match=None):
        # Authorization/disable/rotation must be checked even for a cached ETag.
        device = self._device(token)
        if device["state"] != "active":
            return self._status(device)
        spec = self._spec(device)
        baseline = self.agent.baseline
        host = baseline["endpoint"]
        manifest = {"schema_version": 1, "format": "ftm-managed", "device_id": device["id"],
                    "revision": device["revision"], "name": device["name"], "platform": device["platform"],
                    "wireguard": {"client_public_key": device["wg_public_key"], "addresses": spec["allowed_ips"],
                                  "server_public_key": baseline["server_public"], "preshared_key": device["preshared_key"],
                                  "allowed_ips": ["0.0.0.0/0", "::/0"], "dns": ["1.1.1.1", "8.8.8.8"], "mtu": 1280,
                                  "local_endpoint": "127.0.0.1:9000", "persistent_keepalive": 25, "ipv6_policy": "block"},
                    "freeturn": {"v": 1, "provider": "vk", "peer": host + ":" + str(baseline["port"]),
                                 "transport": "tcp", "mode": "udp", "obf": "rtpopus3", "key": baseline["obf_key"],
                                 "n": 6, "spc": 3, "cid": device["cid"], "dns": "auto", "mcap": True,
                                 "vk": baseline["vk_link"]},
                    "management": {"origin": "https://" + host, "api_path": "/api/client/v1/", "internal_api_ip": str(self.agent.subnet.network_address + 1),
                                   "tls_server_name": host, "refresh_seconds": 1800}}
        from .managed_profile import validate_manifest
        validate_manifest(manifest)
        raw = json.dumps(manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
        etag = '"' + hashlib.sha256(raw).hexdigest() + '"'
        match = False
        if isinstance(if_none_match, str) and len(if_none_match) <= 512:
            match = any(value.strip().removeprefix("W/") in (etag, "*") for value in if_none_match.split(",")[:16])
        return {"ready": True, "etag": etag, "not_modified": match, **({} if match else {"config": manifest})}
