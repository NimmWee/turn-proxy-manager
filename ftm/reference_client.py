"""Contract-only caller. No VPN adapter, traffic routing or native secure storage."""

import hashlib
import http.client
import ipaddress
import json
import ssl
import socket
import urllib.error
import urllib.request
from urllib.parse import urlsplit

from .credentials import _digest
from .managed_profile import to_share, validate_manifest


class ClientSyncError(RuntimeError):
    def __init__(self, status=None):
        self.status = status
        super().__init__("Client synchronization failed; last good configuration retained")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class _InternalHTTPS(urllib.request.HTTPSHandler):
    def __init__(self, origin, address):
        super().__init__(context=ssl.create_default_context())
        self.identity = urlsplit(origin).hostname
        try:
            ip = ipaddress.IPv4Address(address)
        except (ValueError, TypeError):
            raise ClientSyncError() from None
        if not any(ip in ipaddress.ip_network(net) for net in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16')):
            raise ClientSyncError()
        self.address = str(ip)

    def https_open(self, request):
        if urlsplit(request.full_url).hostname != self.identity:
            raise ClientSyncError()

        def connection(host, **kwargs):
            result = http.client.HTTPSConnection(host, **kwargs)

            def dial(destination, timeout=socket._GLOBAL_DEFAULT_TIMEOUT, source_address=None):
                if destination != (self.identity, 443):
                    raise ClientSyncError()
                return socket.create_connection((self.address, 443), timeout, source_address)

            # HTTPSConnection still wraps TLS using its original host identity.
            result._create_connection = dial
            return result

        return self.do_open(connection, request, context=self._context)


class ReferenceClient:
    def __init__(self, origin, *, private_key, public_key, device_token, client_id, internal_address=None):
        parsed = urlsplit(origin)
        if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.path
                or parsed.query or parsed.fragment or parsed.port not in (None, 443) or _digest(device_token, "device") is None):
            raise ClientSyncError()
        self.origin, self.private_key, self.public_key = origin, private_key, public_key
        self.token, self.client_id = device_token, client_id
        self.etag = self.last_good = self.last_share = None
        self.state = "UNCONFIGURED"
        transport = _InternalHTTPS(origin, internal_address) if internal_address is not None else urllib.request.HTTPSHandler(context=ssl.create_default_context())
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect(), transport)

    def _request(self, operation, token, body=None, etag=None):
        headers = {"Authorization": "Bearer " + token, "Accept": "application/json"}
        if etag:
            headers["If-None-Match"] = etag
        raw = None
        if body is not None:
            raw = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(self.origin + "/api/client/v1/" + operation, data=raw, headers=headers)
        try:
            try:
                response = self.opener.open(request, timeout=15)
            except urllib.error.HTTPError as error:
                response = error
            with response:
                data = response.read(65537)
                if len(data) > 65536:
                    raise ClientSyncError()
                if response.status not in (200, 202, 304):
                    raise ClientSyncError(response.status)
                if response.status == 304:
                    return response.status, None, response.headers.get("ETag")
                from .installer import _unique_object
                return response.status, json.loads(data, object_pairs_hook=_unique_object), response.headers.get("ETag")
        except (OSError, ValueError, urllib.error.URLError):
            raise ClientSyncError() from None

    def enroll(self, user_token, *, name, platform, request_id):
        status, data, _ = self._request("enroll", user_token, {"name": name, "platform": platform, "public_key": self.public_key,
                                      "client_id": self.client_id, "device_token_hash": _digest(self.token, "device"), "request_id": request_id})
        self.state = "PENDING" if status == 202 else "REGISTERED"
        return data

    def status(self):
        _, data, _ = self._request("status", self.token)
        return data

    def refresh(self):
        try:
            status, value, etag = self._request("subscription", self.token, etag=self.etag if self.last_good else None)
            if status == 202:
                self.state = "PENDING"
                return False
            if status == 304:
                if self.last_good is None or etag != self.etag:
                    raise ClientSyncError()
                self.state = "MANAGED"
                return False
            validate_manifest(value, expected_public_key=self.public_key, expected_origin=self.origin)
            expected = '"' + hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()).hexdigest() + '"'
            if etag != expected:
                raise ClientSyncError()
            share = to_share(value, self.private_key, expected_public_key=self.public_key, expected_origin=self.origin)
            # All validation/local construction succeeds before committing the new snapshot.
            self.last_good, self.last_share, self.etag, self.state = value, share, etag, "MANAGED"
            return True
        except (ClientSyncError, ValueError) as error:
            self.state = "REVOKED" if isinstance(error, ClientSyncError) and error.status in (401, 403) else "DEGRADED"
            raise ClientSyncError(getattr(error, "status", None)) from None
