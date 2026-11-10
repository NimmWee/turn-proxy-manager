"""Native bearer-only HTTPS routes. No ambient cookie authorization or token URLs."""

import asyncio
from collections import deque
import hashlib
import threading
import time
from typing import Literal
import uuid

from fastapi import Depends, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, ConfigDict, Field

from .client_protocol import ClientFault
from .credentials import _digest

PREFIX = "/api/client/v1/"


def problem(code, status=None):
    error = ClientFault(code)
    headers = {"Cache-Control": "no-store"}
    if error.status == 401:
        headers["WWW-Authenticate"] = "Bearer"
    if error.status in (429, 503):
        headers["Retry-After"] = "60" if error.status == 429 else "5"
    return JSONResponse({"error": {"code": error.code, "message": error.message, "correlation_id": uuid.uuid4().hex}},
                        status_code=status or error.status, headers=headers)


class RequestBudget:
    def __init__(self, *, clock=time.monotonic):
        self.clock, self.entries, self.lock = clock, {}, threading.Lock()

    def claim(self, operation, ip, token):
        # Store hashes, never bearer values. Hard bounds cover random-token/IP spray.
        key = hashlib.sha256(token.encode()).hexdigest()
        buckets = [("global", 300), ("ip:" + ip, 120), ("credential:" + key, 30)]
        if operation in ("enroll", "claim"):
            buckets += [("enroll-ip:" + ip, 10), ("enroll-token:" + key, 10)]
        with self.lock:
            now = self.clock()
            for identifier in list(self.entries):
                stamps = self.entries[identifier]
                while stamps and now - stamps[0] >= 60:
                    stamps.popleft()
                if not stamps:
                    del self.entries[identifier]
            if len(self.entries) + sum(identifier not in self.entries for identifier, _ in buckets) > 2048:
                raise ClientFault("rate_limited")
            if any(len(self.entries.get(identifier, ())) >= limit for identifier, limit in buckets):
                raise ClientFault("rate_limited")
            for identifier, _ in buckets:
                self.entries.setdefault(identifier, deque()).append(now)


class Registration(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=128, strict=True)
    platform: Literal["android", "windows", "other"]
    public_key: str = Field(min_length=44, max_length=44, strict=True)
    client_id: str = Field(pattern=r"^[a-f0-9]{32}$", strict=True)
    device_token_hash: str = Field(pattern=r"^[a-f0-9]{64}$", strict=True)
    request_id: uuid.UUID


class BootstrapClaim(BaseModel):
    model_config = ConfigDict(extra="forbid")
    device_id: uuid.UUID
    device_token_hash: str = Field(pattern=r"^[a-f0-9]{64}$", strict=True)


def install_routes(app, rpc, rpc_limit):
    budget = RequestBudget()

    @app.exception_handler(ClientFault)
    async def client_failure(request, error):
        return problem(error.code)

    def bearer(request: Request):
        if request.url.scheme != "https":
            raise ClientFault("credential_invalid")
        if request.url.query:
            raise ClientFault("invalid_request")
        scheme, _, token = request.headers.get("authorization", "").partition(" ")
        # Throttle malformed tokens too, without retaining arbitrary large strings.
        if len(token) > 100:
            token = "invalid"
        operation = request.url.path.rsplit("/", 1)[-1]
        budget.claim(operation, request.client.host if request.client else "unknown", token)
        kind = "bootstrap" if operation == "claim" else "user" if operation == "enroll" else "device"
        if scheme.lower() != "bearer" or _digest(token, kind) is None:
            raise ClientFault("credential_invalid")
        return token

    async def invoke(operation, args):
        try:
            async with rpc_limit:
                return await asyncio.to_thread(rpc, operation, args)
        except ClientFault:
            raise
        except (ValueError, RuntimeError, OSError):
            raise ClientFault("service_unavailable") from None

    @app.post(PREFIX + "enroll")
    async def enroll(value: Registration, token=Depends(bearer)):
        result = await invoke("client.enroll", {"token": token, "registration": value.model_dump(mode="json")})
        return JSONResponse(result, status_code=200 if result["state"] == "active" else 202,
                            headers={"Cache-Control": "no-store", "Retry-After": "5"})

    @app.get(PREFIX + "status")
    async def status(token=Depends(bearer)):
        return await invoke("client.status", {"token": token})

    @app.post(PREFIX + "bootstrap/claim")
    async def bootstrap_claim(value: BootstrapClaim, request: Request, nonce=Depends(bearer)):
        result = await invoke("client.bootstrap_claim", {'nonce': nonce, **value.model_dump(mode='json'),
                              'source_ip': request.client.host if request.client else 'unknown'})
        return JSONResponse(result, headers={"Cache-Control": "no-store"})

    @app.get(PREFIX + "subscription")
    async def subscription(request: Request, token=Depends(bearer)):
        args = {"token": token}
        if "if-none-match" in request.headers:
            args["if_none_match"] = request.headers["if-none-match"]
        result = await invoke("client.subscription", args)
        if not result["ready"]:
            return JSONResponse(result, status_code=202, headers={"Retry-After": "5"})
        headers = {"ETag": result["etag"], "Cache-Control": "private, no-store"}
        if result["not_modified"]:
            return Response(status_code=304, headers=headers)
        return JSONResponse(result["config"], headers=headers)
