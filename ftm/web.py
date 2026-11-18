"""Rootless private admin API and static panel. All metadata access uses Unix IPC."""

import argparse
import asyncio
import json
from pathlib import Path
from typing import Literal
import uuid

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt
from starlette.middleware.trustedhost import TrustedHostMiddleware

from . import control
from .client_protocol import ClientFault
from .web_auth import Auth, InvalidCredentials, RateLimited, SESSION_TTL, load_config

COOKIE = "ftm_session"
ROOT = Path(__file__).resolve().parents[1]


class BodyLimit:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope["method"] in ("GET", "HEAD", "OPTIONS"):
            return await self.app(scope, receive, send)
        chunks, total = [], 0
        while True:
            try:
                message = await asyncio.wait_for(receive(), timeout=5)
            except asyncio.TimeoutError:
                if scope.get("path", "").startswith("/api/client/v1/"):
                    from .client_web import problem
                    return await problem("invalid_request", 408)(scope, receive, send)
                return await JSONResponse({"detail": "Время загрузки запроса истекло"}, 408)(scope, receive, send)
            if message["type"] == "http.disconnect":
                return
            data = message.get("body", b"")
            total += len(data)
            if total > 16384:
                if scope.get("path", "").startswith("/api/client/v1/"):
                    from .client_web import problem
                    return await problem("invalid_request", 413)(scope, receive, send)
                return await JSONResponse({"detail": "Запрос слишком большой"}, 413, headers={"Connection": "close"})(scope, receive, send)
            chunks.append(data)
            if not message.get("more_body", False):
                break
        delivered = False

        async def bounded_receive():
            nonlocal delivered
            if not delivered:
                delivered = True
                return {"type": "http.request", "body": b"".join(chunks), "more_body": False}
            return await receive()

        await self.app(scope, bounded_receive, send)


class StrictBody(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=False)


class Login(StrictBody):
    username: str = Field(min_length=1, max_length=128, strict=True)
    password: str = Field(min_length=1, max_length=1024, strict=True)


class NewUser(StrictBody):
    name: str = Field(min_length=1, max_length=128, strict=True)
    device_limit: StrictInt | None = Field(default=None, ge=1, le=245)


class Enabled(StrictBody):
    enabled: StrictBool


class NewDevice(StrictBody):
    user_id: uuid.UUID
    name: str = Field(min_length=1, max_length=128, strict=True)
    platform: Literal["android", "windows", "ios", "other"]
    public_key: str = Field(min_length=44, max_length=44, strict=True)
    request_id: uuid.UUID


class RoutingPublish(StrictBody):
    expected_revision: StrictInt = Field(ge=0)
    policy: dict


class ExportSubscription(StrictBody):
    password: str = Field(min_length=1, max_length=1024, strict=True)
    request_id: uuid.UUID


class ExportBootstrap(ExportSubscription):
    name: str = Field(min_length=1, max_length=128, strict=True)
    platform: Literal['android', 'windows', 'other']


class RevokeSubscription(StrictBody):
    password: str = Field(min_length=1, max_length=1024, strict=True)
    expected_version: StrictInt = Field(ge=1, le=2**63 - 2)


def create_app(config, *, rpc=control.request, static_dir=None):
    auth = Auth(config)
    prefix = "/a/" + auth.config["panel_slug"]
    assets = Path(static_dir) if static_dir else ROOT / "web/dist"
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    app.state.auth = auth
    app.add_middleware(BodyLimit)
    public_origin = auth.config.get("public_origin")
    hosts = ["localhost", "127.0.0.1"] + ([public_origin.removeprefix("https://")] if public_origin else [])
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=hosts)
    rpc_limit = asyncio.Semaphore(4)

    @app.middleware("http")
    async def headers(request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Content-Security-Policy"] = ("default-src 'self'; script-src 'self'; style-src 'self'; "
            "img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; "
            "frame-ancestors 'none'; form-action 'self'")
        response.headers["Cache-Control"] = "public,max-age=31536000,immutable" if request.url.path.startswith(prefix + "/assets/") else "no-store"
        return response

    @app.exception_handler(RequestValidationError)
    async def validation_error(request, error):
        # FastAPI's default detail can echo passwords and input values.
        if request.url.path.startswith("/api/client/v1/"):
            from .client_web import problem
            return problem("invalid_request")
        return JSONResponse({"detail": "Проверьте поля формы"}, status_code=422)

    def session(request: Request):
        found = auth.session(request.cookies.get(COOKIE))
        if not found:
            raise HTTPException(401, "Войдите в панель")
        return found

    def origin(request: Request):
        expected = public_origin or str(request.base_url).rstrip("/")
        if request.headers.get("origin") != expected or (public_origin and request.url.scheme != "https"):
            raise HTTPException(403, "Источник запроса не подтверждён")

    def mutation(request: Request, found=Depends(session)):
        origin(request)
        if not auth.authorize_mutation(request.cookies.get(COOKIE), request.headers.get("x-csrf-token")):
            raise HTTPException(403, "Обновите страницу и повторите действие")
        return found

    async def invoke(operation, args=None):
        try:
            async with rpc_limit:
                result = await asyncio.to_thread(rpc, operation, args)
        except ClientFault as error:
            raise HTTPException(error.status, error.message, headers={'Retry-After': '600'} if error.status == 429 else None) from None
        except (ValueError, RuntimeError, OSError):
            raise HTTPException(503, "Сервер занят или действие отклонено. Повторите позже") from None
        if isinstance(result, dict) and isinstance(result.get("apply"), dict) and result["apply"].get("errors"):
            return JSONResponse(result, status_code=202)
        return result

    @app.get("/", response_class=HTMLResponse)
    def landing():
        return ('<!doctype html><html lang="ru"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
                '<title>Личная страница</title><link rel="stylesheet" href="/landing.css"><main><span>Личное пространство</span>'
                '<h1>Здесь будет кое-что новое.</h1><p>Страница готовится к запуску. Загляните чуть позже.</p></main></html>')

    @app.get("/landing.css")
    def landing_css():
        return Response('body{margin:0;background:#f6f8fc;color:#192740;font:18px system-ui,sans-serif;display:grid;min-height:100svh;place-items:center}main{max-width:600px;padding:40px}span{color:#64748b;font-size:14px}h1{font-size:clamp(30px,5vw,48px);letter-spacing:-.04em;line-height:1.15}p{color:#64748b;line-height:1.7}', media_type="text/css")

    @app.get(prefix + "/")
    def panel():
        if not (assets / "index.html").is_file():
            raise HTTPException(503, "Панель собирается")
        return FileResponse(assets / "index.html")

    @app.post(prefix + "/api/auth/login")
    async def login(value: Login, request: Request, response: Response):
        origin(request)
        try:
            token, csrf = await asyncio.to_thread(auth.login, value.username, value.password, request.client.host if request.client else "local")
        except InvalidCredentials:
            raise HTTPException(401, "Неверное имя или пароль") from None
        except RateLimited as error:
            raise HTTPException(429, "Слишком много попыток. Попробуйте позже", headers={"Retry-After": str(error.retry_after)}) from None
        response.set_cookie(COOKIE, token, max_age=SESSION_TTL, httponly=True, secure=auth.config["secure_cookie"],
                            samesite="strict", path=prefix + "/")
        return {"username": auth.config["username"], "csrf": csrf}

    @app.get(prefix + "/api/auth/me")
    def me(found=Depends(session)):
        return {"username": found["username"], "csrf": found["csrf"]}

    @app.post(prefix + "/api/auth/logout", dependencies=[Depends(mutation)])
    def logout(request: Request, response: Response):
        auth.logout(request.cookies.get(COOKIE))
        response.delete_cookie(COOKIE, path=prefix + "/", httponly=True, samesite="strict", secure=auth.config["secure_cookie"])
        return {"logged_out": True}

    @app.get(prefix + "/api/status", dependencies=[Depends(session)])
    async def status():
        return await invoke("status")

    @app.get(prefix + "/api/metrics", dependencies=[Depends(session)])
    async def metrics():
        return await invoke("metrics")

    @app.get(prefix + "/api/metrics/history", dependencies=[Depends(session)])
    async def metrics_history(hours: int = Query(24)):
        from .metrics_history import RESOLUTION_MINUTES
        if hours not in RESOLUTION_MINUTES:
            raise HTTPException(422, "Выберите период мониторинга")
        return await invoke("metrics.history", {"hours": hours})

    @app.get(prefix + "/api/settings", dependencies=[Depends(session)])
    async def panel_settings():
        from .metrics_history import HISTORY_DAYS
        return {"public_origin": public_origin, "secure_cookie": auth.config["secure_cookie"],
                "credential_export_enabled": public_origin is not None, "history_days": HISTORY_DAYS}

    @app.get(prefix + "/api/routing", dependencies=[Depends(session)])
    async def routing_get():
        return await invoke("routing.get")

    @app.post(prefix + "/api/routing", dependencies=[Depends(mutation)])
    async def routing_publish(value: RoutingPublish):
        return await invoke("routing.publish", value.model_dump())

    @app.get(prefix + "/api/users", dependencies=[Depends(session)])
    async def users():
        return await invoke("users.list")

    @app.get(prefix + "/api/subscriptions", dependencies=[Depends(session)])
    async def subscriptions(page: int = Query(1, ge=1, le=10_000), search: str = Query("", max_length=128)):
        return await invoke("subscriptions.list", {"page": page, "search": search})

    @app.get(prefix + "/api/events", dependencies=[Depends(session)])
    async def events():
        return await invoke("events.list", {"limit": 100})

    @app.post(prefix + "/api/users", dependencies=[Depends(mutation)])
    async def new_user(value: NewUser):
        return await invoke("users.create", value.model_dump())

    @app.post(prefix + "/api/users/{identifier}/enabled", dependencies=[Depends(mutation)])
    async def user_enabled(identifier: uuid.UUID, value: Enabled):
        return await invoke("users.set_enabled", {"id": str(identifier), "enabled": value.enabled})

    @app.post(prefix + '/api/users/{identifier}/subscription-export', dependencies=[Depends(mutation)])
    async def subscription_export(identifier: uuid.UUID, value: ExportSubscription):
        if not public_origin:
            raise HTTPException(403, 'Выдача доступна только через защищённую панель')
        return await invoke('admin.subscription_export', {'user_id': str(identifier), **value.model_dump(mode='json')})

    @app.post(prefix + '/api/users/{identifier}/subscription-revoke', dependencies=[Depends(mutation)])
    async def subscription_revoke(identifier: uuid.UUID, value: RevokeSubscription):
        if not public_origin:
            raise HTTPException(403, 'Отзыв доступен через защищённую панель')
        return await invoke('admin.subscription_revoke', {'user_id': str(identifier), **value.model_dump()})

    @app.post(prefix + '/api/users/{identifier}/bootstrap-export', dependencies=[Depends(mutation)])
    async def bootstrap_export(identifier: uuid.UUID, value: ExportBootstrap):
        if not public_origin:
            raise HTTPException(403, 'Выдача доступна только через защищённую панель')
        return await invoke('admin.bootstrap_export', {'user_id': str(identifier), **value.model_dump(mode='json')})

    @app.get(prefix + "/api/devices", dependencies=[Depends(session)])
    async def devices():
        return await invoke("devices.list", {"telemetry": True})

    @app.post(prefix + "/api/devices", dependencies=[Depends(mutation)])
    async def new_device(value: NewDevice):
        return await invoke("devices.add", value.model_dump(mode="json"))

    @app.post(prefix + "/api/devices/{identifier}/enabled", dependencies=[Depends(mutation)])
    async def device_enabled(identifier: uuid.UUID, value: Enabled):
        return await invoke("devices.set_enabled", {"id": str(identifier), "enabled": value.enabled})

    if public_origin:
        from .client_web import install_routes
        install_routes(app, rpc, rpc_limit)
    if (assets / "assets").is_dir():
        app.mount(prefix + "/assets", StaticFiles(directory=assets / "assets"), name="panel-assets")
    return app


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=Path("/etc/ftm/web.json"))
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--static-dir", type=Path)
    args = parser.parse_args()
    import uvicorn
    uvicorn.run(create_app(load_config(args.config), static_dir=args.static_dir), host="127.0.0.1", port=args.port,
                proxy_headers=True, forwarded_allow_ips="127.0.0.1", server_header=False, access_log=False, workers=1, limit_concurrency=16,
                backlog=32, timeout_keep_alive=5)


if __name__ == "__main__":
    main()
