from __future__ import annotations

import asyncio
import logging
import json
import time
from contextlib import asynccontextmanager
from urllib.parse import urlsplit

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.openapi.utils import get_openapi
from sqlalchemy import func, select
from sqlalchemy.exc import SQLAlchemyError

from . import db as t
from .admin import router as admin_router
from .data_api import router as data_router
from .inference import InferencePool, LocalModels
from .security import current_user, encryptor, fail, hash_password
from .service import DetectionService
from .settings import Settings
from .tasks import TaskRunner
from .workbench import router as workbench_router

logger = logging.getLogger("qwenguard")


class BodyLimit:
    def __init__(self, app, limit=2 * 1024 * 1024):
        self.app, self.limit = app, limit

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope["method"] in ("GET", "HEAD"):
            return await self.app(scope, receive, send)
        chunks, length = [], 0
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            body = message.get("body", b"")
            length += len(body)
            if length > self.limit:
                response = JSONResponse({"error": {"code": "body_too_large", "message": "请求体超过 2 MiB"}}, 413)
                return await response(scope, receive, send)
            chunks.append(body)
            if not message.get("more_body"):
                break
        consumed = False
        async def replay():
            nonlocal consumed
            if not consumed:
                consumed = True
                return {"type": "http.request", "body": b"".join(chunks), "more_body": False}
            return await receive()
        await self.app(scope, replay, send)


def create_app(settings=None, models=None):
    settings = settings or Settings()
    settings.validate()
    db = t.Database(settings.database_url)
    models = models or LocalModels()
    pool = InferencePool(settings.inference_capacity)
    cipher = encryptor(settings.secret)
    service = DetectionService(db, models, pool, cipher, settings.audit_raw_retention_days)
    runner = TaskRunner(db, service, cipher, settings)

    @asynccontextmanager
    async def lifespan(app):
        db.initialize()
        # Upgrade existing v3 development job payloads to encrypted-at-rest storage.
        with db.engine.begin() as conn:
            for job in conn.execute(select(t.jobs.c.id, t.jobs.c["items"])).mappings():
                if isinstance(job["items"], list):
                    conn.execute(t.jobs.update().where(t.jobs.c.id == job["id"]).values(
                        items={"encrypted": cipher.encrypt(json.dumps(job["items"], ensure_ascii=False).encode()).decode()}))
        if not db.one(select(t.users.c.id).limit(1)):
            if not settings.admin_password:
                raise RuntimeError("Initial deployment requires BOOTSTRAP_ADMIN_PASSWORD")
            db.insert(t.users, username=settings.admin_user, password_hash=hash_password(settings.admin_password),
                      is_admin=True, enabled=True)
        if settings.testing:
            await asyncio.to_thread(models.load)
        else:
            asyncio.create_task(asyncio.to_thread(models.load))
        if not settings.testing:
            runner.start()
        try:
            yield
        finally:
            await runner.close()
            pool.close()
            db.engine.dispose()

    app = FastAPI(title="QwenGuard 企业安全平台", version="3.0.0",
        description="文本审核与受控增量 Chat API。管理面使用会话；数据面使用应用 API Key。多模态暂未开放。",
        lifespan=lifespan)
    app.state.db, app.state.settings, app.state.models = db, settings, models
    app.state.pool, app.state.cipher, app.state.service, app.state.runner = pool, cipher, service, runner
    app.state.stream_active = False
    app.state.dummy_hash = hash_password("invalid-user-timing-placeholder")
    app.add_middleware(BodyLimit)

    @app.middleware("http")
    async def request_context(request: Request, call_next):
        request.state.request_id = t.ident()
        start = time.perf_counter()
        try:
            origin = request.headers.get("origin")
            if origin and request.method not in ("GET", "HEAD", "OPTIONS"):
                same_origin = f"{request.url.scheme}://{request.headers.get('host', '')}"
                if origin != same_origin and origin not in settings.allowed_origins:
                    fail(403, "origin_denied", "请求来源不被允许")
            if request.url.path in ("/docs", "/redoc", "/openapi.json"):
                current_user(request)
            response = await call_next(request)
        except HTTPException as exc:
            response = JSONResponse({"error": exc.detail, "request_id": request.state.request_id}, exc.status_code)
        response.headers["X-Request-Id"] = request.state.request_id
        response.headers["X-Process-Time-Ms"] = str(round((time.perf_counter() - start) * 1000, 2))
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "same-origin"
        if request.url.path.startswith(("/api/", "/v1/")):
            response.headers["Cache-Control"] = "no-store"
        elif request.url.path.startswith("/console-assets/") or response.headers.get("content-type", "").startswith("text/html"):
            response.headers["Cache-Control"] = "no-cache"
        return response

    @app.exception_handler(HTTPException)
    async def http_error(request, exc):
        detail = exc.detail if isinstance(exc.detail, dict) else {"code": "http_error", "message": str(exc.detail)}
        headers = {"Retry-After": "60"} if exc.status_code == 429 else {}
        return JSONResponse({"error": detail, "request_id": request.state.request_id}, exc.status_code, headers=headers)

    @app.exception_handler(RequestValidationError)
    async def validation_error(request, exc):
        # Pydantic errors contain input values; never echo passwords or API keys.
        fields = [{"field": ".".join(str(p) for p in e["loc"]), "type": e["type"]} for e in exc.errors()]
        return JSONResponse({"error": {"code": "validation_error", "message": "参数校验失败", "fields": fields},
                             "request_id": request.state.request_id}, 422)

    @app.exception_handler(SQLAlchemyError)
    async def database_error(request, exc):
        logger.error("database operation failed request_id=%s type=%s", request.state.request_id, type(exc).__name__)
        return JSONResponse({"error": {"code": "storage_unavailable", "message": "持久化服务暂不可用", "retryable": True},
                             "request_id": request.state.request_id}, 503)

    @app.exception_handler(Exception)
    async def unknown_error(request, exc):
        logger.error("request failed request_id=%s type=%s", request.state.request_id, type(exc).__name__)
        return JSONResponse({"error": {"code": "internal_error", "message": "请求未完成", "retryable": False},
                             "request_id": request.state.request_id}, 500)

    app.include_router(admin_router)
    app.include_router(workbench_router)
    app.include_router(data_router)

    def openapi_contract():
        if app.openapi_schema:
            return app.openapi_schema
        schema = get_openapi(title=app.title, version=app.version, description=app.description, routes=app.routes)
        schema.setdefault("components", {}).setdefault("securitySchemes", {})["ManagementSession"] = {
            "type": "apiKey", "in": "cookie", "name": "qg_session",
            "description": "通过 /api/admin/auth/login 获取；写操作还需 X-CSRF-Token。"}
        for path, operations in schema["paths"].items():
            if path.startswith("/api/admin") and path != "/api/admin/auth/login":
                for method, operation in operations.items():
                    if method not in ("get", "post", "put", "delete", "patch"):
                        continue
                    operation["security"] = [{"ManagementSession": []}]
                    if method != "get":
                        operation.setdefault("parameters", []).append({
                            "name": "X-CSRF-Token", "in": "header", "required": True,
                            "schema": {"type": "string"}, "description": "从登录或 /auth/me 获取"})
        app.openapi_schema = schema
        return schema
    app.openapi = openapi_contract

    @app.get("/health/live", tags=["健康检查"])
    async def live():
        return {"status": "ok"}

    @app.get("/health")
    @app.get("/health/ready", tags=["健康检查"])
    async def ready():
        db.one(select(func.count()).select_from(t.schema_versions))
        loaded = models.status().get("loaded", False)
        return JSONResponse({"status": "ready" if loaded else "unavailable", "models_loaded": loaded,
                             "version": "3.0.0"}, 200 if loaded else 503)

    @app.api_route("/api/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"], include_in_schema=False)
    async def retired_api(path: str, request: Request):
        current_user(request)
        fail(410, "legacy_route_retired", "旧管理接口已停用，请使用 /api/admin 接口")

    if settings.static_dir.exists():
        app.mount("/console-assets", StaticFiles(directory=str(settings.static_dir)), name="console-assets")

    @app.get("/{path:path}", include_in_schema=False)
    async def console(path: str):
        if path.startswith(("api/", "v1/")):
            fail(404, "not_found", "接口不存在")
        return FileResponse(settings.static_dir / "index.html", headers={
            "Cache-Control": "no-cache",
            "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'",
        })

    return app
