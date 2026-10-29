from __future__ import annotations

import asyncio
import json
import threading
import time

from fastapi import APIRouter, Query, Request, Security
from fastapi.responses import StreamingResponse
from fastapi.security import APIKeyHeader, HTTPBearer
from pydantic import Field
from sqlalchemy import select

from . import db as t
from . import schemas as s
from .inference import InferenceTimeout, QueueFull
from .security import api_identity, fail, redact

router = APIRouter(tags=["检测数据面"], dependencies=[
    Security(HTTPBearer(auto_error=False)),
    Security(APIKeyHeader(name="X-API-Key", auto_error=False)),
])


def source(application):
    return "production" if application["environment"] == "production" else "sandbox"


async def detect(request, application, key, body, version=None):
    prompt, response = body.effective_pair()
    return await request.app.state.service.detect(
        application, key["id"], prompt, response, request.state.request_id,
        source=source(application), endpoint=request.url.path, version=version,
        include_stream_tokens=body.include_stream_tokens,
        scope=body.scope, caller_context=body.caller_metadata())


@router.post("/v1/guard/detect", response_model=s.DetectionResult, response_model_exclude_none=True)
@router.post("/v1/guard", response_model=s.DetectionResult, response_model_exclude_none=True, include_in_schema=False)
async def guard_detect(body: s.Detect, request: Request):
    application, key = api_identity(request)
    return await detect(request, application, key, body)


@router.post("/v1/guard/input", response_model=s.LegacyResult, response_model_exclude_none=True)
async def guard_input(body: s.InputRequest, request: Request):
    application, key = api_identity(request)
    result = await detect(request, application, key, s.Detect(prompt=body.text))
    return {**result, "allowed": result["decision"] in ("allow", "mask"),
            "sanitized_text": result.get("sanitized_content", body.text) if result["decision"] in ("allow", "mask") else ""}


@router.post("/v1/guard/output", response_model=s.LegacyResult, response_model_exclude_none=True)
async def guard_output(body: s.OutputRequest, request: Request):
    application, key = api_identity(request)
    result = await detect(request, application, key, s.Detect(prompt=body.prompt or "审核助手回复", response=body.text))
    return {**result, "allowed": result["decision"] in ("allow", "mask"),
            "sanitized_text": result.get("sanitized_content", body.text) if result["decision"] in ("allow", "mask") else ""}


@router.post("/v1/guard/batch")
async def guard_batch(body: s.BatchRequest, request: Request):
    application, key = api_identity(request, units=len(body.items))
    version = request.app.state.service.policy(application)
    results = []
    from fastapi import HTTPException
    for index, item in enumerate(body.items):
        try:
            result = await detect(request, application, key, item, version)
        except HTTPException as exc:
            result = {"execution_status": "error", "error": exc.detail, "http_status": exc.status_code}
        results.append({"index": index, **result})
    return {"request_id": request.state.request_id, "results": results,
            "summary": {"total": len(results), "completed": sum(r["execution_status"] == "completed" for r in results)}}


class Moderation(s.StrictModel):
    input: str | list[str]
    model: str = Field(default="Qwen3Guard-Gen-0.6B", max_length=160)


@router.post("/v1/moderations")
async def moderation(body: Moderation, request: Request):
    items = [body.input] if isinstance(body.input, str) else body.input
    if not 1 <= len(items) <= 32 or any(not item.strip() or len(item) > 16000 for item in items):
        fail(422, "invalid_input", "输入须为 1～32 条非空文本，每条最多 16000 字符")
    application, key = api_identity(request, units=len(items))
    version = request.app.state.service.policy(application)
    results = []
    for text in items:
        result = await detect(request, application, key, s.Detect(prompt=text), version)
        results.append({"flagged": result["decision"] in ("block", "review"),
                        "categories": {"policy_violation": result["decision"] == "block"},
                        "category_scores": {"policy_violation": result["risk_score"]},
                        "guardrail": result})
    return {"id": request.state.request_id, "model": body.model, "results": results,
            "compatibility": "text-only envelope; categories are platform-specific policy scores"}


class Deobfuscate(s.InputRequest):
    mask_pii: bool = True


@router.post("/v1/guard/deobfuscate")
async def deobfuscate(body: Deobfuscate, request: Request):
    api_identity(request)
    from app.security_shield import security_shield
    text, methods = security_shield.deobfuscate_and_unwrap(body.text)
    return {"request_id": request.state.request_id, "text": redact(text) if body.mask_pii else text,
            "methods": methods, "notice": "文本转换工具，结果不代表内容安全判定"}


class StreamScan(s.StrictModel):
    prompt: str = Field(default="", max_length=16000)
    response: str = Field(min_length=1, max_length=16000)
    chunk_delay_ms: int = Field(default=0, ge=0, le=500)


@router.post("/v1/guard/stream")
async def offline_stream(body: StreamScan, request: Request):
    application, key = api_identity(request)
    version = request.app.state.service.policy(application)
    # Explicit offline mode: never label buffered analysis as real-time generation.
    result = await detect(request, application, key, s.Detect(prompt=body.prompt or "审核回复",
                          response=body.response, include_stream_tokens=True), version)
    scan = result.pop("stream_diagnostic")
    return {**scan, **result, "mode": "offline_token_diagnostic",
            "notice": "完整文本上的 Stream Token 诊断；SSE 是结果回放。增量生成护栏使用 /v1/chat/completions stream=true"}


@router.post("/v1/guard/stream/sse")
async def offline_stream_sse(body: StreamScan, request: Request):
    result = await offline_stream(body, request)
    async def events():
        yield 'event: mode\ndata: {"mode":"offline_token_diagnostic","replay":true}\n\n'
        for token in result.get("token_stream", []):
            yield f"event: token\ndata: {json.dumps(token, ensure_ascii=False)}\n\n"
            if body.chunk_delay_ms:
                await asyncio.sleep(body.chunk_delay_ms / 1000)
        yield f"event: summary\ndata: {json.dumps({k:v for k,v in result.items() if k != 'token_stream'}, ensure_ascii=False)}\n\n"
    return StreamingResponse(events(), media_type="text/event-stream")


@router.get("/v1/guard/categories")
async def categories(request: Request):
    api_identity(request)
    from scripts.build_tc260_dataset import TC260_TAXONOMY
    return {"taxonomy": TC260_TAXONOMY, "modalities": ["text"], "score_kind": "policy_score"}


@router.get("/v1/platform/catalog")
@router.get("/api/v1/catalog", include_in_schema=False)
async def catalog(request: Request):
    api_identity(request)
    schema = request.app.openapi()
    return {"version": "3.0.0", "contract": "/openapi.json",
            "endpoints": {path: spec for path, spec in schema["paths"].items() if path.startswith("/v1/")},
            "schemas": schema["components"]["schemas"],
            "capabilities": {"text": True, "incremental_guarded_chat": True, "policy_management_api": True,
                             "image": False, "audio": False, "video": False, "document": False},
            "compatibility": "Text chat streaming subset; moderation categories are platform-specific"}


def _policy_api_identity(request: Request, write: bool = False):
    if write:
        return api_identity(request, scope="policy:manage")
    raw = request.headers.get("X-API-Key", "")
    authorization = request.headers.get("Authorization", "")
    if authorization.lower().startswith("bearer "):
        raw = authorization[7:].strip()
    db = request.app.state.db
    from .security import digest
    row = db.one(select(t.keys).where(t.keys.c.token_hash == digest(raw))) if raw else None
    scope = "policy:manage" if (row and "policy:manage" in (row["scopes"] or [])) else "detect"
    return api_identity(request, scope=scope)


@router.get("/v1/policies")
async def v1_list_policies(request: Request):
    application, _ = _policy_api_identity(request, write=False)
    db = request.app.state.db
    items = db.all(select(t.policies).where(
        t.policies.c.project_id == application["project_id"]).order_by(t.policies.c.created_at.desc()))
    for policy in items:
        policy["versions"] = db.all(select(t.versions).where(
            t.versions.c.policy_id == policy["id"]).order_by(t.versions.c.version.desc()))
    return {
        "project_id": application["project_id"],
        "application_id": application["id"],
        "current_policy_id": application["policy_id"],
        "items": items,
    }


@router.get("/v1/policies/current")
async def v1_current_policy(request: Request):
    application, _ = _policy_api_identity(request, write=False)
    db = request.app.state.db
    policy = db.one(select(t.policies).where(t.policies.c.id == application["policy_id"]))
    version = request.app.state.service.policy(application)
    return {
        "project_id": application["project_id"],
        "application_id": application["id"],
        "application_name": application["name"],
        "environment": application["environment"],
        "policy_id": policy["id"],
        "policy_name": policy["name"],
        "version": version["version"],
        "published_version": policy["published_version"],
        "config": version["config"],
    }


@router.post("/v1/policies", status_code=201)
async def v1_create_policy(body: s.V1PolicyCreate, request: Request):
    application, key = _policy_api_identity(request, write=True)
    db = request.app.state.db
    project_id = application["project_id"]
    policy_id = t.ident()
    actor_id = f"apikey:{key['id']}"
    pub_ver = 1 if body.publish_immediately else 0
    cfg_dump = body.config.model_dump()
    with db.engine.begin() as conn:
        conn.execute(t.policies.insert().values(
            id=policy_id, created_at=time.time(), project_id=project_id,
            name=body.name, published_version=pub_ver))
        conn.execute(t.versions.insert().values(
            id=t.ident(), created_at=time.time(), policy_id=policy_id,
            version=1, config=cfg_dump, author_id=actor_id))
        if body.publish_immediately:
            conn.execute(t.operations.insert().values(
                id=t.ident(), created_at=time.time(), actor_id=actor_id,
                project_id=project_id, action="policy.publish", target_id=policy_id,
                detail={"from": 0, "to": 1, "via": "v1_api"}))
        if body.bind_to_application:
            if not body.publish_immediately:
                fail(422, "policy_unpublished", "绑定到当前应用时需同时启用 publish_immediately")
            conn.execute(t.apps.update().where(t.apps.c.id == application["id"]).values(policy_id=policy_id))
    db.operation(actor_id, "policy.create", policy_id, project_id, via="v1_api")
    return {
        "id": policy_id,
        "name": body.name,
        "project_id": project_id,
        "version": 1,
        "published_version": pub_ver,
        "bound_to_application": body.bind_to_application,
        "application_id": application["id"],
        "config": cfg_dump,
    }


@router.put("/v1/policies/current")
async def v1_update_current_policy(request: Request):
    from fastapi.exceptions import RequestValidationError
    from pydantic import ValidationError
    from sqlalchemy import func
    application, key = _policy_api_identity(request, write=True)
    db = request.app.state.db
    try:
        payload = await request.json()
    except Exception:
        fail(422, "invalid_json", "请求体须为合法 JSON 对象")
    if not isinstance(payload, dict):
        fail(422, "invalid_payload", "请求体须为策略配置字典")
    raw_updates = payload.get("config") if isinstance(payload.get("config"), dict) else payload
    if not isinstance(raw_updates, dict):
        fail(422, "invalid_payload", "请求体须为策略配置字典")
    current_version = request.app.state.service.policy(application)
    merged = {**current_version["config"], **raw_updates}
    try:
        validated_config = s.PolicyConfig(**merged).model_dump()
    except ValidationError as exc:
        raise RequestValidationError(exc.errors()) from exc
    policy_id = application["policy_id"]
    actor_id = f"apikey:{key['id']}"
    with db.engine.begin() as conn:
        policy = t.row(conn.execute(select(t.policies).where(t.policies.c.id == policy_id).with_for_update()))
        latest = conn.execute(select(func.max(t.versions.c.version)).where(t.versions.c.policy_id == policy_id)).scalar() or 0
        new_ver = latest + 1
        conn.execute(t.versions.insert().values(
            id=t.ident(), created_at=time.time(), policy_id=policy_id,
            version=new_ver, config=validated_config, author_id=actor_id))
        conn.execute(t.policies.update().where(t.policies.c.id == policy_id).values(published_version=new_ver))
        conn.execute(t.operations.insert().values(
            id=t.ident(), created_at=time.time(), actor_id=actor_id,
            project_id=application["project_id"], action="policy.publish", target_id=policy_id,
            detail={"from": policy["published_version"], "to": new_ver, "via": "v1_api_current_update"}))
    return {
        "policy_id": policy_id,
        "policy_name": policy["name"],
        "version": new_ver,
        "published_version": new_ver,
        "application_id": application["id"],
        "config": validated_config,
    }


@router.post("/v1/policies/{policy_id}/versions", status_code=201)
async def v1_create_policy_version(policy_id: str, body: s.PolicyConfig, request: Request):
    from sqlalchemy import func
    application, key = _policy_api_identity(request, write=True)
    db = request.app.state.db
    policy = db.one(select(t.policies).where(
        t.policies.c.id == policy_id, t.policies.c.project_id == application["project_id"]))
    if not policy:
        fail(404, "not_found", "策略不存在或不属于当前项目")
    actor_id = f"apikey:{key['id']}"
    with db.engine.begin() as conn:
        conn.execute(select(t.policies).where(t.policies.c.id == policy_id).with_for_update())
        latest = conn.execute(select(func.max(t.versions.c.version)).where(t.versions.c.policy_id == policy_id)).scalar() or 0
        item = {"id": t.ident(), "created_at": time.time(), "policy_id": policy_id,
                "version": latest + 1, "config": body.model_dump(), "author_id": actor_id}
        conn.execute(t.versions.insert().values(**item))
    db.operation(actor_id, "policy.draft", policy_id, application["project_id"], version=latest + 1)
    return item


@router.post("/v1/policies/{policy_id}/publish")
async def v1_publish_policy(policy_id: str, body: s.V1PolicyPublish, request: Request):
    application, key = _policy_api_identity(request, write=True)
    db = request.app.state.db
    policy = db.one(select(t.policies).where(
        t.policies.c.id == policy_id, t.policies.c.project_id == application["project_id"]))
    if not policy:
        fail(404, "not_found", "策略不存在或不属于当前项目")
    version = db.one(select(t.versions).where(
        t.versions.c.policy_id == policy_id, t.versions.c.version == body.version))
    if not version:
        fail(404, "not_found", "策略版本不存在")
    actor_id = f"apikey:{key['id']}"
    with db.engine.begin() as conn:
        conn.execute(t.policies.update().where(t.policies.c.id == policy_id).values(published_version=body.version))
        if body.bind_to_application:
            conn.execute(t.apps.update().where(t.apps.c.id == application["id"]).values(policy_id=policy_id))
        conn.execute(t.operations.insert().values(
            id=t.ident(), created_at=time.time(), actor_id=actor_id,
            project_id=application["project_id"], action="policy.publish", target_id=policy_id,
            detail={"from": policy["published_version"], "to": body.version, "via": "v1_api"}))
    return {
        "policy_id": policy_id,
        "published_version": body.version,
        "bound_to_application": body.bind_to_application,
        "application_id": application["id"],
        "config": version["config"],
    }


@router.put("/v1/policies/{policy_id}/bind")
async def v1_bind_policy(policy_id: str, request: Request):
    application, key = _policy_api_identity(request, write=True)
    db = request.app.state.db
    policy = db.one(select(t.policies).where(
        t.policies.c.id == policy_id, t.policies.c.project_id == application["project_id"]))
    if not policy or not policy["published_version"]:
        fail(422, "policy_unpublished", "目标策略不存在或尚未发布")
    actor_id = f"apikey:{key['id']}"
    with db.engine.begin() as conn:
        conn.execute(t.apps.update().where(t.apps.c.id == application["id"]).values(policy_id=policy_id))
    db.operation(actor_id, "application.settings", application["id"], application["project_id"], policy_id=policy_id)
    return {
        "ok": True,
        "application_id": application["id"],
        "policy_id": policy_id,
        "published_version": policy["published_version"],
    }


@router.get("/v1/audit/logs")
@router.get("/api/audit/logs", include_in_schema=False)
async def own_audit(request: Request, limit: int = Query(50, ge=1, le=200), before: float | None = None):
    application, _ = api_identity(request, scope="audit:read")
    statement = select(t.events).where(t.events.c.application_id == application["id"])
    if before:
        statement = statement.where(t.events.c.created_at < before)
    items = request.app.state.db.all(statement.order_by(t.events.c.created_at.desc()).limit(limit + 1))
    more = len(items) > limit
    items = items[:limit]
    return {"items": items, "next_cursor": items[-1]["created_at"] if more else None}


@router.get("/v1/audit/summary")
@router.get("/api/audit/summary", include_in_schema=False)
async def own_audit_summary(request: Request):
    from sqlalchemy import func, case
    application, _ = api_identity(request, scope="audit:read")
    result = request.app.state.db.one(select(func.count().label("total"),
        func.sum(case((t.events.c.decision == "block", 1), else_=0)).label("blocked"),
        func.sum(case((t.events.c.execution_status != "completed", 1), else_=0)).label("errors")
    ).where(t.events.c.application_id == application["id"],
            t.events.c.source == source(application)))
    return {**result, "blocked": result["blocked"] or 0, "errors": result["errors"] or 0,
            "application_id": application["id"], "source": source(application), "unit": "detection_items"}


def advance(iterator):
    try:
        return {"done": False, "text": next(iterator)}
    except StopIteration:
        return {"done": True, "text": ""}


@router.post("/v1/chat/completions", responses={200: {"description": "JSON completion or incremental audited SSE",
    "content": {"text/event-stream": {"schema": {"type": "string"}}}}})
async def chat(body: s.Chat, request: Request):
    started = time.monotonic()
    application, key = api_identity(request, scope="chat")
    state = request.app.state
    if state.stream_active:
        fail(503, "stream_capacity", "当前生成通道繁忙，请稍后重试")
    version = state.service.policy(application)
    state.stream_active = True
    prompt = "\n".join(f"{m.role}: {m.content}" for m in body.messages)
    try:
        input_result = await state.service.detect(application, key["id"], prompt, None,
            request.state.request_id, source=source(application), endpoint="chat_input", version=version)
    except BaseException:
        state.stream_active = False
        raise

    async def guarded_chunks():
        stop = threading.Event()
        iterator = None
        terminal = False
        text = ""
        def record_terminal(result=None, error="stream_failed"):
            nonlocal terminal
            value = state.service.stream_terminal(application, key["id"], prompt,
                request.state.request_id, source(application), version, result=result, error=error,
                elapsed_ms=(time.monotonic() - started) * 1000, response=text)
            terminal = True
            return value
        try:
            if input_result["decision"] != "allow":
                terminal = True
                yield {"kind": "blocked", "result": input_result}
                return
            iterator = state.models.generation([m.model_dump() for m in body.messages],
                                               body.max_tokens, body.temperature, stop)
            text, pending = "", ""
            deadline = time.monotonic() + 120
            while time.monotonic() < deadline:
                if await request.is_disconnected():
                    record_terminal(error="client_disconnected")
                    return
                part = await state.pool.run(lambda: advance(iterator), timeout=30)
                text += part["text"]
                pending += part["text"]
                if len(text) > 16000:
                    raise ValueError("generation_limit")
                if len(pending) >= version["config"]["stream_window_chars"] or part["done"]:
                    if not text:
                        raise RuntimeError("empty_generation")
                    result = await state.service.detect(application, key["id"], prompt, text,
                        request.state.request_id,
                        source="stream_window",
                        endpoint="chat_output", version=version)
                    # PII mask in a cumulative stream can rewrite already emitted
                    # positions. Treat mask conservatively as blocked for streaming.
                    if result["decision"] != "allow":
                        result = record_terminal(result=result)
                        yield {"kind": "blocked", "result": result}
                        return
                    if pending:
                        yield {"kind": "content", "text": pending, "result": result}
                        pending = ""
                if part["done"]:
                    result = record_terminal(result=result)
                    yield {"kind": "done", "result": result}
                    return
            raise InferenceTimeout()
        finally:
            stop.set()
            # A timed-out next() might still be executing. Closing a running
            # generator is invalid; cancellation signal stops it on next advance.
            if iterator:
                try:
                    iterator.close()
                except ValueError:
                    pass
            state.stream_active = False
            if not terminal:
                import sys
                error = "client_disconnected" if isinstance(sys.exception(), (asyncio.CancelledError, GeneratorExit)) else "stream_failed"
                record_terminal(error=error)

    request_id = request.state.request_id
    created = int(time.time())
    base = {"id": "chatcmpl-" + request_id, "created": created, "model": body.model}

    if body.stream:
        async def sse():
            try:
                yield "data: " + json.dumps({**base, "object": "chat.completion.chunk",
                    "choices": [{"index": 0, "delta": {"role": "assistant"}, "finish_reason": None}]}) + "\n\n"
                async for item in guarded_chunks():
                    terminal = item["kind"] in ("blocked", "done")
                    payload = {**base, "object": "chat.completion.chunk",
                        "choices": [{"index": 0, "delta": {"content": item["text"]} if item["kind"] == "content" else {},
                                     "finish_reason": ("content_filter" if item["kind"] == "blocked" else "stop") if terminal else None}]}
                    if terminal:
                        payload["guardrail"] = item["result"]
                    yield "data: " + json.dumps(payload, ensure_ascii=False) + "\n\n"
                yield "data: [DONE]\n\n"
            except asyncio.CancelledError:
                raise
            except Exception:
                yield "event: error\ndata: " + json.dumps({"request_id": request_id,
                    "error": {"code": "stream_failed", "message": "流式审核未完成，未审核片段已停止发送"}}) + "\n\n"
            finally:
                state.stream_active = False
        return StreamingResponse(sse(), media_type="text/event-stream",
                                 headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})
    result, content, reason = input_result, "", "stop"
    try:
        async for item in guarded_chunks():
            result = item["result"]
            if item["kind"] == "content":
                content += item["text"]
            if item["kind"] == "blocked":
                content, reason = "", "content_filter"
    except Exception:
        fail(503, "generation_failed", "生成或检测未完成")
    return {**base, "object": "chat.completion", "guardrail": result,
            "choices": [{"index": 0, "message": {"role": "assistant", "content": content}, "finish_reason": reason}]}
