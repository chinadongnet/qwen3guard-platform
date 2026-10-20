from __future__ import annotations

import asyncio
import hashlib
import json
import math
import secrets
import time

from fastapi import APIRouter, Query, Request, Response
from sqlalchemy import case, func, select
from sqlalchemy.exc import IntegrityError

from . import db as t
from . import schemas as s
from .network import post_json, validate_url
from .security import (current_user, digest, fail, global_admin, hash_password,
                       project_access, rate_limit, redact, verify_password)

router = APIRouter(prefix="/api/admin", tags=["管理面"])
EDIT = ("admin",)
OPERATE = ("admin", "operator")
DEVELOP = ("admin", "developer")


def database(request):
    return request.app.state.db


def scoped_object(request, table, object_id, roles=None):
    item = database(request).one(select(table).where(table.c.id == object_id))
    if not item:
        fail(404, "not_found", "记录不存在")
    project_access(request, item["project_id"], roles)
    return item


@router.post("/auth/login")
async def login(body: s.Login, request: Request, response: Response):
    db = database(request)
    ip = request.client.host if request.client else "unknown"
    rate_limit(db, "login-ip:" + digest(ip), 20)
    rate_limit(db, "login-user:" + digest(body.username), 10)
    user = db.one(select(t.users).where(t.users.c.username == body.username))
    encoded = user["password_hash"] if user else request.app.state.dummy_hash
    valid = await asyncio.to_thread(verify_password, body.password, encoded)
    if not valid or not user or not user["enabled"]:
        fail(401, "invalid_credentials", "用户名或密码错误")
    token, csrf = secrets.token_urlsafe(40), secrets.token_urlsafe(32)
    lifetime = request.app.state.settings.session_seconds
    with db.engine.begin() as conn:
        # Serialize session issuance with password changes and account disabling.
        # Never issue a new session using a hash verified before a concurrent change.
        still_valid = conn.execute(select(t.users.c.id).where(
            t.users.c.id == user["id"], t.users.c.password_hash == encoded,
            t.users.c.enabled.is_(True)).with_for_update()).first()
        if not still_valid:
            fail(401, "invalid_credentials", "用户名或密码错误")
        conn.execute(t.sessions.delete().where(t.sessions.c.expires_at <= time.time()))
        conn.execute(t.sessions.insert().values(id=t.ident(), created_at=time.time(),
            user_id=user["id"], token_hash=digest(token), csrf=csrf, expires_at=time.time() + lifetime))
    response.set_cookie("qg_session", token, max_age=lifetime, httponly=True,
                        secure=request.app.state.settings.secure_cookie, samesite="strict", path="/")
    db.operation(user["id"], "auth.login", user["id"])
    return {"user": {"id": user["id"], "username": user["username"], "is_admin": user["is_admin"]}, "csrf_token": csrf}


@router.get("/auth/me")
async def me(request: Request):
    user = current_user(request)
    return {"user": {"id": user["id"], "username": user["username"], "is_admin": user["is_admin"]},
            "csrf_token": request.state.session["csrf"]}


@router.post("/auth/logout")
async def logout(request: Request, response: Response):
    user = current_user(request)
    db = database(request)
    with db.engine.begin() as conn:
        conn.execute(t.sessions.delete().where(t.sessions.c.id == request.state.session["id"]))
    db.operation(user["id"], "auth.logout", user["id"])
    response.delete_cookie("qg_session", path="/")
    return {"ok": True}


@router.get("/users")
async def list_users(request: Request):
    global_admin(request)
    return {"items": database(request).all(select(t.users.c.id, t.users.c.username, t.users.c.enabled, t.users.c.is_admin))}


@router.post("/auth/password")
async def change_password(body: s.PasswordChange, request: Request, response: Response):
    user = current_user(request)
    db = database(request)
    rate_limit(db, "password-change:" + user["id"], 5)
    if not await asyncio.to_thread(verify_password, body.current_password, user["password_hash"]):
        fail(403, "incorrect_password", "当前密码不正确")
    if body.current_password == body.new_password:
        fail(422, "password_unchanged", "新密码不能与当前密码相同")
    encoded = await asyncio.to_thread(hash_password, body.new_password)
    with db.engine.begin() as conn:
        changed = conn.execute(t.users.update().where(
            t.users.c.id == user["id"], t.users.c.password_hash == user["password_hash"],
            t.users.c.enabled.is_(True)).values(password_hash=encoded))
        if changed.rowcount != 1:
            fail(409, "credentials_changed", "账户状态已变更，请重新登录")
        conn.execute(t.sessions.delete().where(t.sessions.c.user_id == user["id"]))
        conn.execute(t.operations.insert().values(
            id=t.ident(), created_at=time.time(), actor_id=user["id"], project_id=None,
            action="auth.password_changed", target_id=user["id"],
            detail={"sessions_revoked": True}))
    response.delete_cookie("qg_session", path="/")
    return {"ok": True, "reauthentication_required": True}


@router.put("/users/{user_id}/enabled")
async def enable_user(user_id: str, body: s.Enabled, request: Request):
    actor = global_admin(request)
    if user_id == actor["id"] and not body.enabled:
        fail(409, "self_disable", "不能停用当前管理员账户")
    db = database(request)
    with db.engine.begin() as conn:
        updated = conn.execute(t.users.update().where(t.users.c.id == user_id).values(enabled=body.enabled))
        if updated.rowcount != 1:
            fail(404, "not_found", "用户不存在")
        if not body.enabled:
            conn.execute(t.sessions.delete().where(t.sessions.c.user_id == user_id))
    db.operation(actor["id"], "user.set_enabled", user_id, enabled=body.enabled)
    return {"ok": True}


@router.post("/users", status_code=201)
async def create_user(body: s.UserCreate, request: Request):
    actor = global_admin(request)
    db = database(request)
    try:
        user = db.insert(t.users, username=body.username,
                         password_hash=await asyncio.to_thread(hash_password, body.password),
                         is_admin=False, enabled=True)
    except IntegrityError:
        fail(409, "username_exists", "用户名已存在")
    db.operation(actor["id"], "user.create", user["id"])
    return {"id": user["id"], "username": user["username"]}


@router.get("/projects")
async def list_projects(request: Request):
    user = current_user(request)
    statement = select(t.projects)
    if not user["is_admin"]:
        statement = statement.where(t.projects.c.id.in_(
            select(t.members.c.project_id).where(t.members.c.user_id == user["id"])))
    items = database(request).all(statement.order_by(t.projects.c.created_at))
    for item in items:
        member = database(request).one(select(t.members).where(
            t.members.c.project_id == item["id"], t.members.c.user_id == user["id"]))
        item["role"] = "admin" if user["is_admin"] else member["role"]
    return {"items": items}


@router.post("/projects", status_code=201)
async def create_project(body: s.Named, request: Request):
    user = global_admin(request)
    db = database(request)
    project = db.insert(t.projects, name=body.name)
    db.operation(user["id"], "project.create", project["id"], project["id"])
    return project


@router.get("/projects/{project_id}/members")
async def list_members(project_id: str, request: Request):
    project_access(request, project_id, EDIT)
    return {"items": database(request).all(select(
        t.members.c.id, t.members.c.user_id, t.members.c.role, t.users.c.username
    ).join(t.users, t.users.c.id == t.members.c.user_id).where(t.members.c.project_id == project_id))}


@router.put("/projects/{project_id}/members")
async def set_member(project_id: str, body: s.Membership, request: Request):
    actor = project_access(request, project_id, EDIT)
    db = database(request)
    if not db.one(select(t.users).where(t.users.c.id == body.user_id)):
        fail(404, "not_found", "用户不存在")
    with db.engine.begin() as conn:
        member = t.row(conn.execute(select(t.members).where(
            t.members.c.project_id == project_id, t.members.c.user_id == body.user_id)))
        if member:
            conn.execute(t.members.update().where(t.members.c.id == member["id"]).values(role=body.role))
        else:
            conn.execute(t.members.insert().values(id=t.ident(), created_at=time.time(),
                project_id=project_id, user_id=body.user_id, role=body.role))
    db.operation(actor["id"], "member.set_role", body.user_id, project_id, role=body.role)
    return {"ok": True}


@router.get("/policies")
async def list_policies(request: Request, project_id: str):
    project_access(request, project_id)
    db = database(request)
    items = db.all(select(t.policies).where(t.policies.c.project_id == project_id).order_by(t.policies.c.created_at.desc()))
    for policy in items:
        policy["versions"] = db.all(select(t.versions).where(
            t.versions.c.policy_id == policy["id"]).order_by(t.versions.c.version.desc()))
    return {"items": items}


@router.post("/policies", status_code=201)
async def create_policy(body: s.PolicyCreate, request: Request, project_id: str):
    user = project_access(request, project_id, EDIT)
    db = database(request)
    policy_id = t.ident()
    with db.engine.begin() as conn:
        conn.execute(t.policies.insert().values(id=policy_id, created_at=time.time(),
            project_id=project_id, name=body.name, published_version=0))
        conn.execute(t.versions.insert().values(id=t.ident(), created_at=time.time(),
            policy_id=policy_id, version=1, config=body.config.model_dump(), author_id=user["id"]))
    db.operation(user["id"], "policy.create", policy_id, project_id)
    return {"id": policy_id, "version": 1, "published_version": 0}


@router.post("/policies/{policy_id}/versions", status_code=201)
async def create_version(policy_id: str, body: s.PolicyConfig, request: Request):
    policy = scoped_object(request, t.policies, policy_id, EDIT)
    db = database(request)
    with db.engine.begin() as conn:
        conn.execute(select(t.policies).where(t.policies.c.id == policy_id).with_for_update())
        latest = conn.execute(select(func.max(t.versions.c.version)).where(t.versions.c.policy_id == policy_id)).scalar() or 0
        item = {"id": t.ident(), "created_at": time.time(), "policy_id": policy_id,
                "version": latest + 1, "config": body.model_dump(), "author_id": request.state.user["id"]}
        conn.execute(t.versions.insert().values(**item))
    db.operation(request.state.user["id"], "policy.draft", policy_id, policy["project_id"], version=latest + 1)
    return item


@router.post("/policies/{policy_id}/publish")
async def publish(policy_id: str, body: s.Publish, request: Request):
    policy = scoped_object(request, t.policies, policy_id, EDIT)
    db = database(request)
    version = db.one(select(t.versions).where(
        t.versions.c.policy_id == policy_id, t.versions.c.version == body.version))
    if not version:
        fail(404, "not_found", "策略版本不存在")
    if policy["published_version"] and body.version != policy["published_version"]:
        history = db.all(select(t.operations.c.detail).where(
            t.operations.c.target_id == policy_id, t.operations.c.action == "policy.publish"))
        rollback = any(item["detail"].get("to") == body.version for item in history)
        if not rollback:
            evaluated = db.all(select(t.jobs).where(t.jobs.c.policy_version_id == version["id"],
                                                     t.jobs.c.state == "completed"))
            passed = False
            for job in evaluated:
                results = db.all(select(t.job_items.c.result).where(t.job_items.c.job_id == job["id"]))
                if results and len(results) == job["total"] and all(
                    r["result"].get("execution_status") == "completed" and r["result"].get("passed") is True
                    for r in results):
                    passed = True
            if not passed:
                fail(409, "evaluation_required", "新策略版本须先完成带标签的回归评测且全部通过；历史已发布版本可回滚")
    with db.engine.begin() as conn:
        updated = conn.execute(t.policies.update().where(
            t.policies.c.id == policy_id, t.policies.c.published_version == body.expected_current
        ).values(published_version=body.version))
        if updated.rowcount != 1:
            fail(409, "version_conflict", "策略已被修改，请刷新后重新发布")
        conn.execute(t.operations.insert().values(
            id=t.ident(), created_at=time.time(), actor_id=request.state.user["id"],
            project_id=policy["project_id"], action="policy.publish", target_id=policy_id,
            detail={"from": body.expected_current, "to": body.version}))
    return {"published_version": body.version}


@router.get("/applications")
async def list_applications(request: Request, project_id: str):
    project_access(request, project_id)
    return {"items": database(request).all(select(t.apps).where(
        t.apps.c.project_id == project_id).order_by(t.apps.c.created_at.desc()))}


@router.post("/applications", status_code=201)
async def create_application(body: s.ApplicationCreate, request: Request, project_id: str):
    user = project_access(request, project_id, DEVELOP)
    db = database(request)
    policy = db.one(select(t.policies).where(t.policies.c.id == body.policy_id, t.policies.c.project_id == project_id))
    if not policy or not policy["published_version"]:
        fail(422, "policy_unpublished", "请选择本项目已发布的策略")
    item = db.insert(t.apps, project_id=project_id, enabled=True, **body.model_dump())
    db.operation(user["id"], "application.create", item["id"], project_id)
    return item


@router.put("/applications/{application_id}/enabled")
async def enable_application(application_id: str, body: s.Enabled, request: Request):
    application = scoped_object(request, t.apps, application_id, EDIT)
    db = database(request)
    with db.engine.begin() as conn:
        conn.execute(t.apps.update().where(t.apps.c.id == application_id).values(enabled=body.enabled))
    db.operation(request.state.user["id"], "application.set_enabled", application_id,
                 application["project_id"], enabled=body.enabled)
    return {"ok": True}


def public_key(key):
    return {k: v for k, v in key.items() if k != "token_hash"}


@router.get("/applications/{application_id}/keys")
async def list_keys(application_id: str, request: Request):
    scoped_object(request, t.apps, application_id, DEVELOP)
    paused = {r["key_id"] for r in database(request).all(select(t.key_suspensions))}
    return {"items": [{**public_key(k), "enabled": k["id"] not in paused} for k in database(request).all(select(t.keys).where(
        t.keys.c.application_id == application_id).order_by(t.keys.c.created_at.desc()))]}


class KeySettings(s.StrictModel):
    enabled: bool
    rpm: int = Query(ge=1, le=10000)


@router.put("/keys/{key_id}/settings")
async def key_settings(key_id: str, body: KeySettings, request: Request):
    db = database(request)
    key = db.one(select(t.keys).where(t.keys.c.id == key_id))
    if not key:
        fail(404, "not_found", "凭证不存在")
    app = scoped_object(request, t.apps, key["application_id"], DEVELOP)
    if key["revoked"]:
        fail(409, "key_revoked", "撤销凭证不能恢复，请新建凭证")
    with db.engine.begin() as conn:
        conn.execute(t.keys.update().where(t.keys.c.id == key_id).values(rpm=body.rpm))
        conn.execute(t.key_suspensions.delete().where(t.key_suspensions.c.key_id == key_id))
        if not body.enabled:
            conn.execute(t.key_suspensions.insert().values(id=t.ident(), created_at=time.time(), key_id=key_id))
    db.operation(request.state.user["id"], "key.settings", key_id, app["project_id"],
                 enabled=body.enabled, rpm=body.rpm)
    return {"ok": True}


@router.put("/applications/{application_id}/settings")
async def application_settings(application_id: str, body: s.ApplicationCreate, request: Request):
    app = scoped_object(request, t.apps, application_id, EDIT)
    policy = database(request).one(select(t.policies).where(
        t.policies.c.id == body.policy_id, t.policies.c.project_id == app["project_id"]))
    if not policy or not policy["published_version"]:
        fail(422, "policy_unpublished", "请选择本项目已发布策略")
    with database(request).engine.begin() as conn:
        conn.execute(t.apps.update().where(t.apps.c.id == application_id).values(**body.model_dump()))
    database(request).operation(request.state.user["id"], "application.settings", application_id, app["project_id"])
    return {"ok": True}


@router.post("/applications/{application_id}/keys", status_code=201)
async def create_key(application_id: str, body: s.KeyCreate, request: Request):
    application = scoped_object(request, t.apps, application_id, DEVELOP)
    db = database(request)
    token = "qg_" + secrets.token_urlsafe(32)
    item = db.insert(t.keys, application_id=application_id, name=body.name,
        prefix=token[:11], token_hash=digest(token), expires_at=time.time() + body.expires_days * 86400,
        revoked=False, rpm=body.rpm, scopes=body.scopes)
    db.operation(request.state.user["id"], "key.create", item["id"], application["project_id"])
    return {**public_key(item), "token": token, "notice": "仅本次显示，请存入业务系统的密钥管理器"}


@router.post("/keys/{key_id}/revoke")
async def revoke_key(key_id: str, request: Request):
    db = database(request)
    key = db.one(select(t.keys).where(t.keys.c.id == key_id))
    if not key:
        fail(404, "not_found", "凭证不存在")
    application = scoped_object(request, t.apps, key["application_id"], DEVELOP)
    with db.engine.begin() as conn:
        conn.execute(t.keys.update().where(t.keys.c.id == key_id).values(revoked=True))
    db.operation(request.state.user["id"], "key.revoke", key_id, application["project_id"])
    return {"ok": True}


@router.post("/keys/{key_id}/rotate", status_code=201)
async def rotate_key(key_id: str, request: Request):
    db = database(request)
    key = db.one(select(t.keys).where(t.keys.c.id == key_id))
    if not key:
        fail(404, "not_found", "凭证不存在")
    application = scoped_object(request, t.apps, key["application_id"], DEVELOP)
    if key["revoked"] or key["expires_at"] <= time.time():
        fail(409, "key_inactive", "请为失效凭证重新创建密钥")
    token = "qg_" + secrets.token_urlsafe(32)
    item = {**key, "id": t.ident(), "created_at": time.time(), "token_hash": digest(token),
            "prefix": token[:11], "last_used_at": None}
    with db.engine.begin() as conn:
        conn.execute(t.keys.insert().values(**item))
        # Explicit 24-hour overlap, bounded by the original expiration.
        conn.execute(t.keys.update().where(t.keys.c.id == key_id).values(
            expires_at=min(time.time() + 86400, key["expires_at"])))
    db.operation(request.state.user["id"], "key.rotate", key_id, application["project_id"], successor=item["id"])
    return {**public_key(item), "token": token, "overlap_hours": 24}


@router.post("/applications/{application_id}/test")
async def console_test(application_id: str, body: s.Detect, request: Request):
    application = scoped_object(request, t.apps, application_id, ("admin", "developer", "operator"))
    rate_limit(database(request), "console:" + request.state.user["id"], 30)
    return await request.app.state.service.detect(application, None, body.context(), body.response,
        request.state.request_id, source="sandbox", endpoint="console_test")


@router.get("/detections")
async def list_detections(request: Request, project_id: str, application_id: str | None = None,
                          decision: str | None = None, request_id: str | None = None,
                          source: str | None = None, before: float | None = None,
                          environment: str | None = None, since: float | None = None,
                          key_id: str | None = None, archived: bool = False,
                          limit: int = Query(50, ge=1, le=200)):
    project_access(request, project_id)
    statement = select(t.events).where(t.events.c.project_id == project_id)
    for column, value in ((t.events.c.application_id, application_id), (t.events.c.decision, decision),
                          (t.events.c.request_id, request_id), (t.events.c.source, source),
                          (t.events.c.environment, environment), (t.events.c.key_id, key_id)):
        if value:
            statement = statement.where(column == value)
    if before:
        statement = statement.where(t.events.c.created_at < before)
    if since is not None:
        statement = statement.where(t.events.c.created_at >= since)
    archive_query = select(t.audit_archives.c.event_id).where(t.audit_archives.c.project_id == project_id)
    statement = statement.where(t.events.c.id.in_(archive_query) if archived else t.events.c.id.not_in(archive_query))
    items = database(request).all(statement.order_by(t.events.c.created_at.desc()).limit(limit + 1))
    has_more = len(items) > limit
    items = items[:limit]
    return {"items": items, "next_cursor": items[-1]["created_at"] if has_more else None}


@router.get("/detections/{event_id}")
async def detection_detail(event_id: str, request: Request):
    return scoped_object(request, t.events, event_id)


@router.get("/overview")
async def overview(request: Request, project_id: str, hours: int = Query(24, ge=1, le=720),
                   environment: str = "production"):
    project_access(request, project_id)
    if environment not in ("production", "sandbox"):
        fail(422, "invalid_environment", "环境无效")
    db = database(request)
    # Sandbox testing is explicitly excluded from production metrics.
    filters = (
        t.events.c.project_id == project_id, t.events.c.environment == environment,
        t.events.c.source == ("production" if environment == "production" else "sandbox"),
        t.events.c.created_at >= time.time() - hours * 3600)
    counts = db.one(select(func.count().label("total"),
        func.sum(case((t.events.c.execution_status == "completed", 1), else_=0)).label("completed"),
        func.sum(case(((t.events.c.execution_status == "completed") & (t.events.c.decision == "block"), 1),
                      else_=0)).label("blocked")).select_from(t.events).where(*filters))
    total, completed, blocked = counts["total"], counts["completed"] or 0, counts["blocked"] or 0
    if db.engine.dialect.name == "postgresql":
        quantiles = db.one(select(*[
            func.percentile_cont(p).within_group(t.events.c.latency_ms).label(name)
            for p, name in ((.5, "p50"), (.95, "p95"), (.99, "p99"))
        ]).where(*filters))
    else:
        # SQLite is for local development/tests. Production aggregation stays in PostgreSQL.
        latencies = sorted(r["latency_ms"] for r in db.all(select(t.events.c.latency_ms).where(*filters))
                           if r["latency_ms"] is not None)
        quantiles = {name: latencies[max(0, math.ceil(len(latencies) * p) - 1)] if latencies else None
                     for p, name in ((.5, "p50"), (.95, "p95"), (.99, "p99"))}
    open_count = db.one(select(func.count().label("n")).select_from(
        t.incidents.join(t.events, t.events.c.id == t.incidents.c.event_id)).where(
        t.incidents.c.project_id == project_id, t.incidents.c.state.in_(["open", "investigating"]),
        t.events.c.environment == environment,
        t.events.c.source == ("production" if environment == "production" else "sandbox")))["n"]
    return {"total": total, "completed": completed, "blocked": blocked,
            "errors": total - completed,
            "success_rate": round(completed / total * 100, 2) if total else None,
            "block_rate": round(blocked / completed * 100, 2) if completed else None,
            "p50_ms": quantiles["p50"], "p95_ms": quantiles["p95"], "p99_ms": quantiles["p99"],
            "open_incidents": open_count, "hours": hours, "environment": environment,
            "updated_at": time.time(), "unit": "detection_items",
            "definition": "指定环境的在线检测条目；批量每项计数，评测和历史数据排除"}


@router.get("/endpoints")
async def list_endpoints(request: Request, project_id: str):
    project_access(request, project_id)
    items = database(request).all(select(t.endpoints).where(t.endpoints.c.project_id == project_id))
    return {"items": [{k: v for k, v in item.items() if k != "credential"} for item in items]}


@router.post("/endpoints", status_code=201)
async def create_endpoint(body: s.EndpointCreate, request: Request, project_id: str):
    user = project_access(request, project_id, EDIT)
    try:
        await asyncio.to_thread(validate_url, body.url, request.app.state.settings.private_hosts)
    except (ValueError, OSError):
        fail(422, "target_not_allowed", "目标地址不可用或未授权；内网地址需加入部署白名单")
    values = body.model_dump()
    values["credential"] = request.app.state.cipher.encrypt(body.credential.encode()).decode() if body.credential else ""
    item = database(request).insert(t.endpoints, project_id=project_id, enabled=True, **values)
    database(request).operation(user["id"], "endpoint.create", item["id"], project_id)
    return {k: v for k, v in item.items() if k != "credential"}


@router.post("/endpoints/{endpoint_id}/test")
async def test_endpoint(endpoint_id: str, request: Request):
    target = scoped_object(request, t.endpoints, endpoint_id, EDIT)
    rate_limit(database(request), "endpoint-test:" + request.state.user["id"], 5)
    credential = request.app.state.cipher.decrypt(target["credential"].encode()).decode() if target["credential"] else ""
    started = time.perf_counter()
    try:
        result, status = await asyncio.wait_for(post_json(
            target["url"], {"model": target["model"], "messages": [{"role": "user", "content": "请回复：连接成功"}],
                            "max_tokens": 16, "stream": False},
            request.app.state.settings.private_hosts, credential), 25)
        content = result["choices"][0]["message"]["content"]
        if not isinstance(content, str):
            raise ValueError()
    except Exception:
        fail(502, "endpoint_test_failed", "连接测试失败，请检查地址、凭证与 OpenAI Chat 协议")
    return {"ok": True, "status": status, "latency_ms": round((time.perf_counter() - started) * 1000, 2),
            "preview": redact(content)[:100]}


@router.get("/evaluations")
async def list_evaluations(request: Request, project_id: str):
    project_access(request, project_id)
    items = database(request).all(select(t.jobs).where(t.jobs.c.project_id == project_id).order_by(t.jobs.c.created_at.desc()).limit(100))
    return {"items": [{k: v for k, v in item.items() if k != "items"} for item in items]}


@router.post("/evaluations", status_code=202)
async def create_evaluation(body: s.EvaluationCreate, request: Request, project_id: str):
    user = project_access(request, project_id, OPERATE)
    db = database(request)
    application = db.one(select(t.apps).where(t.apps.c.id == body.application_id, t.apps.c.project_id == project_id))
    if not application:
        fail(404, "not_found", "应用不存在")
    if body.endpoint_id and not db.one(select(t.endpoints).where(
        t.endpoints.c.id == body.endpoint_id, t.endpoints.c.project_id == project_id)):
        fail(404, "not_found", "目标端点不存在")
    version = request.app.state.service.policy(application)
    if body.policy_version is not None:
        version = db.one(select(t.versions).where(t.versions.c.policy_id == application["policy_id"],
                                                 t.versions.c.version == body.policy_version))
        if not version:
            fail(404, "not_found", "应用策略的目标版本不存在")
    prior = db.one(select(t.jobs).where(t.jobs.c.project_id == project_id, t.jobs.c.idempotency_key == body.idempotency_key))
    items = [item.model_dump() for item in body.items]
    fingerprint = hashlib.sha256(json.dumps(items, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
    if prior:
        if prior["dataset_hash"] != fingerprint or prior["application_id"] != body.application_id or prior["endpoint_id"] != body.endpoint_id or prior["policy_version_id"] != version["id"]:
            fail(409, "idempotency_conflict", "幂等键已用于不同任务")
        return {"id": prior["id"], "state": prior["state"]}
    rate_limit(db, "evaluation:" + project_id, 10, seconds=3600)
    item = db.insert(t.jobs, project_id=project_id, application_id=body.application_id,
        endpoint_id=body.endpoint_id, policy_version_id=version["id"], name=body.name, state="queued",
        dataset_hash=fingerprint, items={"encrypted": request.app.state.cipher.encrypt(
            json.dumps(items, ensure_ascii=False).encode()).decode()},
        completed=0, total=len(items), cancel_requested=False,
        idempotency_key=body.idempotency_key)
    db.operation(user["id"], "evaluation.create", item["id"], project_id, dataset_hash=fingerprint)
    return {"id": item["id"], "state": "queued"}


@router.get("/evaluations/{job_id}")
async def evaluation_detail(job_id: str, request: Request):
    job = scoped_object(request, t.jobs, job_id)
    items = database(request).all(select(t.job_items).where(t.job_items.c.job_id == job_id).order_by(t.job_items.c.position))
    from .quality import summarize
    snapshot = (json.loads(request.app.state.cipher.decrypt(job["items"]["encrypted"].encode()))
                if isinstance(job["items"], dict) else job["items"])
    expected_total = (0 if job["endpoint_id"] else sum(
        isinstance(i.get("expected_unsafe"), bool) and i.get("mode", "text") == "text" for i in snapshot))
    return {**{k: v for k, v in job.items() if k != "items"}, "results": items,
            "metrics": summarize([r["result"] for r in items], expected_total),
            "evaluation_source": "Qwen3Guard automated reviewer; labels supplied by caller and not independently verified",
            "is_independent_benchmark": False}


@router.post("/evaluations/{job_id}/cancel")
async def cancel_evaluation(job_id: str, request: Request):
    job = scoped_object(request, t.jobs, job_id, OPERATE)
    with database(request).engine.begin() as conn:
        conn.execute(t.jobs.update().where(t.jobs.c.id == job_id, t.jobs.c.state.in_(["queued", "running"])).values(
            cancel_requested=True, state="cancelled" if job["state"] == "queued" else job["state"]))
    database(request).operation(request.state.user["id"], "evaluation.cancel", job_id, job["project_id"])
    return {"ok": True, "notice": "已请求取消；正在执行的检测结束后停止"}


@router.post("/evaluations/{job_id}/resume")
async def resume_evaluation(job_id: str, request: Request):
    job = scoped_object(request, t.jobs, job_id, OPERATE)
    if job["state"] not in ("failed", "interrupted", "cancelled"):
        fail(409, "job_not_resumable", "任务当前状态不可恢复")
    with database(request).engine.begin() as conn:
        conn.execute(t.jobs.update().where(t.jobs.c.id == job_id).values(
            state="queued", cancel_requested=False, error_code=None))
    database(request).operation(request.state.user["id"], "evaluation.resume", job_id, job["project_id"])
    return {"ok": True}


@router.get("/incidents")
async def list_incidents(request: Request, project_id: str):
    project_access(request, project_id)
    items = database(request).all(select(t.incidents, t.events.c.environment, t.events.c.source).join(
        t.events, t.events.c.id == t.incidents.c.event_id).where(
        t.incidents.c.project_id == project_id).order_by(t.incidents.c.created_at.desc()).limit(100))
    for item in items:
        item["reviews"] = database(request).all(select(t.reviews).where(
            t.reviews.c.incident_id == item["id"]).order_by(t.reviews.c.created_at))
    return {"items": items}


@router.post("/incidents/{incident_id}/reviews", status_code=201)
async def review_incident(incident_id: str, body: s.Review, request: Request):
    incident = scoped_object(request, t.incidents, incident_id, OPERATE)
    db = database(request)
    with db.engine.begin() as conn:
        conn.execute(t.reviews.insert().values(id=t.ident(), created_at=time.time(), incident_id=incident_id,
            actor_id=request.state.user["id"], state=body.state, note=body.note))
        conn.execute(t.incidents.update().where(t.incidents.c.id == incident_id).values(
            state=body.state, assignee=body.assignee))
        conn.execute(t.operations.insert().values(id=t.ident(), created_at=time.time(),
            project_id=incident["project_id"], actor_id=request.state.user["id"],
            action="incident.review", target_id=incident_id, detail={"state": body.state}))
    return {"ok": True}


@router.get("/webhooks")
async def list_hooks(request: Request, project_id: str):
    project_access(request, project_id, OPERATE)
    db = database(request)
    items = db.all(select(t.hooks).where(t.hooks.c.project_id == project_id))
    return {"items": [{k: v for k, v in item.items() if k != "secret"} for item in items],
            "deliveries": db.all(select(t.deliveries).where(
                t.deliveries.c.project_id == project_id).order_by(t.deliveries.c.created_at.desc()).limit(50))}


@router.post("/webhooks", status_code=201)
async def create_hook(body: s.HookCreate, request: Request, project_id: str):
    user = project_access(request, project_id, EDIT)
    try:
        await asyncio.to_thread(validate_url, body.url, request.app.state.settings.private_hosts)
    except (ValueError, OSError):
        fail(422, "target_not_allowed", "通知目标地址不可用或未授权")
    secret = secrets.token_urlsafe(32)
    item = database(request).insert(t.hooks, project_id=project_id, url=body.url,
        secret=request.app.state.cipher.encrypt(secret.encode()).decode(), enabled=True)
    database(request).operation(user["id"], "webhook.create", item["id"], project_id)
    return {"id": item["id"], "signing_secret": secret}


@router.post("/webhooks/{hook_id}/disable")
async def disable_hook(hook_id: str, request: Request):
    hook = scoped_object(request, t.hooks, hook_id, EDIT)
    with database(request).engine.begin() as conn:
        conn.execute(t.hooks.update().where(t.hooks.c.id == hook_id).values(enabled=False))
    database(request).operation(request.state.user["id"], "webhook.disable", hook_id, hook["project_id"])
    return {"ok": True}


@router.get("/operations")
async def operation_log(request: Request, project_id: str):
    project_access(request, project_id, ("admin", "auditor", "operator"))
    return {"items": database(request).all(select(t.operations).where(
        t.operations.c.project_id == project_id).order_by(t.operations.c.created_at.desc()).limit(100))}


@router.get("/system")
async def system_status(request: Request):
    global_admin(request)
    state = request.app.state
    return {"model": state.models.status(), "inference_pending": state.pool.pending,
            "inference_capacity": state.pool.capacity, "database": state.db.engine.dialect.name,
            "schema_version": 2, "worker_mode": "single-coordinator",
            "modalities": {"text": "available", "image": "todo", "audio": "todo", "video": "todo", "document": "todo"}}
