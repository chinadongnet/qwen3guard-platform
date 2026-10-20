from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
import time

from cryptography.fernet import Fernet
from fastapi import HTTPException, Request
from sqlalchemy import select

from . import db as tables


def digest(token):
    return hashlib.sha256(token.encode()).hexdigest()


def hash_password(password):
    salt = secrets.token_hex(16)
    value = hashlib.scrypt(password.encode(), salt=salt.encode(), n=16384, r=8, p=1)
    return f"scrypt${salt}${value.hex()}"


def verify_password(password, encoded):
    try:
        algorithm, salt, expected = encoded.split("$")
        if algorithm != "scrypt":
            return False
        value = hashlib.scrypt(password.encode(), salt=salt.encode(), n=16384, r=8, p=1)
        return hmac.compare_digest(value.hex(), expected)
    except (ValueError, TypeError):
        return False


def encryptor(secret):
    return Fernet(base64.urlsafe_b64encode(hashlib.sha256(secret.encode()).digest()))


PII_PATTERNS = [
    ("api_secret", re.compile(r"\b(?:sk-|qg-live-|qg_)[A-Za-z0-9_-]{16,}")),
    ("email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("cn_id", re.compile(r"\b\d{17}[\dXx]\b")),
    ("phone", re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)")),
    ("bank_card", re.compile(r"(?<!\d)\d{16,19}(?!\d)")),
]


def redact(text):
    for name, pattern in PII_PATTERNS:
        text = pattern.sub(f"[{name.upper()}]", text)
    return text


def pii_findings(text):
    return [{"type": name, "start": m.start(), "end": m.end()}
            for name, pattern in PII_PATTERNS for m in pattern.finditer(text)]


def fail(status, code, message):
    raise HTTPException(status, {"code": code, "message": message,
                                 "retryable": status in (429, 503, 504)})


def current_user(request: Request):
    database = request.app.state.db
    token = request.cookies.get("qg_session", "")
    session = database.one(select(tables.sessions).where(
        tables.sessions.c.token_hash == digest(token),
        tables.sessions.c.expires_at > time.time())) if token else None
    user = database.one(select(tables.users).where(
        tables.users.c.id == session["user_id"], tables.users.c.enabled.is_(True))) if session else None
    if not user:
        fail(401, "authentication_required", "请先登录")
    if request.method not in ("GET", "HEAD", "OPTIONS"):
        if not hmac.compare_digest(request.headers.get("X-CSRF-Token", ""), session["csrf"]):
            fail(403, "csrf_failed", "会话校验失败，请刷新页面")
    request.state.user = user
    request.state.session = session
    return user


def project_access(request, project_id, roles=None):
    user = current_user(request)
    database = request.app.state.db
    project = database.one(select(tables.projects).where(tables.projects.c.id == project_id))
    if not project:
        fail(404, "not_found", "项目不存在")
    if user["is_admin"]:
        return user
    member = database.one(select(tables.members).where(
        tables.members.c.user_id == user["id"], tables.members.c.project_id == project_id))
    if not member or (roles and member["role"] not in roles):
        fail(403, "forbidden", "没有此项目的操作权限")
    return user


def global_admin(request):
    user = current_user(request)
    if not user["is_admin"]:
        fail(403, "forbidden", "仅平台管理员可执行")
    return user


def rate_limit(database, bucket, limit, units=1, seconds=60):
    """Atomic, cross-process budget in the shared relational database."""
    now_window = int(time.time()) // seconds
    dialect = database.engine.dialect.name
    if dialect == "postgresql":
        from sqlalchemy.dialects.postgresql import insert
    else:
        from sqlalchemy.dialects.sqlite import insert
    with database.engine.begin() as conn:
        stmt = insert(tables.counters).values(bucket=bucket, window=now_window, count=0)
        conn.execute(stmt.on_conflict_do_nothing(index_elements=["bucket"]))
        conn.execute(tables.counters.update().where(
            tables.counters.c.bucket == bucket, tables.counters.c.window != now_window
        ).values(window=now_window, count=0))
        updated = conn.execute(tables.counters.update().where(
            tables.counters.c.bucket == bucket, tables.counters.c.count + units <= limit
        ).values(count=tables.counters.c.count + units))
        if updated.rowcount != 1:
            fail(429, "rate_limited", "请求额度已用尽，请稍后重试")


def api_identity(request, scope="detect", units=1):
    raw = request.headers.get("X-API-Key", "")
    authorization = request.headers.get("Authorization", "")
    if authorization.lower().startswith("bearer "):
        raw = authorization[7:].strip()
    if not raw or len(raw) > 256:
        fail(401, "invalid_api_key", "需要有效的 API Key")
    database = request.app.state.db
    key = database.one(select(tables.keys).where(tables.keys.c.token_hash == digest(raw)))
    if not key or not hmac.compare_digest(key["token_hash"], digest(raw)):
        fail(401, "invalid_api_key", "需要有效的 API Key")
    if key["revoked"] or key["expires_at"] <= time.time():
        fail(403, "key_inactive", "凭证已过期或撤销")
    if scope not in key["scopes"]:
        fail(403, "insufficient_scope", "凭证没有此接口权限")
    application = database.one(select(tables.apps).where(
        tables.apps.c.id == key["application_id"], tables.apps.c.enabled.is_(True)))
    if not application:
        fail(403, "application_inactive", "应用不可用")
    if database.one(select(tables.key_suspensions.c.id).where(tables.key_suspensions.c.key_id == key["id"])):
        fail(403, "key_suspended", "凭证已暂停")
    rate_limit(database, "key:" + key["id"], key["rpm"], units=units)
    with database.engine.begin() as conn:
        conn.execute(tables.keys.update().where(tables.keys.c.id == key["id"]).values(last_used_at=time.time()))
    return application, key
