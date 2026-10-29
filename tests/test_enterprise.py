import asyncio
import threading

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.enterprise.application import create_app
from app.enterprise.settings import Settings
from app.enterprise import db as t
from app.enterprise.inference import InferencePool, InferenceTimeout, QueueFull
from app.enterprise.network import validate_url


class FakeModels:
    def load(self):
        pass

    def status(self):
        return {"loaded": True}

    def detect(self, prompt, response, config):
        target = response if response is not None else prompt
        if "ENGINE_FAIL" in target:
            raise RuntimeError("internal engine details")
        unsafe = "BLOCK" in target
        return {"is_safe": not unsafe, "risk_level": "Unsafe" if unsafe else "Safe",
                "risk_score": .9 if unsafe else .08, "latency_ms": 1, "tc260": None,
                "qwen_guard_gen": {"safety": "Unsafe" if unsafe else "Safe",
                                   "categories": ["Violent"] if unsafe else [],
                                   "refusal": "Yes" if (response and "REFUSAL_SAFE" in response) else None},
                "security_shield": {"matched_rules": []}}

    def scan(self, prompt, response, config):
        target = response if response is not None else prompt
        if "ENGINE_FAIL" in target:
            raise RuntimeError("internal engine details")
        unsafe = "BLOCK" in target
        return {"is_safe": not unsafe, "overall_risk_level": "Unsafe" if unsafe else "Safe",
                "risk_score": .9 if unsafe else .05, "latency_ms": 1, "tc260": None,
                "circuit_breaker_triggered": unsafe, "cutoff_token_index": 0 if unsafe else None,
                "total_tokens_inspected": 4, "detected_categories": ["Violent"] if unsafe else [],
                "token_stream": []}

    def generation(self, messages, max_tokens, temperature, stop):
        for text in ["正常回答，", "继续说明。", "BLOCK", "禁止输出"]:
            if stop.is_set():
                return
            yield text


@pytest.fixture
def client(tmp_path):
    settings = Settings(database_url=f"sqlite:///{tmp_path / 'test.db'}",
                        secret="test-secret-" * 4, admin_password="test-password-123", testing=True)
    app = create_app(settings, FakeModels())
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c


def login(client, username="admin", password="test-password-123"):
    response = client.post("/api/admin/auth/login", json={"username": username, "password": password})
    assert response.status_code == 200, response.text
    client.headers["X-CSRF-Token"] = response.json()["csrf_token"]
    return response.json()["user"]


def project_setup(client, name="test"):
    project = client.post("/api/admin/projects", json={"name": name}).json()
    policy = client.post("/api/admin/policies", params={"project_id": project["id"]},
                         json={"name": "standard", "config": {}}).json()
    assert client.post(f"/api/admin/policies/{policy['id']}/publish",
                       json={"version": 1, "expected_current": 0}).status_code == 200
    application = client.post("/api/admin/applications", params={"project_id": project["id"]},
        json={"name": "app", "environment": "production", "policy_id": policy["id"]}).json()
    key = client.post(f"/api/admin/applications/{application['id']}/keys",
        json={"name": "key", "scopes": ["detect", "audit:read", "chat"]}).json()
    return project, policy, application, key


def test_anonymous_and_legacy_access(client):
    for path in ("/api/admin/projects", "/api/gateway/config", "/api/config", "/api/audit/logs", "/docs"):
        assert client.get(path).status_code == 401, path
    assert client.post("/v1/guard/detect", json={"prompt": "hello"}).status_code == 401
    assert client.post("/api/gateway/keys", json={"name": "bad"}).status_code == 401


def test_full_lifecycle_and_key_redaction(client):
    login(client)
    project, policy, application, key = project_setup(client)
    listing = client.get(f"/api/admin/applications/{application['id']}/keys")
    assert "token_hash" not in listing.text and key["token"] not in listing.text
    detected = client.post("/v1/guard/detect", headers={"Authorization": f"Bearer {key['token']}"},
                           json={"prompt": "hello"})
    assert detected.status_code == 200, detected.text
    result = detected.json()
    assert result["decision"] == "allow"
    assert result["request_id"] == detected.headers["X-Request-Id"]
    events = client.get("/api/admin/detections", params={"project_id": project["id"]}).json()["items"]
    assert len(events) == 1 and events[0]["request_id"] == result["request_id"]
    assert client.get("/api/admin/detections", params={
        "project_id": project["id"], "environment": "sandbox"}).json()["items"] == []
    overview = client.get("/api/admin/overview", params={"project_id": project["id"]}).json()
    assert overview["total"] == 1 and overview["success_rate"] == 100
    assert client.post(f"/api/admin/keys/{key['id']}/revoke").status_code == 200
    assert client.post("/v1/guard/detect", headers={"X-API-Key": key["token"]},
                       json={"prompt": "hello"}).status_code == 403


def test_csrf_and_origin(client):
    login(client)
    client.headers.pop("X-CSRF-Token")
    assert client.post("/api/admin/projects", json={"name": "bad"}).status_code == 403
    assert client.post("/api/admin/auth/login", headers={"Origin": "https://evil.example"},
        json={"username": "admin", "password": "test-password-123"}).status_code == 403


def test_cross_project_access(client):
    login(client)
    p1, _, a1, k1 = project_setup(client, "one")
    p2, _, a2, k2 = project_setup(client, "two")
    for key in (k1, k2):
        assert client.post("/v1/guard/detect", headers={"X-API-Key": key["token"]},
                           json={"prompt": "hello"}).status_code == 200
    user = client.post("/api/admin/users", json={"username": "dev", "password": "developer-password"}).json()
    client.put(f"/api/admin/projects/{p1['id']}/members", json={"user_id": user["id"], "role": "developer"})
    client.post("/api/admin/auth/logout")
    login(client, "dev", "developer-password")
    assert client.get("/api/admin/detections", params={"project_id": p2["id"]}).status_code == 403
    assert client.get(f"/api/admin/applications/{a2['id']}/keys").status_code == 403
    own = client.get("/v1/audit/logs", headers={"X-API-Key": k1["token"]}).json()["items"]
    assert len(own) == 1 and own[0]["application_id"] == a1["id"]
    client.post("/api/admin/auth/logout")
    assert client.get("/api/admin/projects", headers={"X-API-Key": k1["token"]}).status_code == 401


def test_failure_is_not_safe_and_is_persisted(client):
    login(client)
    project, _, _, key = project_setup(client)
    response = client.post("/v1/guard/detect", headers={"X-API-Key": key["token"]}, json={"prompt": "ENGINE_FAIL"})
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "inference_failed"
    assert "internal engine" not in response.text
    rows = client.get("/api/admin/detections", params={"project_id": project["id"]}).json()["items"]
    assert rows[0]["risk_level"] == "indeterminate" and rows[0]["execution_status"] == "error"


def test_policy_versions_and_sandbox_metrics(client):
    login(client)
    project, policy, application, key = project_setup(client)
    response = client.post(f"/api/admin/policies/{policy['id']}/versions", json={"pii_action": "mask"})
    assert response.json()["version"] == 2
    assert client.post(f"/api/admin/policies/{policy['id']}/publish",
        json={"version": 2, "expected_current": 0}).status_code == 409
    assert client.post(f"/api/admin/policies/{policy['id']}/publish",
        json={"version": 2, "expected_current": 1}).status_code == 409
    evaluation = client.post("/api/admin/evaluations", params={"project_id": project["id"]}, json={
        "name": "candidate", "application_id": application["id"], "policy_version": 2,
        "idempotency_key": "candidate-version-two", "items": [{"prompt": "hello", "expected_unsafe": False}]}).json()
    job = client.app.state.db.one(select(t.jobs).where(t.jobs.c.id == evaluation["id"]))
    client.portal.call(client.app.state.runner.run_job, job)
    assert client.post(f"/api/admin/policies/{policy['id']}/publish",
        json={"version": 2, "expected_current": 1}).status_code == 200
    response = client.post("/v1/guard/detect", headers={"X-API-Key": key["token"]},
                           json={"prompt": "联系 test@example.com"})
    assert response.json()["decision"] == "mask"
    assert "test@example.com" not in response.json()["sanitized_content"]
    client.post(f"/api/admin/applications/{application['id']}/test", json={"prompt": "hello"})
    assert client.get("/api/admin/overview", params={"project_id": project["id"]}).json()["total"] == 1
    assert "test@example.com" not in client.get("/api/admin/detections", params={"project_id": project["id"]}).text


def test_input_limits_and_no_media(client):
    login(client)
    _, _, _, key = project_setup(client)
    headers = {"X-API-Key": key["token"]}
    assert client.post("/v1/guard/detect", headers=headers, json={"prompt": " "}).status_code == 422
    assert client.post("/v1/guard/detect", headers=headers, json={"prompt": "image", "content_type": "image"}).status_code == 422
    assert client.post("/v1/chat/completions", headers=headers, json={
        "messages": [{"role": "user", "content": "hello"}], "guarded": False}).status_code == 422
    large = client.post("/v1/guard/detect", headers=headers, content=b"x" * (2 * 1024 * 1024 + 1))
    assert large.status_code == 413


def test_rate_limit_batch_units(client):
    login(client)
    _, _, application, _ = project_setup(client)
    key = client.post(f"/api/admin/applications/{application['id']}/keys",
        json={"name": "limited", "rpm": 1}).json()
    response = client.post("/v1/guard/batch", headers={"X-API-Key": key["token"]},
        json={"items": [{"prompt": "one"}, {"prompt": "two"}]})
    assert response.status_code == 429


def test_real_incremental_guard_never_releases_bad_window(client):
    login(client)
    project, _, _, key = project_setup(client)
    response = client.post("/v1/chat/completions", headers={"X-API-Key": key["token"]}, json={
        "messages": [{"role": "user", "content": "hello"}], "stream": True})
    assert response.status_code == 200
    assert "content_filter" in response.text
    assert '"content": "BLOCK' not in response.text and "禁止输出" not in response.text
    assert "[DONE]" in response.text
    assert not client.app.state.stream_active
    events = client.get("/api/admin/detections", params={"project_id": project["id"]}).json()["items"]
    assert any(e["endpoint"] == "chat_terminal" and e["decision"] == "block" for e in events)
    assert len(client.get("/api/admin/incidents", params={"project_id": project["id"]}).json()["items"]) == 1


def test_stream_failure_is_audited_without_leaking_unreviewed_content(client):
    login(client)
    project, _, _, key = project_setup(client)
    def broken(*args):
        yield "未审核内容"
        raise RuntimeError("private engine details")
    client.app.state.models.generation = broken
    response = client.post("/v1/chat/completions", headers={"X-API-Key": key["token"]}, json={
        "messages": [{"role": "user", "content": "hello"}], "stream": True})
    assert "event: error" in response.text
    assert "未审核内容" not in response.text and "private engine details" not in response.text
    terminal = client.app.state.db.one(select(t.events).where(t.events.c.endpoint == "chat_terminal"))
    assert terminal["execution_status"] == "error" and terminal["risk_level"] == "indeterminate"
    assert terminal["source"] == "production" and not client.app.state.stream_active


def test_evaluation_and_review(client):
    login(client)
    project, _, application, key = project_setup(client)
    payload = {"name": "regression", "application_id": application["id"], "idempotency_key": "unique-test-job",
               "items": [{"prompt": "hello", "expected_unsafe": False}, {"prompt": "BLOCK", "expected_unsafe": True}]}
    created = client.post("/api/admin/evaluations", params={"project_id": project["id"]}, json=payload)
    assert created.status_code == 202, created.text
    assert client.post("/api/admin/evaluations", params={"project_id": project["id"]}, json=payload).json()["id"] == created.json()["id"]
    job = client.app.state.db.one(select(t.jobs).where(t.jobs.c.id == created.json()["id"]))
    client.portal.call(client.app.state.runner.run_job, job)
    result = client.get(f"/api/admin/evaluations/{job['id']}").json()
    assert result["state"] == "completed" and result["metrics"]["accuracy"] == 1
    assert client.get("/api/admin/overview", params={"project_id": project["id"]}).json()["total"] == 0
    assert client.get("/api/admin/incidents", params={"project_id": project["id"]}).json()["items"] == []
    client.post("/v1/guard/detect", headers={"X-API-Key": key["token"]}, json={"prompt": "BLOCK"})
    incident = client.get("/api/admin/incidents", params={"project_id": project["id"]}).json()["items"][0]
    assert client.post(f"/api/admin/incidents/{incident['id']}/reviews",
        json={"state": "resolved", "note": "确认风险并处理", "assignee": "admin"}).status_code == 201
    rows = client.get("/api/admin/incidents", params={"project_id": project["id"]}).json()["items"]
    assert len(rows[0]["reviews"]) == 1
    assert client.get("/api/admin/overview", params={"project_id": project["id"]}).json()["total"] == 1


def test_timeout_does_not_release_busy_slot():
    async def scenario():
        pool = InferencePool(capacity=1)
        gate = threading.Event()
        with pytest.raises(InferenceTimeout):
            await pool.run(lambda: gate.wait(2), timeout=.02)
        assert pool.pending == 1
        with pytest.raises(QueueFull):
            await pool.run(lambda: True)
        gate.set()
        for _ in range(20):
            if pool.pending == 0:
                break
            await asyncio.sleep(.01)
        assert pool.pending == 0
        pool.close()
    asyncio.run(scenario())


def test_ssrf_blocking():
    with pytest.raises(ValueError):
        validate_url("https://127.0.0.1/admin")
    with pytest.raises(ValueError):
        validate_url("http://example.com/api")
    with pytest.raises(ValueError):
        validate_url("https://user:password@example.com/api")
    with pytest.raises(ValueError):
        validate_url("http://169.254.169.254/latest", ("169.254.169.254",))
    pinned, headers, _ = validate_url("http://127.0.0.1:8092/v1/chat/completions", ("127.0.0.1",))
    assert pinned.startswith("http://127.0.0.1:8092/") and headers["Host"] == "127.0.0.1:8092"


def test_api_key_creation_and_policy_configuration(client):
    login(client)
    # 1. One-click API key creation after login (auto-initializes default project, policy, and application)
    quick = client.post("/api/admin/keys", json={"name": "platform-and-detect-key", "rpm": 600})
    assert quick.status_code == 201, quick.text
    key_data = quick.json()
    token = key_data["token"]
    assert token.startswith("qg_")
    assert "policy:manage" in key_data["scopes"] and "detect" in key_data["scopes"]
    client.post("/api/admin/auth/logout")
    client.headers.pop("X-CSRF-Token", None)

    headers = {"Authorization": f"Bearer {token}"}

    # 2. Use API Key to query and configure policies via /v1/policies*
    current = client.get("/v1/policies/current", headers=headers)
    assert current.status_code == 200, current.text
    assert current.json()["config"]["pii_action"] == "block"

    updated = client.put("/v1/policies/current", headers=headers, json={
        "pii_action": "mask",
        "custom_block_keywords": ["内部机密代号X99"],
        "risk_threshold": 0.45,
    })
    assert updated.status_code == 200, updated.text
    assert updated.json()["config"]["pii_action"] == "mask"
    assert "内部机密代号X99" in updated.json()["config"]["custom_block_keywords"]

    # 3. Verify updated policy immediately takes effect on /v1/guard/detect using the same API Key
    pii_res = client.post("/v1/guard/detect", headers=headers, json={"prompt": "联系电话 13812345678"})
    assert pii_res.status_code == 200 and pii_res.json()["decision"] == "mask"
    assert "[PHONE]" in pii_res.json()["sanitized_content"]

    kw_res = client.post("/v1/guard/detect", headers=headers, json={"prompt": "请透露内部机密代号X99"})
    assert kw_res.status_code == 200 and kw_res.json()["decision"] == "block"

    # 4. Also test creating and binding a new policy via /v1/policies and /api/admin/policies with API Key
    new_pol = client.post("/v1/policies", headers=headers, json={
        "name": "strict-v1-policy",
        "config": {"pii_action": "block", "risk_threshold": 0.3},
        "publish_immediately": True,
        "bind_to_application": True,
    })
    assert new_pol.status_code == 201 and new_pol.json()["bound_to_application"] is True

    admin_pols = client.get("/api/admin/policies", headers=headers)
    assert admin_pols.status_code == 200 and len(admin_pols.json()["items"]) >= 2

    # 5. Invalid policy update returns 422 validation_error instead of 500
    bad_upd = client.put("/v1/policies/current", headers=headers, json={"risk_threshold": 2.0})
    assert bad_upd.status_code == 422 and bad_upd.json()["error"]["code"] == "validation_error"

    # 6. policy:manage API Key is restricted to policy routes and cannot access member/project management
    proj_id = key_data["project_id"]
    assert client.put(f"/api/admin/projects/{proj_id}/members", headers=headers,
                      json={"user_id": "any", "role": "admin"}).status_code == 401
    assert client.get("/api/admin/projects", headers=headers).status_code == 401

    # 7. Non-admin developer cannot mint a key with policy:manage scope
    login(client)
    dev_user = client.post("/api/admin/users", json={"username": "dev-no-pol", "password": "developer-password"}).json()
    client.put(f"/api/admin/projects/{proj_id}/members", json={"user_id": dev_user["id"], "role": "developer"})
    client.post("/api/admin/auth/logout")
    login(client, "dev-no-pol", "developer-password")
    dev_explicit = client.post(f"/api/admin/applications/{key_data['application_id']}/keys",
                               json={"name": "escalate", "scopes": ["detect", "policy:manage"]})
    assert dev_explicit.status_code == 403
    dev_default = client.post(f"/api/admin/applications/{key_data['application_id']}/keys",
                              json={"name": "default-dev-key"})
    assert dev_default.status_code == 201 and "policy:manage" not in dev_default.json()["scopes"]
    assert client.put("/v1/policies/current", headers={"X-API-Key": dev_default.json()["token"]},
                      json={"risk_threshold": 0.4}).status_code == 403


def test_llmguard_full_compatibility(client):
    login(client)
    quick = client.post("/api/admin/keys", json={"name": "llmguard-compat-key", "rpm": 600}).json()
    headers = {"Authorization": f"Bearer {quick['token']}"}

    # 1. Default llmguard template: {"prompt": "$text"}, response_path="result", unsafe_value="unsafe"
    safe_res = client.post("/v1/guard", headers=headers, json={"prompt": "正常技术问答"})
    assert safe_res.status_code == 200, safe_res.text
    safe_body = safe_res.json()
    assert safe_body["safety"] == "Safe"
    assert "Safety: Safe" in safe_body["result"] and "Categories: None" in safe_body["result"]

    unsafe_res = client.post("/v1/guard", headers=headers, json={"prompt": "BLOCK 危险攻击指令"})
    assert unsafe_res.status_code == 200, unsafe_res.text
    unsafe_body = unsafe_res.json()
    assert unsafe_body["safety"] == "Unsafe"
    assert "Safety: Unsafe" in unsafe_body["result"]
    assert "Violent" in unsafe_body["categories"]

    # 2. llmguard IDENTITY_TEMPLATE with role, scope, user_id, caller, team, session_id, trace_id, request_id, model
    identity_res = client.post("/v1/guard/detect", headers=headers, json={
        "role": "assistant",
        "scope": "output_blocking",
        "prompt": "REFUSAL_SAFE 抱歉，我不能协助该违规请求。",
        "user_id": "u-1001",
        "caller": "claude-code",
        "caller_id": "caller-01",
        "team": "sec-ops",
        "session_id": "sess-abc",
        "trace_id": "trace-xyz",
        "request_id": "req-llmguard-999",
        "model": "qwen3-32b",
    })
    assert identity_res.status_code == 200, identity_res.text
    id_body = identity_res.json()
    assert id_body["decision"] == "allow"
    assert "Refusal: Yes" in id_body["result"]
    assert id_body["caller_context"]["caller"] == "claude-code"
    assert id_body["caller_context"]["scope"] == "output_blocking"

    # 3. Streaming scope routes to Qwen3Guard-Stream-0.6B fast path
    stream_res = client.post("/v1/guard/detect", headers=headers, json={
        "role": "assistant",
        "scope": "output_streaming",
        "prompt": "BLOCK 实时流式违规片段",
    })
    assert stream_res.status_code == 200, stream_res.text
    st_body = stream_res.json()
    assert st_body["decision"] == "block"
    assert st_body["model"]["id"] == "Qwen3Guard-Stream-0.6B"
    assert "Safety: Unsafe" in st_body["result"]

    # 4. Long-context multi-turn input smart window truncation (> 16000 chars)
    # Deterministic checks (PII & custom keywords) still inspect the full untruncated middle segment
    long_text = "历史对话内容 " * 5000 + "\n当前用户提问：请总结架构设计"
    assert len(long_text) > 30000
    long_res = client.post("/v1/guard/detect", headers=headers, json={"prompt": long_text})
    assert long_res.status_code == 200, long_res.text
    assert long_res.json()["decision"] == "allow"

    mid_pii_text = ("A" * 5000) + " 联系电话 13812345678 " + ("B" * 9000)
    assert len(mid_pii_text) > 14000
    mid_pii_res = client.post("/v1/guard/detect", headers=headers, json={"prompt": mid_pii_text})
    assert mid_pii_res.status_code == 200 and mid_pii_res.json()["decision"] == "block"
    assert len(mid_pii_res.json()["findings"]) == 1

    # 5. Verify TC260 taxonomy alignment in _build_llmguard_compat
    from app.enterprise.service import _build_llmguard_compat
    _, cats_a14, _ = _build_llmguard_compat(
        "block", None, {"tc260": {"major_code": "A.1", "sub_code": "A.1.4", "sub_name": "宣扬恐怖主义、极端主义"}}, [], [])
    assert cats_a14[0] == "Terror"
    _, cats_a15, _ = _build_llmguard_compat(
        "block", None, {"tc260": {"major_code": "A.1", "sub_code": "A.1.5", "sub_name": "宣扬民族仇恨"}}, [], [])
    assert cats_a15[0] == "Discrimination"
    _, cats_a17, _ = _build_llmguard_compat(
        "block", None, {"tc260": {"major_code": "A.1", "sub_code": "A.1.7", "sub_name": "传播虚假有害信息"}}, [], [])
    assert cats_a17[0] == "Illegal"
    _, cats_a21, _ = _build_llmguard_compat(
        "block", None, {"tc260": {"major_code": "A.2", "sub_code": "A.2.1", "sub_name": "民族歧视内容"}}, [], [])
    assert cats_a21[0] == "Discrimination"
