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
                "security_shield": {"matched_rules": []}}

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
