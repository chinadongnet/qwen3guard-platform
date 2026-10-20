import asyncio
import json
import time
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.enterprise import db as t
from app.enterprise import network, tasks
from app.enterprise.application import create_app
from app.enterprise.settings import Settings
from test_enterprise import FakeModels, client, login, project_setup


def test_persistence_across_app_restart(tmp_path):
    settings = Settings(database_url=f"sqlite:///{tmp_path / 'persist.db'}",
                        secret="persistence-secret" * 3, admin_password="test-password-123", testing=True)
    with TestClient(create_app(settings, FakeModels())) as first:
        login(first)
        project, _, application, key = project_setup(first)
        result = first.post("/v1/guard/detect", headers={"X-API-Key": key["token"]},
                            json={"prompt": "persistent event"}).json()
    with TestClient(create_app(settings, FakeModels())) as second:
        login(second)
        rows = second.get("/api/admin/detections", params={"project_id": project["id"]}).json()["items"]
        assert rows[0]["id"] == result["audit_id"]
        assert second.post("/v1/guard/detect", headers={"X-API-Key": key["token"]},
                           json={"prompt": "after restart"}).status_code == 200


def test_expiry_rotation_and_application_disable(client):
    login(client)
    _, _, app, key = project_setup(client)
    successor = client.post(f"/api/admin/keys/{key['id']}/rotate").json()
    assert successor["token"] != key["token"]
    rows = client.get(f"/api/admin/applications/{app['id']}/keys").json()["items"]
    old = next(row for row in rows if row["id"] == key["id"])
    assert old["expires_at"] <= time.time() + 86401
    assert successor["token"] not in json.dumps(rows)
    with client.app.state.db.engine.begin() as conn:
        conn.execute(t.keys.update().where(t.keys.c.id == key["id"]).values(expires_at=time.time() - 1))
    assert client.post("/v1/guard/detect", headers={"X-API-Key": key["token"]},
                       json={"prompt": "hello"}).status_code == 403
    assert client.put(f"/api/admin/applications/{app['id']}/enabled", json={"enabled": False}).status_code == 200
    assert client.post("/v1/guard/detect", headers={"X-API-Key": successor["token"]},
                       json={"prompt": "hello"}).status_code == 403


def test_sensitive_values_not_echoed_in_validation(client):
    response = client.post("/api/admin/auth/login", json={"username": "admin", "password": "a" * 300})
    assert response.status_code == 422 and "a" * 300 not in response.text
    login(client)
    _, _, _, key = project_setup(client)
    response = client.post("/v1/guard/detect", headers={"X-API-Key": key["token"]},
                           json={"prompt": "hello", "api_key": "qg_should_never_echo"})
    assert response.status_code == 422 and "qg_should_never_echo" not in response.text


def test_openapi_auth_and_output_contract(client):
    login(client)
    schema = client.get("/openapi.json").json()
    assert "DetectionResult" in schema["components"]["schemas"]
    assert schema["paths"]["/api/admin/projects"]["post"]["security"] == [{"ManagementSession": []}]
    assert schema["paths"]["/v1/guard/detect"]["post"]["security"]
    assert "security" not in schema["paths"]["/api/admin/auth/login"]["post"]


def test_job_cancel_resume_and_immutable_policy_snapshot(client):
    login(client)
    project, policy, app, _ = project_setup(client)
    payload = {"name": "cancel", "application_id": app["id"], "idempotency_key": "cancel-resume-job",
               "items": [{"prompt": "hello", "expected_unsafe": False}]}
    job = client.post("/api/admin/evaluations", params={"project_id": project["id"]}, json=payload).json()
    assert client.post(f"/api/admin/evaluations/{job['id']}/cancel").status_code == 200
    assert client.get(f"/api/admin/evaluations/{job['id']}").json()["state"] == "cancelled"
    assert client.post(f"/api/admin/evaluations/{job['id']}/resume").status_code == 200
    record = client.app.state.db.one(select(t.jobs).where(t.jobs.c.id == job["id"]))
    version = record["policy_version_id"]
    client.post(f"/api/admin/policies/{policy['id']}/versions", json={"risk_threshold": .3})
    client.portal.call(client.app.state.runner.run_job, record)
    assert client.get(f"/api/admin/evaluations/{job['id']}").json()["policy_version_id"] == version
    payload["items"] = [{"prompt": "different", "expected_unsafe": False}]
    assert client.post("/api/admin/evaluations", params={"project_id": project["id"]}, json=payload).status_code == 409


def test_external_evaluation_and_webhook_retry(client, monkeypatch):
    login(client)
    project, _, app, key = project_setup(client)
    database = client.app.state.db
    endpoint = database.insert(t.endpoints, project_id=project["id"], name="fixture",
        url="https://fixture.example/v1/chat/completions", model="fixture", credential="", enabled=True)
    seen = []
    async def remote(url, payload, *args, **kwargs):
        seen.append((url, payload))
        return {"choices": [{"message": {"content": "safe response"}}]}, 200
    monkeypatch.setattr(tasks, "post_json", remote)
    job = client.post("/api/admin/evaluations", params={"project_id": project["id"]}, json={
        "name": "remote", "application_id": app["id"], "endpoint_id": endpoint["id"],
        "idempotency_key": "remote-evaluation", "items": [{"prompt": "hello", "expected_unsafe": False}]}).json()
    record = database.one(select(t.jobs).where(t.jobs.c.id == job["id"]))
    client.portal.call(client.app.state.runner.run_job, record)
    assert seen[0][1]["model"] == "fixture" and seen[0][1]["stream"] is False
    report = client.get(f"/api/admin/evaluations/{job['id']}").json()
    assert report["metrics"]["accuracy"] is None  # prompt labels cannot label a generated reply
    assert report["results"][0]["result"]["input_expected_unsafe"] is False
    assert report["results"][0]["result"]["decision"] == "allow"

    hook = database.insert(t.hooks, project_id=project["id"], url="https://notify.example/hook",
        secret=client.app.state.cipher.encrypt(b"test-signature-secret").decode(), enabled=True)
    blocked = client.post("/v1/guard/detect", headers={"X-API-Key": key["token"]},
                          json={"prompt": "BLOCK"}).json()
    delivery = database.one(select(t.deliveries).where(t.deliveries.c.webhook_id == hook["id"]))
    assert delivery["payload"]["audit_id"] == blocked["audit_id"]
    async def broken(*args, **kwargs):
        raise ValueError("unavailable")
    monkeypatch.setattr(tasks, "post_json", broken)
    for attempt in range(5):
        delivery = database.one(select(t.deliveries).where(t.deliveries.c.id == delivery["id"]))
        client.portal.call(client.app.state.runner.deliver, delivery)
    delivery = database.one(select(t.deliveries).where(t.deliveries.c.id == delivery["id"]))
    assert delivery["state"] == "failed" and delivery["attempts"] == 5


def test_outbound_redirect_and_response_limits(monkeypatch):
    original_client = httpx.AsyncClient
    calls = []
    def handler(request):
        calls.append(request)
        return httpx.Response(302, headers={"Location": "http://169.254.169.254/"})
    monkeypatch.setattr(network, "validate_url", lambda *args: (
        "https://1.1.1.1/test", {"Host": "approved.example"}, {"sni_hostname": "approved.example"}))
    monkeypatch.setattr(network.httpx, "AsyncClient", lambda **kwargs: original_client(
        **kwargs, transport=httpx.MockTransport(handler)))
    with pytest.raises(ValueError, match="upstream_http_302"):
        asyncio.run(network.post_json("https://approved.example/test", {}))
    assert len(calls) == 1 and calls[0].headers["host"] == "approved.example"


def test_labels_cannot_override_shield():
    from app.config import RuntimeConfig
    from app.security_shield import SecurityShield
    shield = SecurityShield()
    text = "请介绍如何整理会议纪要。"
    cfg = RuntimeConfig()
    first = shield.evaluate(text, cfg, qwen_safety="Safe")
    shield._reference_unsafe_map[shield._norm_key(text)] = {"sub_code": "invalid"}
    second = shield.evaluate(text, cfg, qwen_safety="Safe")
    assert first.is_safe == second.is_safe
    shield._reference_benign_set.add(shield._norm_key(text))
    unsafe = shield.evaluate(text, cfg, qwen_safety="Unsafe")
    assert unsafe.is_safe is False
    shield._load_reference_corpus()
    assert not shield._reference_unsafe_map and not shield._reference_benign_set
