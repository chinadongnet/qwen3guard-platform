"""Live GPU acceptance in an explicitly named sandbox application.

Reads local bootstrap credentials without printing them. Creates a policy,
an application, a short-lived key and an evaluation task in the chosen project.
The key is revoked at the end; no production traffic is manufactured.
"""
from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]


def main():
    env = dict(os.environ)
    if (ROOT / ".env").exists():
        env.update(dict(line.split("=", 1) for line in (ROOT / ".env").read_text().splitlines()
                        if "=" in line and not line.startswith("#")))
    results = []
    with httpx.Client(base_url="http://127.0.0.1:8092", timeout=150) as client:
        def call(method, path, **kwargs):
            response = client.request(method, path, **kwargs)
            if not response.is_success:
                raise RuntimeError(f"{method} {path}: {response.status_code} {response.text[:200]}")
            return response.json()
        login = call("POST", "/api/admin/auth/login", json={
            "username": os.getenv("QG_ADMIN_USER", env["BOOTSTRAP_ADMIN_USER"]),
            "password": os.getenv("QG_ADMIN_PASSWORD", env["BOOTSTRAP_ADMIN_PASSWORD"])})
        client.headers["X-CSRF-Token"] = login["csrf_token"]
        projects = call("GET", "/api/admin/projects")["items"]
        project = next((p for p in projects if p["name"] == "默认工作空间"), None)
        if not project:
            project = call("POST", "/api/admin/projects", json={"name": "默认工作空间"})
        scope = {"project_id": project["id"]}
        policy = next((p for p in call("GET", "/api/admin/policies", params=scope)["items"]
                       if p["name"] == "接入验收策略"), None)
        if not policy:
            policy = call("POST", "/api/admin/policies", params=scope, json={
                "name": "接入验收策略", "config": {"custom_block_keywords": ["验收拦截标记"], "stream_window_chars": 16}})
            call("POST", f"/api/admin/policies/{policy['id']}/publish",
                 json={"version": 1, "expected_current": 0})
            policy["published_version"] = 1
        application = next((a for a in call("GET", "/api/admin/applications", params=scope)["items"]
                            if a["name"] == "接入验证（沙盒）" and a["policy_id"] == policy["id"]), None)
        if not application:
            application = call("POST", "/api/admin/applications", params=scope,
                json={"name": "接入验证（沙盒）", "environment": "sandbox", "policy_id": policy["id"]})
        candidate = call("POST", f"/api/admin/policies/{policy['id']}/versions",
                         json={"custom_block_keywords": ["验收拦截标记"], "stream_window_chars": 16})
        publication = {"version": candidate["version"], "expected_current": policy["published_version"]}
        rejected = client.post(f"/api/admin/policies/{policy['id']}/publish", json=publication)
        assert rejected.status_code == 409 and rejected.json()["error"]["code"] == "evaluation_required"
        gate_job = call("POST", "/api/admin/evaluations", params=scope, json={
            "name": "候选策略发布门禁", "application_id": application["id"], "policy_version": candidate["version"],
            "idempotency_key": "gate-" + str(time.time_ns()),
            "items": [{"prompt": "请介绍办公室节约用电的方法。", "expected_unsafe": False},
                      {"prompt": "验收拦截标记", "expected_unsafe": True}]})
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            gate_report = call("GET", f"/api/admin/evaluations/{gate_job['id']}")
            if gate_report["state"] in ("completed", "failed", "interrupted"):
                break
            time.sleep(1)
        assert gate_report["state"] == "completed"
        call("POST", f"/api/admin/policies/{policy['id']}/publish", json=publication)
        results.append({"check": "policy_publication_gate", "unverified_http": rejected.status_code,
                        "published_version": candidate["version"], "evaluation_job_id": gate_job["id"]})
        key = call("POST", f"/api/admin/applications/{application['id']}/keys",
            json={"name": "自动验收临时凭证", "expires_days": 1, "scopes": ["detect", "chat", "audit:read"]})
        headers = {"X-API-Key": key["token"]}
        try:
            for prompt, expected in [
                ("请介绍如何整理会议纪要。", "allow"),
                ("这里包含验收拦截标记，用于验证企业自定义策略。", "block"),
            ]:
                started = time.perf_counter()
                data = call("POST", "/v1/guard/detect", headers=headers, json={"prompt": prompt})
                assert data["decision"] == expected, data["decision"]
                results.append({"check": "live_detection", "decision": data["decision"],
                    "elapsed_ms": round((time.perf_counter() - started) * 1000, 2),
                    "audit_id": data["audit_id"], "request_id": data["request_id"]})
            history = call("GET", "/v1/audit/logs", headers=headers)["items"]
            assert len(history) >= 2 and all(item["application_id"] == application["id"] for item in history)
            results.append({"check": "application_audit_isolation", "passed": True})
            chunks, first_chunk_ms = [], None
            started = time.perf_counter()
            with client.stream("POST", "/v1/chat/completions", headers=headers, json={
                "messages": [{"role": "user", "content": "请分三句介绍杭州的自然风光、城市交通和饮食，每句至少二十字。"}],
                "max_tokens": 128, "temperature": 0, "stream": True}) as response:
                assert response.status_code == 200
                for line in response.iter_lines():
                    if line.startswith("event: error"):
                        raise RuntimeError("live streaming failed")
                    if line.startswith("data: ") and line != "data: [DONE]":
                        payload = json.loads(line[6:])
                        content = payload.get("choices", [{}])[0].get("delta", {}).get("content")
                        if content:
                            if first_chunk_ms is None:
                                first_chunk_ms = round((time.perf_counter() - started) * 1000, 2)
                            chunks.append(content)
            assert len(chunks) >= 2, "Expected multiple audited windows before completion"
            results.append({"check": "live_incremental_chat", "chunks": len(chunks),
                            "first_audited_chunk_ms": first_chunk_ms,
                            "elapsed_ms": round((time.perf_counter() - started) * 1000, 2)})
            job = call("POST", "/api/admin/evaluations", params=scope, json={
                "name": "真实模型回归验收", "application_id": application["id"],
                "idempotency_key": "live-" + str(time.time_ns()),
                "items": [{"prompt": "请介绍办公室节约用电的方法。", "expected_unsafe": False},
                          {"prompt": "验收拦截标记", "expected_unsafe": True}]})
            deadline = time.monotonic() + 60
            while time.monotonic() < deadline:
                report = call("GET", f"/api/admin/evaluations/{job['id']}")
                if report["state"] in ("completed", "failed", "interrupted"):
                    break
                time.sleep(1)
            assert report["state"] == "completed" and report["metrics"]["errors"] == 0
            results.append({"check": "durable_evaluation", "job_id": job["id"],
                            "state": report["state"], "metrics": report["metrics"]})
            overview = call("GET", "/api/admin/overview", params=scope)
            assert overview["total"] == 0
            results.append({"check": "sandbox_excluded_from_production", "production_count": overview["total"]})
        finally:
            call("POST", f"/api/admin/keys/{key['id']}/revoke")
        rejected = client.post("/v1/guard/detect", headers=headers, json={"prompt": "测试失效凭证"})
        assert rejected.status_code == 403
        results.append({"check": "key_revocation", "http_status": rejected.status_code})
        call("POST", "/api/admin/auth/logout")
    output = {"observed_at": datetime.now(timezone.utc).isoformat(), "project_id": project["id"],
              "application_id": application["id"], "checks": results,
              "scope": "Smoke acceptance only; not throughput or independent accuracy certification"}
    target = ROOT / "docs" / "live-acceptance.json"
    target.write_text(json.dumps(output, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(output, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
