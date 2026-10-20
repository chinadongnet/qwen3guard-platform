"""Live feature acceptance using the named sandbox and current local credentials."""
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
import httpx

ROOT = Path(__file__).resolve().parents[1]


def main():
    credentials = dict(line.split(": ", 1) for line in (ROOT/"data/bootstrap-credentials.txt")
                       .read_text(encoding="utf-8").splitlines() if ": " in line)
    records = []
    with httpx.Client(base_url="http://127.0.0.1:8092", timeout=150) as c:
        def call(method, path, **kwargs):
            response = c.request(method, path, **kwargs)
            if not response.is_success:
                raise RuntimeError(f"{method} {path}: HTTP {response.status_code} {response.text[:150]}")
            return response.json()
        for _ in range(30):
            try:
                if c.get("/health/ready").status_code == 200:
                    break
            except httpx.HTTPError:
                pass
            time.sleep(1)
        auth = call("POST", "/api/admin/auth/login", json={
            "username": os.getenv("QG_ADMIN_USER", credentials["Username"]),
            "password": os.getenv("QG_ADMIN_PASSWORD", credentials["Password"])})
        c.headers["X-CSRF-Token"] = auth["csrf_token"]
        projects = call("GET", "/api/admin/projects")["items"]
        project = next(p for p in projects if p["name"] == "默认工作空间")
        scope = {"project_id": project["id"]}
        app = next(a for a in call("GET", "/api/admin/applications", params=scope)["items"]
                   if a["name"] == "接入验证（沙盒）" and a["environment"] == "sandbox")
        base = "/api/admin/workbench"
        for dataset, expected in (("curated", 142), ("full", 1607)):
            seeded = call("POST", base+"/banks/seed", params=scope|{"dataset":dataset})
            bank = call("GET", base+"/cases", params=scope|{"dataset":dataset})
            assert bank["total"] >= expected
            records.append({"check":"bank_import","dataset":dataset,"count":bank["total"],
                            "subcategories":bank["stats"]["subcategories"],**seeded})
        presets = call("GET", base+"/presets", params=scope)
        assert len(presets["items"]) == 4
        cfg = presets["defaults"] | {"custom_block_keywords":["覆盖验收标记"]}
        body = {"application_id":app["id"],"prompt":"这是一条覆盖验收标记，用于测试策略配置。","config":cfg}
        preview = call("POST", base+"/prompt-preview", json=body)
        assert "<BEGIN SAFETY POLICY>" in preview["rendered_prompt"]
        ab = call("POST", base+"/ab-test", json=body)
        assert ab["candidate"]["decision"] == "block"
        records.append({"check":"prompt_and_ab","presets":4,"run_id":ab["run_id"],
                        "baseline":ab["baseline"]["decision"],"candidate":ab["candidate"]["decision"]})
        scan = call("POST", base+"/token-scan", json={
            "application_id":app["id"],"prompt":"请介绍杭州。","response":"杭州以西湖和茶文化闻名。"})
        assert scan["result"]["total_tokens_inspected"] > 0
        records.append({"check":"real_stream_model","run_id":scan["run_id"],"mode":scan["mode"],
                        "tokens":scan["result"]["total_tokens_inspected"],"is_safe":scan["result"]["is_safe"]})
        compare = call("POST", base+"/compare-generation", json={
            "application_id":app["id"],"prompt":"用一句话介绍杭州。"})
        assert compare["raw_response"]
        records.append({"check":"real_generation_comparison","run_id":compare["run_id"],
                        "blocked":compare["blocked"],"output_length":len(compare["raw_response"])})
        key = call("POST", f"/api/admin/applications/{app['id']}/keys", json={
            "name":"功能覆盖验收临时凭证","expires_days":1,"scopes":["detect","audit:read"]})
        try:
            r = c.post("/v1/guard/stream/sse", headers={"X-API-Key":key["token"]},
                       json={"prompt":"介绍杭州","response":"杭州以西湖闻名。"})
            assert r.status_code == 200 and "event: token" in r.text and '"replay":true' in r.text
            records.append({"check":"data_api_token_sse","status":r.status_code,"token_events":r.text.count("event: token")})
            own = call("GET", "/v1/audit/logs", headers={"X-API-Key":key["token"]})["items"]
            original = call("GET", base+f"/detections/{own[0]['id']}/original")
            assert original["response"] == "杭州以西湖闻名。"
            assert call("GET", "/v1/audit/summary", headers={"X-API-Key":key["token"]})["total"] == 1
            records.append({"check":"encrypted_original_and_own_summary","roundtrip":True,"total":1})
        finally:
            call("POST", f"/api/admin/keys/{key['id']}/revoke")
        samples = [{"id":"coverage-safe","prompt":"请介绍办公室节约用电的方法。","expected_unsafe":False,"sub_code":"BENIGN"},
                   {"id":"coverage-rule","prompt":"验收拦截标记","expected_unsafe":True,"sub_code":"CUSTOM"}]
        call("POST", base+"/cases/import", params=scope, json={"dataset":"custom","items":samples})
        cases = call("GET", base+"/cases", params=scope|{"dataset":"custom"})["items"]
        ids = [i["id"] for i in cases if i["case_key"] in ("coverage-safe","coverage-rule")]
        job = call("POST", base+"/banks/evaluate", params=scope, json={
            "dataset":"custom","application_id":app["id"],"case_ids":ids,"idempotency_key":"parity-"+str(time.time_ns())})
        deadline = time.monotonic()+90
        while time.monotonic()<deadline:
            report = call("GET", base+f"/reports/{job['id']}")
            if report["state"] in ("completed","failed","interrupted"):
                break
            time.sleep(1)
        assert report["state"] == "completed" and report["metrics"]["errors"] == 0
        for fmt in ("json","csv","md"):
            assert c.get(base+f"/reports/{job['id']}/export?format={fmt}").status_code==200
        records.append({"check":"bank_job_report_exports","job_id":job["id"],
                        "state":report["state"],"metrics":report["metrics"],
                        "category_groups":len(report["by_subcategory"])})
        production = call("GET", "/api/admin/overview", params=scope)["total"]
        assert production == 0
        records.append({"check":"production_isolation","production_items":production})
        call("POST","/api/admin/auth/logout")
    result = {"checked_at":datetime.now(timezone.utc).isoformat(),"checks":records,
              "scope":"Functional GPU acceptance; sample results are not independent quality certification"}
    (ROOT/"docs/feature-parity-live.json").write_text(json.dumps(result,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    print(json.dumps(result,ensure_ascii=False,indent=2))


if __name__ == "__main__":
    main()
