import json
from sqlalchemy import select
from test_enterprise import client, login, project_setup
from app.enterprise import db as t

BASE = "/api/admin/workbench"


def setup(client):
    login(client)
    project, policy, app, key = project_setup(client)
    return project, policy, app, key, {"project_id": project["id"]}


def test_original_banks_import_idempotence_filters_and_isolation(client):
    project, _, _, _, scope = setup(client)
    assert client.post(BASE+"/banks/seed", params=scope).json()["inserted"] == 142
    assert client.post(BASE+"/banks/seed", params=scope).json() == {"inserted": 0, "skipped": 142}
    assert client.post(BASE+"/banks/seed", params=scope|{"dataset":"full"}).json()["inserted"] == 1607
    rows = client.get(BASE+"/cases", params=scope|{"dataset":"full","limit":30}).json()
    assert rows["total"] == 1607 and len(rows["items"]) == 30 and rows["stats"]["subcategories"] == 31
    normal = client.get(BASE+"/cases", params=scope|{"expected_unsafe":False}).json()
    assert all(i["label_expected_unsafe"] is False for i in normal["items"])
    other = client.post("/api/admin/projects", json={"name":"other"}).json()
    assert client.get(BASE+"/cases", params={"project_id":other["id"]}).json()["total"] == 0
    stored = client.app.state.db.one(select(t.cases))
    assert "encrypted" in stored["content"] and "prompt" not in stored["content"]


def test_case_revision_export_archive_restore_and_snapshot(client):
    _, _, app, _, scope = setup(client)
    sample = {"id":"one", "prompt":"hello", "expected_unsafe":False, "sub_code":"BENIGN"}
    created = client.post(BASE+"/cases/import",params=scope,json={"dataset":"custom","items":[sample]})
    assert created.status_code==200
    item = client.get(BASE+"/cases",params=scope|{"dataset":"custom"}).json()["items"][0]
    job = client.post(BASE+"/banks/evaluate",params=scope,json={
        "dataset":"custom","application_id":app["id"],"idempotency_key":"bank-snapshot"}).json()
    changed = {**sample,"prompt":"BLOCK","expected_unsafe":True}
    assert client.put(BASE+f"/cases/{item['id']}",json={"expected_revision":1,"content":changed}).status_code==200
    assert client.put(BASE+f"/cases/{item['id']}",json={"expected_revision":1,"content":changed}).status_code==409
    history = client.get(BASE+f"/cases/{item['id']}/history").json()["items"]
    assert [r["revision"] for r in history]==[2,1]
    queued = client.app.state.db.one(select(t.jobs).where(t.jobs.c.id==job["id"]))
    client.portal.call(client.app.state.runner.run_job,queued)
    report = client.get(BASE+f"/reports/{job['id']}").json()
    assert report["metrics"]["tn"]==1 and report["results"][0]["result"]["case"]["case_revision"]==1
    assert client.get(BASE+f"/reports/{job['id']}/export?format=md").text.startswith("# 审核评测报告")
    assert client.get(BASE+f"/reports/{job['id']}/export?format=csv").status_code==200
    assert client.put(BASE+f"/cases/{item['id']}/archived",json={"enabled":True}).status_code==200
    assert client.get(BASE+"/cases",params=scope|{"dataset":"custom"}).json()["total"]==0
    assert client.put(BASE+f"/cases/{item['id']}/archived",json={"enabled":False}).status_code==200
    assert client.get(BASE+"/cases/export",params=scope|{"dataset":"custom"}).json()["total"]==1


def install_lab_models(client):
    def scan(prompt,response,config):
        text=response or prompt
        unsafe="BLOCK" in text
        return {"is_safe":not unsafe,"overall_risk_level":"Unsafe" if unsafe else "Safe",
            "total_tokens_inspected":len(text),"circuit_breaker_triggered":unsafe,"cutoff_token_index":0 if unsafe else None,
            "safe_prefix_text":"" if unsafe else text,
            "token_stream":[{"index":n,"token":c,"risk_level":"Unsafe" if unsafe else "Safe",
                             "action":"cutoff" if unsafe else "pass"} for n,c in enumerate(text)]}
    client.app.state.models.scan=scan
    client.app.state.models.raw_generation=lambda prompt,cfg: {"final_response":"hello"}


def test_presets_prompt_ab_token_generation_and_production_exclusion(client):
    _, _, app, _, scope=setup(client)
    install_lab_models(client)
    presets=client.get(BASE+"/presets",params=scope).json()
    assert len(presets["items"])==4
    cfg=presets["defaults"]|{"guard_gen_custom_rules":"CUSTOM PREVIEW MARKER"}
    payload={"application_id":app["id"],"prompt":"hello","config":cfg}
    assert "CUSTOM PREVIEW MARKER" in client.post(BASE+"/prompt-preview",json=payload).json()["rendered_prompt"]
    ab=client.post(BASE+"/ab-test",json=payload).json()
    assert ab["baseline"]["decision"]=="allow" and ab["candidate"]["decision"]=="allow"
    scan=client.post(BASE+"/token-scan",json=payload).json()
    assert scan["mode"]=="offline_token_diagnostic" and scan["result"]["total_tokens_inspected"]==5
    compare=client.post(BASE+"/compare-generation",json={"application_id":app["id"],"prompt":"hello"}).json()
    assert compare["raw_response"]=="hello" and not compare["blocked"]
    assert client.get("/api/admin/overview",params=scope).json()["total"]==0
    assert len(client.get(BASE+"/runs",params=scope).json()["items"])==3
    assert client.get(BASE+f"/runs/{ab['run_id']}").status_code==200


def test_data_token_contract_and_error_fail_closed(client):
    _, _, _, key, scope=setup(client);install_lab_models(client)
    headers={"X-API-Key":key["token"]}
    result=client.post("/v1/guard/stream",headers=headers,json={"response":"hello"}).json()
    assert result["mode"]=="offline_token_diagnostic" and len(result["token_stream"])==5
    stream=client.post("/v1/guard/stream/sse",headers=headers,json={"response":"hello"}).text
    assert "event: token" in stream and '"replay":true' in stream
    result=client.post("/v1/guard/detect",headers=headers,json={"prompt":"hello","include_stream_tokens":True}).json()
    assert "stream_diagnostic" in result
    def broken(*args): raise RuntimeError("private details")
    client.app.state.models.scan=broken
    response=client.post("/v1/guard/stream",headers=headers,json={"response":"hello"})
    assert response.status_code==503 and "private details" not in response.text
    events=client.get("/api/admin/detections",params=scope).json()["items"]
    assert events[0]["execution_status"]=="error" and events[0]["risk_level"]=="indeterminate"
    assert all("token_stream" not in json.dumps(e["result"]) for e in events)


def test_review_promote_export_archive_keeps_metrics_and_original(client):
    _, _, app, key, scope=setup(client)
    result=client.post("/v1/guard/detect",headers={"X-API-Key":key["token"]},json={"prompt":"= harmless sample"}).json()
    event=result["audit_id"]
    review=client.post(BASE+f"/detections/{event}/review",json={"state":"resolved","note":"reviewed"})
    assert review.status_code==200
    assert client.post(BASE+f"/detections/{event}/promote",json={
        "prompt":"edited sample","expected_unsafe":False}).json()["inserted"]==1
    exported=client.get(BASE+"/audit/export",params=scope|{"format":"csv"})
    assert exported.status_code==200 and "'= harmless sample" in exported.text
    assert client.post(BASE+"/audit/archive",params=scope,json={"ids":[event],"archived":True}).status_code==200
    assert client.get("/api/admin/detections",params=scope).json()["items"]==[]
    assert client.get("/api/admin/overview",params=scope).json()["total"]==1
    assert len(client.get("/api/admin/detections",params=scope|{"archived":True}).json()["items"])==1
    assert client.post(BASE+"/audit/archive",params=scope,json={"ids":[event],"archived":False}).status_code==200
    assert client.get(BASE+"/audit/summary",params=scope).json()["items"][0]["total"]==1
    assert client.get("/api/audit/summary",headers={"X-API-Key":key["token"]}).json()["total"]==1


def test_workbench_rbac_and_no_cross_project_samples(client):
    project, _, app, _, scope=setup(client)
    client.post(BASE+"/cases/import",params=scope,json={"items":[{"prompt":"private","expected_unsafe":False}]})
    row=client.get(BASE+"/cases",params=scope|{"dataset":"custom"}).json()["items"][0]
    member=client.post("/api/admin/users",json={"username":"outsider","password":"member-password-123"}).json()
    other=client.post("/api/admin/projects",json={"name":"other"}).json()
    client.put(f"/api/admin/projects/{other['id']}/members",json={"user_id":member["id"],"role":"operator"})
    login(client,"outsider","member-password-123")
    assert client.get(BASE+"/cases",params=scope).status_code==403
    assert client.get(BASE+f"/cases/{row['id']}/history").status_code==403
    assert client.post(BASE+"/compare-generation",json={"application_id":app["id"],"prompt":"hello"}).status_code==403
    assert client.post(BASE+"/banks/evaluate",params={"project_id":other["id"]},json={
        "application_id":app["id"],"dataset":"custom","case_ids":[row["id"]],"idempotency_key":"cross-project"}).status_code==404


def test_dynamic_batch_does_not_invent_accuracy_from_input_labels(client):
    _, _, app, _, scope=setup(client);install_lab_models(client)
    client.post(BASE+"/cases/import",params=scope,json={"items":[{"prompt":"hello","expected_unsafe":False}]})
    result=client.post(BASE+"/banks/evaluate",params=scope,json={
        "application_id":app["id"],"dataset":"custom","mode":"generation_compare","idempotency_key":"dynamic-batch"})
    assert result.status_code==202
    job=client.app.state.db.one(select(t.jobs).where(t.jobs.c.id==result.json()["id"]))
    client.portal.call(client.app.state.runner.run_job,job)
    report=client.get(BASE+f"/reports/{job['id']}").json()
    assert report["state"]=="completed" and report["metrics"]["accuracy"] is None
    assert report["results"][0]["result"]["comparison"]["guarded_response"]=="hello"


def test_gateway_pause_resume_and_policy_assignment_are_scoped(client):
    _, _, app, key, scope=setup(client)
    path=f"/api/admin/keys/{key['id']}/settings"
    headers={"X-API-Key":key["token"]}
    assert client.put(path,json={"rpm":20,"enabled":False}).status_code==200
    assert client.post("/v1/guard/detect",headers=headers,json={"prompt":"hello"}).status_code==403
    assert client.put(path,json={"rpm":20,"enabled":True}).status_code==200
    assert client.post("/v1/guard/detect",headers=headers,json={"prompt":"hello"}).status_code==200
    _, other_policy, _, _=project_setup(client,"unrelated")
    assert client.put(f"/api/admin/applications/{app['id']}/settings",json={
        "name":"changed","environment":"sandbox","policy_id":other_policy["id"]}).status_code==422
    assert client.post(f"/api/admin/keys/{key['id']}/revoke").status_code==200
    assert client.put(path,json={"rpm":20,"enabled":True}).status_code==409


def test_original_audit_encrypted_expiring_and_access_logged(client):
    import time
    _, _, app, key, scope=setup(client)
    text="联系 test@example.com"
    result=client.post("/v1/guard/detect",headers={"X-API-Key":key["token"]},json={"prompt":text}).json()
    event=result["audit_id"]
    stored=client.app.state.db.one(select(t.event_payloads).where(t.event_payloads.c.event_id==event))
    assert text not in json.dumps(stored) and "encrypted" in stored["content"]
    assert client.get(BASE+f"/detections/{event}/original").json()["prompt"]==text
    assert client.app.state.db.one(select(t.operations).where(t.operations.c.action=="audit.original_read"))
    assert "test@example.com" not in client.get("/v1/audit/logs",headers={"X-API-Key":key["token"]}).text
    with client.app.state.db.engine.begin() as conn:
        conn.execute(t.event_payloads.update().values(expires_at=time.time()-1))
    assert client.get(BASE+f"/detections/{event}/original").status_code==410
    assert client.get("/api/admin/detections/"+event).status_code==200
    member=client.post("/api/admin/users",json={"username":"reader","password":"member-password-123"}).json()
    client.put(f"/api/admin/projects/{scope['project_id']}/members",json={"user_id":member["id"],"role":"developer"})
    login(client,"reader","member-password-123")
    assert client.get(BASE+f"/detections/{event}/original").status_code==403
