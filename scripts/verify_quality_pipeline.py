"""Live deterministic single/batch parity; no model weights or labels modified."""
import json
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx

ROOT=Path(__file__).resolve().parents[1]


def main():
    cred=dict(line.split(": ",1) for line in (ROOT/"data/bootstrap-credentials.txt")
              .read_text(encoding="utf-8").splitlines() if ": " in line)
    cases=json.loads((ROOT/"data/tc260_cases.json").read_text(encoding="utf-8"))["cases"]
    samples=[{"prompt":c["prompt"],"expected_unsafe":c["expected_unsafe"],"case_id":c["id"]}
             for c in cases[:4]+[i for i in cases if not i["expected_unsafe"]][:4]]
    with httpx.Client(base_url="http://127.0.0.1:8092",timeout=90) as c:
        def call(method,path,**kw):
            r=c.request(method,path,**kw);r.raise_for_status();return r.json()
        auth=call("POST","/api/admin/auth/login",json={"username":cred["Username"],"password":cred["Password"]})
        c.headers["X-CSRF-Token"]=auth["csrf_token"]
        project=next(p for p in call("GET","/api/admin/projects")["items"] if p["name"]=="默认工作空间")
        scope={"project_id":project["id"]}
        app=next(a for a in call("GET","/api/admin/applications",params=scope)["items"]
                 if a["name"]=="接入验证（沙盒）")
        singles=[]
        for sample in samples:
            singles.append(call("POST",f"/api/admin/applications/{app['id']}/test",json={"prompt":sample["prompt"]}))
        job=call("POST","/api/admin/evaluations",params=scope,json={
            "name":"批量推理一致性验收","application_id":app["id"],"items":samples,
            "idempotency_key":"quality-batch-parity-"+str(time.time_ns())})
        for _ in range(180):
            report=call("GET",f"/api/admin/evaluations/{job['id']}")
            if report["state"] in ("completed","failed","interrupted"):break
            time.sleep(1)
        assert report["state"]=="completed" and len(report["results"])==len(samples)
        checks=[]
        for index,row in enumerate(report["results"]):
            single,batch=singles[index],row["result"]
            checks.append({"case_id":samples[index]["case_id"],"single":single["decision"],
                           "batch":batch.get("decision"),"model_assessment_equal":single["model_assessment"]==batch.get("model_assessment"),
                           "decision_equal":single["decision"]==batch.get("decision")})
        result={"checked_at":datetime.now(timezone.utc).isoformat(),"job_id":job["id"],
                "checks":checks,"errors":report["metrics"]["errors"],
                "all_equal":all(i["decision_equal"] and i["model_assessment_equal"] for i in checks),
                "note":"Eight deterministic samples; this is batch-path parity, not a quality score"}
        out=ROOT/"docs/quality-acceptance/batch-parity.json"
        out.write_text(json.dumps(result,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
        call("POST","/api/admin/auth/logout")
        print(json.dumps(result,ensure_ascii=False),flush=True)
        assert result["all_equal"] and result["errors"]==0


if __name__=="__main__":
    main()
