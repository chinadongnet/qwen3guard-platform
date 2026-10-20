"""Re-run every changed postprocessor case on the GPU after deployment."""
import json
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx

ROOT=Path(__file__).resolve().parents[1]
DIR=ROOT/"docs/quality-acceptance"


def main():
    changes=json.loads((DIR/"postrules-full-changes.json").read_text(encoding="utf-8"))
    cases={i["case_key"]:i for i in json.loads((DIR/"postrules-full-cases.json").read_text(encoding="utf-8"))}
    cred=dict(line.split(": ",1) for line in (ROOT/"data/bootstrap-credentials.txt")
              .read_text(encoding="utf-8").splitlines() if ": " in line)
    records=[]
    with httpx.Client(base_url="http://127.0.0.1:8092",timeout=120) as c:
        def call(method,path,**kw):
            r=c.request(method,path,**kw);r.raise_for_status();return r.json()
        auth=call("POST","/api/admin/auth/login",json={"username":cred["Username"],"password":cred["Password"]})
        c.headers["X-CSRF-Token"]=auth["csrf_token"]
        project=next(p for p in call("GET","/api/admin/projects")["items"] if p["name"]=="默认工作空间")
        app=next(a for a in call("GET","/api/admin/applications",params={"project_id":project["id"]})["items"]
                 if a["name"]=="接入验证（沙盒）")
        for change in changes:
            case=cases[change["case_id"]]
            result=call("POST",f"/api/admin/applications/{app['id']}/test",json={
                "prompt":case["prompt"],"response":case["response"] if case["evaluation_target"]=="output" else None})
            records.append({"case_id":case["case_key"],"before":change["before"],"replayed":change["after"],
                            "live":result["decision"],"audit_id":result["audit_id"],
                            "model_assessment":result["model_assessment"],"passed":result["decision"]==change["after"]})
            print(json.dumps(records[-1],ensure_ascii=False),flush=True)
            time.sleep(2.1)  # Stay within the console's existing 30/minute limit.
        production=call("GET","/api/admin/overview",params={"project_id":project["id"]})["total"]
        call("POST","/api/admin/auth/logout")
    evidence={"checked_at":datetime.now(timezone.utc).isoformat(),"checks":records,
              "production_items":production,"all_passed":all(r["passed"] for r in records)}
    (DIR/"postrule-live-verification.json").write_text(json.dumps(evidence,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    assert evidence["all_passed"] and production==0


if __name__=="__main__":
    main()
