"""Re-score frozen model assessments after a postprocessor-only repair.

Run inside the server container AFTER source-validated GPU jobs finish. This
creates explicitly named replay jobs and never claims new GPU inference.
"""
from __future__ import annotations

import ast
import asyncio
import hashlib
import json
from pathlib import Path
import sys
import time

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from sqlalchemy import select
from app.config import RuntimeConfig
from app.enterprise import db as t
from app.enterprise.security import encryptor, redact
from app.enterprise.settings import Settings
from app.enterprise.service import DetectionService
from app.model_manager import ModelManager
from scripts.quality_acceptance import code_manifest

DIR=ROOT/"docs/quality-acceptance"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


async def main():
    source=json.loads((DIR/"source-validated-manifest.json").read_text(encoding="utf-8"))
    snapshot=json.loads((DIR/"postrule-source.json").read_text(encoding="utf-8"))
    shield_source=(ROOT/"app/security_shield.py").read_text(encoding="utf-8")
    tree=ast.parse(shield_source)
    node=next(n for n in ast.walk(tree) if isinstance(n,ast.FunctionDef) and n.name=="deobfuscate_and_unwrap")
    assert hashlib.sha256(ast.get_source_segment(shield_source,node).encode()).hexdigest()==snapshot["deobfuscation_source_sha256"]
    assert sha(ROOT/"app/model_manager.py")==snapshot["model_manager_sha256"]
    assert sha(ROOT/"app/guard_output.py")==snapshot["guard_output_sha256"]
    current_code=code_manifest()
    assert {p for p,h in source["code_sha256"].items() if current_code[p]!=h}=={"app/security_shield.py"}
    settings=Settings();db=t.Database(settings.database_url);cipher=encryptor(settings.secret)
    previous_path=DIR/"postrules-manifest.json"
    if previous_path.exists():
        previous=json.loads(previous_path.read_text(encoding="utf-8"))
        if previous["code_sha256"]!=current_code:
            suffix=previous["code_sha256"]["app/security_shield.py"][:12]
            for artifact in ("manifest","curated-report","full-report","curated-changes","full-changes"):
                existing=DIR/f"postrules-{artifact}.json"
                if existing.exists():
                    (DIR/f"postrules-{suffix}-{artifact}.json").write_bytes(existing.read_bytes())
            for entry in previous["jobs"].values():
                row=db.one(select(t.jobs).where(t.jobs.c.id==entry["id"]))
                if not row["name"].startswith("历史复判"):
                    with db.engine.begin() as conn:
                        conn.execute(t.jobs.update().where(t.jobs.c.id==row["id"]).values(
                            name="历史复判（旧规则）· "+row["name"]))
                    db.operation("quality-acceptance","evaluation.superseded",row["id"],row["project_id"])
    service=DetectionService(db,None,None,cipher,settings.audit_raw_retention_days)
    manager=ModelManager()  # No weights loaded; _gen_result is postprocessing only.
    manifest={**source,"jobs":{},"code_sha256":current_code,"started_at":time.time(),
              "source_run":"source-validated","inference_provenance":"reused immutable GPU model assessments; no new inference",
              "model_path_unchanged_verified":True}
    for dataset,entry in source["jobs"].items():
        original=db.one(select(t.jobs).where(t.jobs.c.id==entry["id"]))
        assert original["state"]=="completed" and original["completed"]==original["total"]
        rows=db.all(select(t.job_items).where(t.job_items.c.job_id==original["id"]).order_by(t.job_items.c.position))
        cases=json.loads(cipher.decrypt(original["items"]["encrypted"].encode()))
        app=db.one(select(t.apps).where(t.apps.c.id==original["application_id"]))
        version=db.one(select(t.versions).where(t.versions.c.id==original["policy_version_id"]))
        cfg=RuntimeConfig(**{k:v for k,v in version["config"].items() if k in RuntimeConfig.model_fields})
        cfg.enable_pii_shield=False
        for row in rows:
            assert row["result"]["execution_status"]=="completed"
            assert row["result"]["model_assessment"]["safety"] in ("Safe","Unsafe","Controversial")
        identity="quality-replay-"+original["id"]+"-"+current_code["app/security_shield.py"][:16]
        job=db.one(select(t.jobs).where(t.jobs.c.project_id==original["project_id"],t.jobs.c.idempotency_key==identity))
        if not job:
            job=db.insert(t.jobs,project_id=original["project_id"],application_id=app["id"],endpoint_id=None,
                policy_version_id=version["id"],name="规则修复复判（复用模型结果）· "+original["name"],
                state="running",dataset_hash=original["dataset_hash"],items=original["items"],
                completed=0,total=original["total"],cancel_requested=False,idempotency_key=identity)
        changes=[]
        for position in range(job["completed"],len(rows)):
            row,item=rows[position]["result"],cases[position]
            assessment=row["model_assessment"]
            raw="Safety: "+assessment["safety"]+"\nCategories: "+(", ".join(assessment["categories"]) or "None")
            if assessment.get("refusal"):raw+="\nRefusal: "+assessment["refusal"]
            prompt,response=item["prompt"],item.get("response")
            mp,mr=prompt,response
            if version["config"].get("pii_action") in ("mask","audit"):
                mp,mr=redact(mp),redact(mr) if mr is not None else None
            started=time.perf_counter()
            prepared=manager._gen_result(mp,mr,cfg,raw,0)
            result=await service.detect(app,None,prompt,response,t.ident(),source="evaluation",
                endpoint="quality_rule_replay",version=version,_model_result=prepared,
                _inference_ms=(time.perf_counter()-started)*1000)
            result.update(expected_unsafe=row["expected_unsafe"],case=row["case"],
                response_preview=row.get("response_preview",""),
                inference_provenance={"kind":"reused_model_assessment","source_job_id":original["id"],
                    "source_item_id":rows[position]["id"],"source_audit_id":row["audit_id"]})
            result["passed"]=(result["decision"]=="block" if result["expected_unsafe"]
                              else result["decision"] in ("allow","mask"))
            if result["decision"]!=row["decision"]:
                changes.append({"case_id":row["case"]["case_id"],"before":row["decision"],
                                "after":result["decision"],"expected_unsafe":row["expected_unsafe"],
                                "model_assessment_unchanged":result["model_assessment"]==assessment})
            with db.engine.begin() as conn:
                # Make the reused inference explicit in the audit as well.
                audited=db.one(select(t.events).where(t.events.c.id==result["audit_id"]))["result"]
                conn.execute(t.events.update().where(t.events.c.id==result["audit_id"]).values(
                    result={**audited,"inference_provenance":result["inference_provenance"]}))
                conn.execute(t.job_items.insert().values(id=t.ident(),created_at=time.time(),job_id=job["id"],
                    position=position,result=result))
                conn.execute(t.jobs.update().where(t.jobs.c.id==job["id"]).values(completed=position+1))
        with db.engine.begin() as conn:
            conn.execute(t.jobs.update().where(t.jobs.c.id==job["id"]).values(state="completed"))
        db.operation("quality-acceptance","evaluation.rule_replay",job["id"],original["project_id"],
            source_job_id=original["id"],changed=len(changes),new_gpu_inference=False)
        manifest["jobs"][dataset]={**entry,"id":job["id"],"state":"completed","source_job_id":original["id"]}
        (DIR/f"postrules-{dataset}-cases.json").write_bytes((DIR/f"source-validated-{dataset}-cases.json").read_bytes())
        if changes:
            (DIR/f"postrules-{dataset}-changes.json").write_text(json.dumps(changes,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
        print(json.dumps({"dataset":dataset,"job_id":job["id"],"changed":len(changes),"new_gpu_inference":False}),flush=True)
    (DIR/"postrules-manifest.json").write_text(json.dumps(manifest,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")


if __name__=="__main__":
    asyncio.run(main())
