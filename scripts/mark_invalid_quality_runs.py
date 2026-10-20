"""Mark only the diagnosed, explicitly named runs; keep their audit evidence."""
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from sqlalchemy import select
from app.enterprise import db as t
from app.enterprise.settings import Settings


def main():
    db=t.Database(Settings().database_url)
    reason="Legacy suite-derived labels were applied to the wrong moderation target; superseded by source-validated acceptance."
    ids=[]
    for name in ("baseline","final"):
        path=ROOT/f"docs/quality-acceptance/{name}-manifest.json"
        manifest=json.loads(path.read_text(encoding="utf-8"))
        for job in manifest["jobs"].values():
            row=db.one(select(t.jobs).where(t.jobs.c.id==job["id"]))
            if row["state"] in ("queued","running"):
                raise RuntimeError("Cancel the diagnosed run before marking it invalid")
            if not row["name"].startswith("诊断作废"):
                with db.engine.begin() as conn:
                    conn.execute(t.jobs.update().where(t.jobs.c.id==row["id"]).values(
                        name="诊断作废（标签对象错误）· "+row["name"]))
                db.operation("quality-acceptance","evaluation.invalidate",row["id"],row["project_id"],reason=reason)
            ids.append(row["id"])
        manifest.update(valid_for_quality=False,invalidation_reason=reason)
        path.write_text(json.dumps(manifest,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    print(json.dumps({"marked_invalid":ids}))


if __name__=="__main__":
    main()
