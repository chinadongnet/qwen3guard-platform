"""Run and inspect durable real-model acceptance jobs without changing labels.

python scripts/quality_acceptance.py start --run baseline --datasets curated
python scripts/quality_acceptance.py status --run baseline
python scripts/quality_acceptance.py export --run baseline
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs/quality-acceptance"


def fingerprint(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def write(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def code_manifest():
    return {str(p.relative_to(ROOT)).replace("\\", "/"): hashlib.sha256(p.read_bytes()).hexdigest()
            for folder in ("app/enterprise",)
            for p in sorted((ROOT / folder).glob("*.py"))} | {
                name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
                for name in ("app/model_manager.py", "app/security_shield.py", "app/config.py", "app/guard_output.py")}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("start", "status", "export", "cancel"))
    parser.add_argument("--run", required=True)
    parser.add_argument("--datasets", nargs="+", default=["curated", "full"], choices=("curated", "full"))
    parser.add_argument("--target", choices=("auto", "input", "output"), default="auto")
    args = parser.parse_args()
    if not args.run.replace("-", "").replace("_", "").isalnum():
        parser.error("run must contain only letters, numbers, hyphens or underscores")
    OUT.mkdir(parents=True, exist_ok=True)
    path = OUT / f"{args.run}-manifest.json"
    credentials = dict(line.split(": ", 1) for line in (ROOT / "data/bootstrap-credentials.txt")
                       .read_text(encoding="utf-8").splitlines() if ": " in line)
    with httpx.Client(base_url="http://127.0.0.1:8092", timeout=90) as c:
        def call(method, url, **kwargs):
            r = c.request(method, url, **kwargs)
            r.raise_for_status()
            return r.json()
        auth = call("POST", "/api/admin/auth/login", json={
            "username": os.getenv("QG_ADMIN_USER", credentials["Username"]),
            "password": os.getenv("QG_ADMIN_PASSWORD", credentials["Password"])})
        c.headers["X-CSRF-Token"] = auth["csrf_token"]
        if args.command == "start":
            if path.exists():
                raise SystemExit("Run already exists; use status/export or choose another run name")
            project = next(p for p in call("GET", "/api/admin/projects")["items"] if p["name"] == "默认工作空间")
            scope = {"project_id": project["id"]}
            app = next(a for a in call("GET", "/api/admin/applications", params=scope)["items"]
                       if a["name"] == "接入验证（沙盒）" and a["environment"] == "sandbox")
            policy = next(p for p in call("GET", "/api/admin/policies", params=scope)["items"]
                          if p["id"] == app["policy_id"])
            version = next(v for v in policy["versions"] if v["version"] == policy["published_version"])
            manifest = {"started_at": datetime.now(timezone.utc).isoformat(),
                        "project_id": project["id"], "application_id": app["id"],
                        "policy_version": version, "code_sha256": code_manifest(), "jobs": {},
                        "target": args.target,
                        "scope": "Source-labeled regression acceptance; not independent certification"}
            write(path, manifest)
            for dataset in args.datasets:
                cases = call("GET", "/api/admin/workbench/cases",
                             params=scope | {"dataset": dataset, "limit": 5000})["items"]
                write(OUT / f"{args.run}-{dataset}-cases.json", cases)
                def case_target(item):
                    return item.get("evaluation_target", "input") if args.target == "auto" else args.target
                def expected(item):
                    if case_target(item) == "output":
                        return item.get("response_expected_unsafe")
                    return item["expected_unsafe"] if item.get("evaluation_target", "input") == "input" else None
                duplicates = defaultdict(list)
                for item in cases:
                    duplicates[fingerprint([item["prompt"].strip(), item.get("response") or ""])].append(item)
                job = call("POST", "/api/admin/workbench/banks/evaluate", params=scope, json={
                    "application_id": app["id"], "dataset": dataset, "target": args.target, "policy_version": version["version"],
                    "idempotency_key": "quality-" + args.run + "-" + dataset})
                manifest["jobs"][dataset] = {**job, "total": len(cases), "snapshot_sha256": fingerprint(cases),
                    "unsafe": sum(expected(i) is True for i in cases),
                    "benign": sum(expected(i) is False for i in cases),
                    "unlabeled": sum(expected(i) is None for i in cases),
                    "targets": dict(Counter(case_target(i) for i in cases)),
                    "duplicate_excess": sum(len(v)-1 for v in duplicates.values()),
                    "conflicting_labels": [[i["case_key"] for i in v] for v in duplicates.values()
                                           if len({expected(i) for i in v}) > 1]}
                write(path, manifest)
            print(json.dumps(manifest["jobs"], ensure_ascii=False))
        else:
            manifest = json.loads(path.read_text(encoding="utf-8"))
            summaries = {}
            for dataset, job in manifest["jobs"].items():
                if args.command == "cancel":
                    call("POST", f"/api/admin/evaluations/{job['id']}/cancel")
                report = call("GET", f"/api/admin/workbench/reports/{job['id']}")
                errors = [r for r in report["results"] if r["result"].get("execution_status") != "completed"]
                mismatches = [r for r in report["results"] if r["result"].get("passed") is False]
                summaries[dataset] = {k: report[k] for k in ("id", "state", "completed", "total", "metrics")}
                summaries[dataset]["mismatch_by_category"] = dict(Counter(
                    r["result"]["case"]["sub_code"] for r in mismatches))
                summaries[dataset]["error_codes"] = dict(Counter(
                    r["result"].get("error", {}).get("code", "unknown") for r in errors))
                if args.command == "export":
                    write(OUT / f"{args.run}-{dataset}-report.json", report)
                    cases = json.loads((OUT / f"{args.run}-{dataset}-cases.json").read_text(encoding="utf-8"))
                    # Exact snapshots make failed samples inspectable without mutating their labels.
                    by_key = {i["case_key"]: i for i in cases}
                    failures = [{"case": by_key.get(r["result"].get("case", {}).get("case_id")),
                                 "result": r["result"]} for r in mismatches + errors]
                    write(OUT / f"{args.run}-{dataset}-failures.json", failures)
            write(OUT / f"{args.run}-progress.json", {"checked_at": datetime.now(timezone.utc).isoformat(),
                                                    "datasets": summaries})
            print(json.dumps(summaries, ensure_ascii=False))
        call("POST", "/api/admin/auth/logout")


if __name__ == "__main__":
    main()
