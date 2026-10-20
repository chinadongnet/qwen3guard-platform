"""Idempotently import legacy logs as untrusted historical data.

Run inside the production container after database initialization. No old
credential is activated; old secrets are hashed and marked revoked.
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sqlalchemy import select
from app.enterprise import db as t
from app.enterprise.settings import Settings
from app.enterprise.schemas import PolicyConfig
from app.enterprise.security import digest, redact, encryptor


def main():
    settings = Settings()
    database = t.Database(settings.database_url)
    cipher = encryptor(settings.secret)
    database.initialize()
    root = Path(__file__).resolve().parents[1]
    gateway = json.loads((root / "data/api_gateway_config.json").read_text(encoding="utf-8"))
    logs = json.loads((root / "data/audit_logs.json").read_text(encoding="utf-8"))
    if not isinstance(logs, list) or not isinstance(gateway.get("api_keys"), list):
        raise ValueError("Invalid legacy data shape; migration aborted")
    project_id, policy_id, version_id = "legacy-import-project", "legacy-import-policy", "legacy-import-policy-v1"
    imported, skipped = 0, 0
    with database.engine.begin() as conn:
        if not conn.execute(select(t.projects.c.id).where(t.projects.c.id == project_id)).first():
            conn.execute(t.projects.insert().values(id=project_id, created_at=time.time(), name="历史记录归档"))
            conn.execute(t.policies.insert().values(id=policy_id, created_at=time.time(),
                project_id=project_id, name="历史导入占位策略", published_version=1))
            conn.execute(t.versions.insert().values(id=version_id, created_at=time.time(),
                policy_id=policy_id, version=1, config=PolicyConfig().model_dump(), author_id="migration"))
        known = {k["id"]: k for k in gateway["api_keys"]}
        for entry in logs:
            known.setdefault(entry.get("api_key_id") or "console", {"name": "历史未归属通道"})
        for old_id, key in known.items():
            app_id = "legacy-app-" + digest(old_id)[:24]
            if not conn.execute(select(t.apps.c.id).where(t.apps.c.id == app_id)).first():
                conn.execute(t.apps.insert().values(id=app_id, created_at=time.time(), project_id=project_id,
                    name=str(key.get("name", old_id))[:120], environment="sandbox", policy_id=policy_id, enabled=False))
                if key.get("token"):
                    conn.execute(t.keys.insert().values(id="legacy-key-" + digest(old_id)[:24], created_at=time.time(),
                        application_id=app_id, name="历史凭证（已撤销）", prefix=str(key.get("prefix", ""))[:40],
                        token_hash=digest(key["token"]), expires_at=time.time(), revoked=True, rpm=1, scopes=[]))
        for entry in logs:
            old_audit = entry.get("audit_id")
            if not old_audit:
                raise ValueError("Legacy record missing audit_id")
            event_id = "legacy-" + digest(old_audit)[:32]
            if conn.execute(select(t.events.c.id).where(t.events.c.id == event_id)).first():
                if not conn.execute(select(t.event_payloads.c.id).where(t.event_payloads.c.event_id == event_id)).first():
                    conn.execute(t.event_payloads.insert().values(id=t.ident(), created_at=time.time(), event_id=event_id,
                        expires_at=time.time()+settings.audit_raw_retention_days*86400,
                        content={"encrypted": cipher.encrypt(json.dumps({
                            "prompt":entry.get("prompt",""),"response":entry.get("response",""),
                            "legacy_trace":entry},ensure_ascii=False).encode()).decode()}))
                skipped += 1
                continue
            old_key = entry.get("api_key_id") or "console"
            conn.execute(t.events.insert().values(id=event_id, created_at=time.time(),
                request_id=event_id, project_id=project_id, application_id="legacy-app-" + digest(old_key)[:24],
                source="legacy_unknown", environment="sandbox", endpoint=str(entry.get("endpoint", ""))[:200],
                execution_status="legacy_unknown", decision=str(entry.get("action", "review"))[:20],
                risk_level=str(entry.get("risk_level", "unknown"))[:32],
                latency_ms=float(entry.get("latency_ms") or 0), policy_version_id=None,
                prompt_preview=redact(str(entry.get("prompt", "")))[:300],
                response_preview=redact(str(entry.get("response", "")))[:300],
                result={"legacy_audit_id": old_audit, "legacy_timestamp": entry.get("timestamp"),
                        "provenance": "unverified", "model_revision": "unknown", "policy_version": "unknown"}))
            imported += 1
            conn.execute(t.event_payloads.insert().values(id=t.ident(), created_at=time.time(), event_id=event_id,
                expires_at=time.time()+settings.audit_raw_retention_days*86400,
                content={"encrypted":cipher.encrypt(json.dumps({"prompt":entry.get("prompt",""),
                    "response":entry.get("response",""),"legacy_trace":entry},ensure_ascii=False).encode()).decode()}))
    database.operation("migration", "legacy.import", project_id, project_id, imported=imported, skipped=skipped)
    print(json.dumps({"source_count": len(logs), "imported": imported, "skipped": skipped,
                      "legacy_keys_active": False, "production_metrics_affected": False}))


if __name__ == "__main__":
    main()
