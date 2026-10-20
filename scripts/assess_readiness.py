"""Capture a redacted readiness baseline without importing the application.

Default: HTTP GET checks only. --smoke adds two benign inference requests,
which the running service records in its audit ledger. This is not a load test.
"""
from __future__ import annotations

import argparse
import json
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path


def request_json(base_url: str, path: str, payload: dict | None = None) -> tuple:
    body = None if payload is None else json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        base_url.rstrip("/") + path,
        data=body,
        headers={"Accept": "application/json", "Content-Type": "application/json"},
    )
    started = time.perf_counter()
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            data = json.load(response)
            return response.status, data, round((time.perf_counter() - started) * 1000, 2)
    except urllib.error.HTTPError as exc:
        # Do not include response bodies, which can contain submitted credentials.
        return exc.code, {}, round((time.perf_counter() - started) * 1000, 2)
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        return None, {}, round((time.perf_counter() - started) * 1000, 2)


def assess(base_url: str, smoke: bool) -> dict:
    report = {
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "scope": "anonymous HTTP baseline; no capacity or accuracy certification",
        "checks": [],
    }

    def add(name: str, outcome: str, **evidence: object) -> None:
        report["checks"].append({"name": name, "outcome": outcome, "evidence": evidence})

    status, data, elapsed = request_json(base_url, "/health")
    ready = isinstance(data, dict) and data.get("models_loaded") is True
    add("model_health", "pass" if status == 200 and ready else "unknown",
        http_status=status, models_loaded=ready, elapsed_ms=elapsed)

    status, data, _ = request_json(base_url, "/api/gateway/config")
    exposed = status == 200 and isinstance(data, dict)
    keys = data.get("api_keys", []) if exposed else []
    add("gateway_config_requires_auth", "fail" if exposed else
        ("pass" if status in (401, 403) else "unknown"), http_status=status)
    add("key_list_hides_secrets", "fail" if any(k.get("token") for k in keys) else
        ("unknown" if not exposed else "pass"),
        checked_without_credentials=True, plaintext_token_count=sum(bool(k.get("token")) for k in keys))
    add("data_plane_auth_config", "fail" if exposed and data.get("require_api_key") is False
        else "unknown", require_api_key=data.get("require_api_key") if exposed else None)

    for path in ("/api/config", "/api/audit/logs?limit=1"):
        status, _, _ = request_json(base_url, path)
        add("anonymous_access:" + path, "fail" if status == 200 else
            ("pass" if status in (401, 403) else "unknown"), http_status=status)

    status, data, _ = request_json(base_url, "/openapi.json")
    if status == 200 and isinstance(data, dict):
        paths = data.get("paths", {})
        schemes = data.get("components", {}).get("securitySchemes", {})
        detect = data.get("components", {}).get("schemas", {}).get("GuardDetectRequest", {})
        add("openapi_contract_inventory", "info", path_count=len(paths),
            security_scheme_count=len(schemes),
            detect_accepts_history="history" in detect.get("properties", {}))
    else:
        add("openapi_contract_inventory", "unknown", http_status=status)

    if smoke:
        for path, payload in (
            ("/v1/guard/detect", {"prompt": "企业整改基线检查：请介绍如何整理会议纪要。"}),
            ("/v1/guard/input", {"text": "企业整改基线检查：请介绍办公室节约用电的方法。"}),
        ):
            status, data, elapsed = request_json(base_url, path, payload)
            data = data if isinstance(data, dict) else {}
            add("benign_inference:" + path,
                "pass" if status == 200 and data.get("audit_id") else "unknown",
                http_status=status, elapsed_ms=elapsed,
                allowed=data.get("is_safe", data.get("allowed")),
                audit_id=data.get("audit_id"),
                risk_level=data.get("risk_level"),
                note="Transport smoke only; these two samples do not measure accuracy.")
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://127.0.0.1:8092")
    parser.add_argument("--smoke", action="store_true", help="Make two audited benign inference calls")
    parser.add_argument("--output", type=Path, help="Write only redacted findings to this JSON file")
    args = parser.parse_args()
    report = assess(args.base_url, args.smoke)
    rendered = json.dumps(report, ensure_ascii=False, indent=2)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)


if __name__ == "__main__":
    main()
