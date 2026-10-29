"""Pytest integration wrapper for the live API Test Environment & GPU Model Benchmark."""
from __future__ import annotations

import os
import pytest
import requests

from scripts.run_api_test_env import APITestRunner, BASE_URL


def _is_live_server_ready() -> bool:
    try:
        r = requests.get(f"{BASE_URL}/health/ready", timeout=2)
        return r.status_code == 200 and r.json().get("models_loaded") is True
    except Exception:
        return False


@pytest.mark.skipif(not _is_live_server_ready(), reason="Live GPU server at http://127.0.0.1:8092 is not running or models not yet loaded")
def test_live_api_end_to_end_and_gpu_benchmarks():
    runner = APITestRunner(BASE_URL)
    runner.wait_until_ready(timeout_s=30)
    runner.run_suite_auth_and_keys()
    runner.run_suite_policy_via_apikey()
    runner.run_suite_all_detection_apis()
    eff = runner.run_suite_effectiveness_metrics()
    perf = runner.run_suite_performance_metrics()

    assert eff["guard_gen"]["accuracy_pct"] >= 85.0
    assert eff["guard_gen"]["recall_pct"] >= 85.0
    assert eff["guard_stream"]["accuracy_pct"] >= 80.0
    assert perf["guard_gen_single"]["model_inference_latency_ms"]["p95_ms"] < 2000.0
    assert perf["guard_stream"]["avg_tokens_per_sec"] > 50.0
