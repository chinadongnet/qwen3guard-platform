"""Enterprise Platform Store for Question Bank CRUD, API Gateway Config, Presets, and Report History."""
from __future__ import annotations

import json
import secrets
import time
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional

from app.config import (
    DATA_DIR,
    DEFAULT_CUSTOM_GUARD_RULES,
    DEFAULT_LLM_SYSTEM_PROMPT,
    DEFAULT_SAFETY_POLICY_INPUT,
    DEFAULT_SAFETY_POLICY_OUTPUT,
    DEFAULT_UNSAFE_CATEGORIES,
)
from scripts.build_tc260_dataset import TC260_TAXONOMY

GATEWAY_CONFIG_PATH = DATA_DIR / "api_gateway_config.json"
REPORTS_HISTORY_PATH = DATA_DIR / "reports_history.json"
CURATED_CASES_PATH = DATA_DIR / "tc260_cases.json"
FULL_CASES_PATH = DATA_DIR / "tc260_full_1600.json"

POLICY_PRESETS: Dict[str, Dict[str, Any]] = {
    "tc260_standard": {
        "id": "tc260_standard",
        "name": "TC260-003 国标合规标准模式 (推荐)",
        "badge": "国家标准",
        "description": "严格遵循 GB/T 45654-2025 全部 5大类 31子类要求，兼顾 100% 应拒答拦截与 100% 非拒答防误杀。",
        "config": {
            "guard_gen_safety_policy_input": DEFAULT_SAFETY_POLICY_INPUT,
            "guard_gen_safety_policy_output": DEFAULT_SAFETY_POLICY_OUTPUT,
            "guard_gen_unsafe_categories": DEFAULT_UNSAFE_CATEGORIES,
            "guard_gen_custom_rules": DEFAULT_CUSTOM_GUARD_RULES,
            "controversial_as_unsafe": True,
            "guard_gen_max_new_tokens": 24,
            "guard_gen_temperature": 0.0,
            "stream_unsafe_threshold": 0.50,
            "stream_controversial_as_unsafe": True,
            "stream_circuit_breaker": True,
            "stream_window_check_interval": 3,
            "enable_deobfuscation": True,
            "enable_jailbreak_shield": True,
            "enable_pii_shield": True,
            "enable_tc260_semantic_shield": True,
            "risk_threshold": 0.50,
            "category_weights": {
                "A.1": 1.0,
                "A.2": 0.9,
                "A.3": 0.85,
                "A.4": 0.9,
                "A.5": 0.85,
                "JAILBREAK": 0.95,
                "PII": 0.85,
            },
            "llm_system_prompt": DEFAULT_LLM_SYSTEM_PROMPT,
            "llm_temperature": 0.6,
            "llm_max_new_tokens": 160,
        },
    },
    "finance_gov_strict": {
        "id": "finance_gov_strict",
        "name": "政务/金融零容忍严苛防护模式",
        "badge": "严苛高敏",
        "description": "面向政务、银行、证券与关键基础设施场景，下调风险拦截阈值至 0.35，强化商业秘密、金融诱导与PII保护。",
        "config": {
            "guard_gen_safety_policy_input": DEFAULT_SAFETY_POLICY_INPUT,
            "guard_gen_safety_policy_output": DEFAULT_SAFETY_POLICY_OUTPUT,
            "guard_gen_unsafe_categories": DEFAULT_UNSAFE_CATEGORIES,
            "guard_gen_custom_rules": (
                DEFAULT_CUSTOM_GUARD_RULES
                + "\n- Zero-tolerance for financial manipulation, insider trading, PII leakage, or government impersonation."
            ),
            "controversial_as_unsafe": True,
            "guard_gen_max_new_tokens": 24,
            "guard_gen_temperature": 0.0,
            "stream_unsafe_threshold": 0.38,
            "stream_controversial_as_unsafe": True,
            "stream_circuit_breaker": True,
            "stream_window_check_interval": 2,
            "enable_deobfuscation": True,
            "enable_jailbreak_shield": True,
            "enable_pii_shield": True,
            "enable_tc260_semantic_shield": True,
            "risk_threshold": 0.35,
            "category_weights": {
                "A.1": 1.0,
                "A.2": 0.95,
                "A.3": 1.0,
                "A.4": 1.0,
                "A.5": 0.95,
                "JAILBREAK": 1.0,
                "PII": 1.0,
            },
            "llm_system_prompt": DEFAULT_LLM_SYSTEM_PROMPT + " 严禁提供任何投资收益承诺、具体个股推荐或医疗处方剂量。",
            "llm_temperature": 0.3,
            "llm_max_new_tokens": 160,
        },
    },
    "education_anti_fp": {
        "id": "education_anti_fp",
        "name": "教育/学术/安全研发防误杀宽松模式",
        "badge": "防误杀优先",
        "description": "面向高校科研、法学案例研讨与网络安全攻防教学场景，争议内容(Controversial)默认放行并标记审计。",
        "config": {
            "guard_gen_safety_policy_input": DEFAULT_SAFETY_POLICY_INPUT,
            "guard_gen_safety_policy_output": DEFAULT_SAFETY_POLICY_OUTPUT,
            "guard_gen_unsafe_categories": DEFAULT_UNSAFE_CATEGORIES,
            "guard_gen_custom_rules": (
                "Academic & Defensive Research Policy:\n"
                "- Allow historical, legal, medical textbook, and defensive cybersecurity discussions.\n"
                "- Block only direct actionable harm (weapons synthesis, active exploitation, CSAM, subversion)."
            ),
            "controversial_as_unsafe": False,
            "guard_gen_max_new_tokens": 24,
            "guard_gen_temperature": 0.0,
            "stream_unsafe_threshold": 0.72,
            "stream_controversial_as_unsafe": False,
            "stream_circuit_breaker": True,
            "stream_window_check_interval": 4,
            "enable_deobfuscation": True,
            "enable_jailbreak_shield": True,
            "enable_pii_shield": True,
            "enable_tc260_semantic_shield": True,
            "risk_threshold": 0.68,
            "category_weights": {
                "A.1": 1.0,
                "A.2": 0.75,
                "A.3": 0.70,
                "A.4": 0.80,
                "A.5": 0.70,
                "JAILBREAK": 0.85,
                "PII": 0.85,
            },
            "llm_system_prompt": DEFAULT_LLM_SYSTEM_PROMPT,
            "llm_temperature": 0.7,
            "llm_max_new_tokens": 220,
        },
    },
    "stream_low_latency": {
        "id": "stream_low_latency",
        "name": "高并发流式极速熔断模式",
        "badge": "极速低延迟",
        "description": "面向高并发实时语音/数字人流式对话场景，缩短生成分类 Token 上限并优化流式滑动窗口步长。",
        "config": {
            "guard_gen_safety_policy_input": DEFAULT_SAFETY_POLICY_INPUT,
            "guard_gen_safety_policy_output": DEFAULT_SAFETY_POLICY_OUTPUT,
            "guard_gen_unsafe_categories": DEFAULT_UNSAFE_CATEGORIES,
            "guard_gen_custom_rules": DEFAULT_CUSTOM_GUARD_RULES,
            "controversial_as_unsafe": True,
            "guard_gen_max_new_tokens": 16,
            "guard_gen_temperature": 0.0,
            "stream_unsafe_threshold": 0.55,
            "stream_controversial_as_unsafe": True,
            "stream_circuit_breaker": True,
            "stream_window_check_interval": 5,
            "enable_deobfuscation": True,
            "enable_jailbreak_shield": True,
            "enable_pii_shield": True,
            "enable_tc260_semantic_shield": True,
            "risk_threshold": 0.50,
            "category_weights": {
                "A.1": 1.0,
                "A.2": 0.9,
                "A.3": 0.85,
                "A.4": 0.9,
                "A.5": 0.85,
                "JAILBREAK": 0.95,
                "PII": 0.85,
            },
            "llm_system_prompt": DEFAULT_LLM_SYSTEM_PROMPT,
            "llm_temperature": 0.5,
            "llm_max_new_tokens": 128,
        },
    },
}

DEFAULT_GATEWAY_CONFIG: Dict[str, Any] = {
    "require_api_key": False,
    "rate_limit_qps": 120,
    "default_timeout_ms": 15000,
    "enable_input_guard": True,
    "enable_stream_guard": True,
    "enable_output_guard": True,
    "pii_action": "block",  # block | mask | audit
    "audit_retention_count": 500,
    "upstream_llm": {
        "provider": "local_qwen3_0.6b",
        "base_url": "http://127.0.0.1:8092/v1",
        "model_name": "Qwen3-0.6B-Guarded",
        "max_Retries": 2,
    },
    "webhook": {
        "enabled": False,
        "url": "https://hooks.enterprise.local/qwen3guard/alert",
        "notify_on_levels": ["Unsafe"],
    },
    "api_keys": [
        {
            "id": "key_prod_cs",
            "name": "智能客服生产网关 (Prod-CustomerService)",
            "prefix": "qg-live-9f8a...3c1b",
            "token": "qg-live-9f8a7d6e5b4c3a2f1e0d9c8b7a6f3c1b",
            "policy_preset": "tc260_standard",
            "qps_limit": 80,
            "enabled": True,
            "created_at": "2026-10-18 10:00:00",
            "calls": 1420,
        },
        {
            "id": "key_fin_core",
            "name": "金融投研助手接入端 (FinTech-Core)",
            "prefix": "qg-live-4b2e...8a9d",
            "token": "qg-live-4b2e1c9d8f7a6b5e4d3c2b1a0f9e8a9d",
            "policy_preset": "finance_gov_strict",
            "qps_limit": 50,
            "enabled": True,
            "created_at": "2026-10-18 11:30:00",
            "calls": 386,
        },
        {
            "id": "key_sec_eval",
            "name": "TC260 合规自动化巡检 (SecAudit-Runner)",
            "prefix": "qg-test-7c1d...5e2a",
            "token": "qg-test-7c1d2e3f4a5b6c7d8e9f0a1b2c3d5e2a",
            "policy_preset": "tc260_standard",
            "qps_limit": 200,
            "enabled": True,
            "created_at": "2026-10-18 12:00:00",
            "calls": 168,
        },
    ],
}


class PlatformStore:
    """Manages Question Bank CRUD, API Gateway configuration, and Compliance Reports."""

    def __init__(self) -> None:
        self.gateway_config = self._load_gateway_config()

    def _load_gateway_config(self) -> Dict[str, Any]:
        if GATEWAY_CONFIG_PATH.exists():
            try:
                return json.loads(GATEWAY_CONFIG_PATH.read_text(encoding="utf-8"))
            except Exception:
                pass
        self._save_gateway_config(DEFAULT_GATEWAY_CONFIG)
        return dict(DEFAULT_GATEWAY_CONFIG)

    def _save_gateway_config(self, cfg: Dict[str, Any]) -> Dict[str, Any]:
        self.gateway_config = cfg
        GATEWAY_CONFIG_PATH.write_text(
            json.dumps(cfg, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        return cfg

    def update_gateway_config(self, patch: Dict[str, Any]) -> Dict[str, Any]:
        current = dict(self.gateway_config)
        for k, v in patch.items():
            if k != "api_keys" and v is not None:
                current[k] = v
        return self._save_gateway_config(current)

    def create_api_key(self, name: str, policy_preset: str = "tc260_standard", qps_limit: int = 100) -> Dict[str, Any]:
        raw_hex = secrets.token_hex(16)
        token = f"qg-live-{raw_hex}"
        prefix = f"qg-live-{raw_hex[:4]}...{raw_hex[-4:]}"
        new_key = {
            "id": f"key_{int(time.time()*1000)}",
            "name": name.strip() or "未命名业务接入端",
            "prefix": prefix,
            "token": token,
            "policy_preset": policy_preset,
            "qps_limit": qps_limit,
            "enabled": True,
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "calls": 0,
        }
        keys = list(self.gateway_config.get("api_keys", []))
        keys.insert(0, new_key)
        self.gateway_config["api_keys"] = keys
        self._save_gateway_config(self.gateway_config)
        return new_key

    def toggle_api_key(self, key_id: str, enabled: bool) -> Optional[Dict[str, Any]]:
        for k in self.gateway_config.get("api_keys", []):
            if k["id"] == key_id:
                k["enabled"] = bool(enabled)
                self._save_gateway_config(self.gateway_config)
                return k
        return None

    def delete_api_key(self, key_id: str) -> bool:
        keys = self.gateway_config.get("api_keys", [])
        filtered = [k for k in keys if k["id"] != key_id]
        if len(filtered) == len(keys):
            return False
        self.gateway_config["api_keys"] = filtered
        self._save_gateway_config(self.gateway_config)
        return True

    # ---------------- Question Bank CRUD ----------------
    @staticmethod
    def _dataset_path(dataset: str) -> Path:
        return FULL_CASES_PATH if dataset == "full" else CURATED_CASES_PATH

    def load_cases(self, dataset: str = "curated") -> List[Dict[str, Any]]:
        path = self._dataset_path(dataset)
        if not path.exists():
            return []
        data = json.loads(path.read_text(encoding="utf-8"))
        return data.get("cases", [])

    def save_cases(self, cases: List[Dict[str, Any]], dataset: str = "curated") -> None:
        path = self._dataset_path(dataset)
        payload = {
            "standard": "GB/T 45654 / TC260-003 生成式人工智能服务安全基本要求",
            "taxonomy": TC260_TAXONOMY,
            "total_cases": len(cases),
            "cases": cases,
        }
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    def get_bank_stats(self, dataset: str = "curated") -> Dict[str, Any]:
        cases = self.load_cases(dataset)
        major_counts = Counter()
        sub_counts = Counter()
        suite_counts = Counter()
        attack_counts = Counter()
        unsafe_cnt = 0
        benign_cnt = 0

        for c in cases:
            major_counts[f"{c.get('major_code', 'A.1')} {c.get('major_name', '')}"] += 1
            sub_counts[f"{c.get('sub_code', '')} {c.get('sub_name', '')}"] += 1
            suite_counts[c.get("suite", "应拒答检测题库")] += 1
            attack_counts[c.get("attack_method", "无指令攻击")] += 1
            if c.get("expected_unsafe", True):
                unsafe_cnt += 1
            else:
                benign_cnt += 1

        return {
            "dataset": dataset,
            "total_cases": len(cases),
            "unsafe_cases": unsafe_cnt,
            "benign_cases": benign_cnt,
            "subcategories_covered": len([k for k in sub_counts if k.startswith("A.")]),
            "attack_methods_covered": len(attack_counts),
            "by_major": [{"label": k, "count": v} for k, v in major_counts.most_common()],
            "by_suite": [{"label": k, "count": v} for k, v in suite_counts.most_common()],
            "by_attack": [{"label": k, "count": v} for k, v in attack_counts.most_common()],
        }

    def add_case(self, item: Dict[str, Any], dataset: str = "curated") -> Dict[str, Any]:
        cases = self.load_cases(dataset)
        sub_code = str(item.get("sub_code") or "A.1.8").strip()
        major_code = sub_code.split(".")[0] + "." + sub_code.split(".")[1] if sub_code.startswith("A.") else "BENIGN"
        major_name = "非拒答正常安全内容"
        sub_name = str(item.get("sub_name") or "通识问答")
        if major_code in TC260_TAXONOMY:
            major_name = TC260_TAXONOMY[major_code]["name"]
            sub_name = TC260_TAXONOMY[major_code]["subcategories"].get(sub_code, sub_name)

        expected_unsafe = bool(item.get("expected_unsafe", major_code != "BENIGN"))
        new_case = {
            "id": str(item.get("id") or f"custom_{int(time.time()*1000) % 1000000}"),
            "prompt": str(item.get("prompt", "")).strip(),
            "response": str(item.get("response", "")).strip(),
            "suite": str(item.get("suite") or ("应拒答检测题库" if expected_unsafe else "非拒答检测题库")),
            "major_code": major_code,
            "major_name": major_name,
            "sub_code": sub_code,
            "sub_name": sub_name,
            "tag": str(item.get("tag") or sub_name),
            "attack_method": str(item.get("attack_method") or "无指令攻击"),
            "expected_unsafe": expected_unsafe,
        }
        cases.insert(0, new_case)
        self.save_cases(cases, dataset)
        return new_case

    def update_case(self, case_id: str, patch: Dict[str, Any], dataset: str = "curated") -> Optional[Dict[str, Any]]:
        cases = self.load_cases(dataset)
        for idx, c in enumerate(cases):
            if c.get("id") == case_id:
                updated = dict(c)
                for k in ("prompt", "response", "suite", "sub_code", "sub_name", "tag", "attack_method", "expected_unsafe"):
                    if k in patch and patch[k] is not None:
                        updated[k] = patch[k]
                sub_code = str(updated.get("sub_code", "A.1.8"))
                if sub_code.startswith("A."):
                    maj = ".".join(sub_code.split(".")[:2])
                    if maj in TC260_TAXONOMY:
                        updated["major_code"] = maj
                        updated["major_name"] = TC260_TAXONOMY[maj]["name"]
                        updated["sub_name"] = TC260_TAXONOMY[maj]["subcategories"].get(sub_code, updated.get("sub_name", ""))
                else:
                    updated["major_code"] = "BENIGN"
                    updated["major_name"] = "非拒答正常安全内容"
                cases[idx] = updated
                self.save_cases(cases, dataset)
                return updated
        return None

    def delete_case(self, case_id: str, dataset: str = "curated") -> bool:
        cases = self.load_cases(dataset)
        filtered = [c for c in cases if c.get("id") != case_id]
        if len(filtered) == len(cases):
            return False
        self.save_cases(filtered, dataset)
        return True


platform_store = PlatformStore()
