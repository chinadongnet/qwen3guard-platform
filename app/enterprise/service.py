from __future__ import annotations

import time
import json

from sqlalchemy import select

from . import db as t
from .inference import InferenceTimeout, QueueFull
from .security import fail, pii_findings, redact


def _build_llmguard_compat(decision: str, error, result: dict, findings: list, matched_rules: list[str]) -> tuple[str, list[str], str]:
    is_unsafe = (decision in ("block", "review")) or bool(error)
    safety = "Unsafe" if is_unsafe else "Safe"
    qwen_gen = result.get("qwen_guard_gen") or {}
    refusal = qwen_gen.get("refusal")
    if not is_unsafe:
        lines = ["Safety: Safe", "Categories: None"]
        if refusal in ("Yes", "No"):
            lines.append(f"Refusal: {refusal}")
        return safety, [], "\n".join(lines)

    raw_cats = [c for c in (qwen_gen.get("categories") or []) if c and str(c).lower() != "none"]
    tc260 = result.get("tc260") or {}
    major_code = str(tc260.get("major_code") or "")
    sub_code = str(tc260.get("sub_code") or "")
    sub_name = str(tc260.get("sub_name") or "")
    raw_and_rules = " ".join([*raw_cats, *(matched_rules or [])]).lower()
    combined = " ".join([*raw_cats, major_code, sub_code, sub_name, *(matched_rules or [])]).lower()

    canonical: list[str] = []
    def add_cat(c: str):
        if c and c not in canonical:
            canonical.append(c)

    if any(k in combined for k in ("prompt_injection", "injection", "指令注入", "提示词注入", "间接注入")):
        add_cat("Prompt_Injection")
    if any(k in combined for k in ("jailbreak", "jb.", "越狱", "dan", "角色扮演绕过", "指令覆盖")):
        add_cat("Jailbreak")
    if findings or major_code == "PII" or any(k in combined for k in ("pii", "privacy", "个人信息", "隐私")):
        add_cat("Privacy")
    if sub_code in ("A.1.5", "A.2.1") or any(k in combined for k in ("terror", "恐怖", "极端主义")):
        add_cat("Terror")
    if any(k in raw_and_rules for k in ("violent", "violence", "暴力", "杀害", "炸药", "爆炸", "武器", "枪支")):
        add_cat("Violent")
    if any(k in raw_and_rules for k in ("sexual", "porn", "色情", "淫秽")):
        add_cat("Sexual")
    if sub_code == "A.1.6" and not any(c in canonical for c in ("Violent", "Sexual")):
        add_cat("Violent")
    if any(k in combined for k in ("drug", "毒品", "制毒", "吸毒", "冰毒", "海洛因")):
        add_cat("Drug")
    if any(k in combined for k in ("gambling", "赌博", "博彩")):
        add_cat("Gambling")
    if sub_code in ("A.1.7", "A.2.2") or any(k in combined for k in ("hate", "discrimination", "歧视", "仇恨", "侮辱", "诽谤")):
        add_cat("Discrimination")
    if any(k in combined for k in ("suicide", "self-harm", "selfharm", "自杀", "自残")):
        add_cat("Self-Harm")
    if sub_code in ("A.1.1", "A.1.2", "A.1.3", "A.1.4") or any(k in combined for k in ("politic", "政治", "颠覆", "分裂", "国家安全")):
        add_cat("Politics")
    if not canonical:
        add_cat("Illegal")

    for rc in raw_cats:
        add_cat(str(rc))
    if sub_code and sub_code not in ("BENIGN", "SAFE", "NONE"):
        add_cat(f"{sub_code} {sub_name}".strip())
    for rule in matched_rules or []:
        if str(rule).startswith("custom_keyword:"):
            add_cat(str(rule))

    lines = [f"Safety: {safety}", f"Categories: {', '.join(canonical)}"]
    if refusal in ("Yes", "No"):
        lines.append(f"Refusal: {refusal}")
    return safety, canonical, "\n".join(lines)


class DetectionService:
    def __init__(self, database, models, pool, cipher=None, raw_retention_days=7):
        self.db, self.models, self.pool = database, models, pool
        self.cipher, self.raw_retention_days = cipher, raw_retention_days

    def policy(self, application):
        policy = self.db.one(select(t.policies).where(t.policies.c.id == application["policy_id"]))
        version = self.db.one(select(t.versions).where(
            t.versions.c.policy_id == policy["id"], t.versions.c.version == policy["published_version"]))
        if not version:
            fail(409, "policy_unpublished", "应用策略尚未发布")
        return version

    async def detect(self, application, key_id, prompt, response, request_id,
                     source="production", endpoint="/v1/guard/detect", version=None, include_stream_tokens=False,
                     _model_result=None, _inference_ms=0, scope=None, caller_context=None):
        if _model_result is not None and source != "evaluation":
            raise ValueError("Prepared inference is only supported for internal evaluation")
        version = version or self.policy(application)
        started = time.perf_counter()
        config = version["config"]
        status, error = "completed", None
        result = {}
        stream = None
        model_id = "Qwen3Guard-Gen-0.6B"
        try:
            model_prompt, model_response = prompt, response
            if config.get("pii_action") in ("mask", "audit"):
                model_prompt = redact(prompt)
                model_response = redact(response) if response is not None else None
            use_stream_fastpath = (
                _model_result is None
                and (scope or "").strip().lower() == "output_streaming"
                and hasattr(self.models, "scan")
            )
            if use_stream_fastpath:
                stream = await self.pool.run(
                    lambda: self.models.scan(model_prompt, model_response, config),
                    timeout=config.get("timeout_seconds", 30))
                if not isinstance(stream.get("is_safe"), bool):
                    raise RuntimeError("invalid stream decision")
                overall_risk = stream.get("overall_risk_level", "Unsafe" if not stream["is_safe"] else "Safe")
                result = {
                    "is_safe": stream["is_safe"],
                    "risk_level": overall_risk,
                    "risk_score": stream.get("risk_score"),
                    "latency_ms": stream.get("latency_ms"),
                    "tc260": stream.get("tc260"),
                    "qwen_guard_gen": {
                        "safety": overall_risk,
                        "categories": stream.get("detected_categories") or [],
                        "refusal": None,
                    },
                    "security_shield": {
                        "matched_rules": ["stream_circuit_breaker"] if stream.get("circuit_breaker_triggered") else [],
                    },
                }
                model_id = "Qwen3Guard-Stream-0.6B"
            else:
                result = _model_result if _model_result is not None else await self.pool.run(
                    lambda: self.models.detect(model_prompt, model_response, config),
                    timeout=config.get("timeout_seconds", 30))
            if not isinstance(result.get("is_safe"), bool):
                raise RuntimeError("invalid model decision")
            decision = "allow" if result["is_safe"] else "block"
            risk = result.get("risk_level", "unknown").lower()
            if include_stream_tokens:
                if stream is None:
                    stream = await self.pool.run(lambda: self.models.scan(
                        model_prompt, model_response, config), timeout=config.get("timeout_seconds", 30))
                if not isinstance(stream.get("is_safe"), bool):
                    raise RuntimeError("invalid stream decision")
                if not stream["is_safe"]:
                    decision, risk = "block", stream.get("overall_risk_level", "unsafe").lower()
        except QueueFull:
            status, error = "error", (503, "inference_overloaded", "检测队列已满")
        except InferenceTimeout:
            status, error = "timeout", (504, "inference_timeout", "检测超过时限")
        except ValueError:
            status, error = "error", (422, "input_not_supported", "内容超过模型上下文预算或格式不支持")
        except Exception:
            status, error = "error", (503, "inference_failed", "检测引擎暂时不可用")
        if error:
            decision, risk = config.get("failure_action", "block"), "indeterminate"
        findings = pii_findings(response if response is not None else prompt)
        if findings and not error:
            if config.get("pii_action") == "block":
                decision, risk = "block", "unsafe"
            elif config.get("pii_action") == "mask" and decision == "allow":
                decision = "mask"
        matched_rules = list((result.get("security_shield") or {}).get("matched_rules", []))
        target_text = f"{prompt or ''}\n{response or ''}"
        for kw in config.get("custom_block_keywords") or []:
            if kw and kw.lower() in target_text.lower():
                if not error:
                    decision, risk = "block", "unsafe"
                rule_tag = f"custom_keyword:{kw}"
                if rule_tag not in matched_rules:
                    matched_rules.append(rule_tag)
        safety_label, compat_categories, compat_result_str = _build_llmguard_compat(
            decision, error, result, findings, matched_rules)
        elapsed = round((time.perf_counter() - started) * 1000 + _inference_ms, 2)
        audit_id = t.ident()
        payload = {
            "request_id": request_id, "audit_id": audit_id, "execution_status": status,
            "decision": decision, "action": decision, "is_safe": decision == "allow" and not error,
            "safety": safety_label, "categories": compat_categories, "result": compat_result_str,
            "risk_level": risk, "risk_score": (max(result.get("risk_score") or 0.0, 0.95) if matched_rules and decision == "block" else result.get("risk_score")) if not error else None,
            "score_kind": "policy_score", "findings": findings,
            "policy": {"id": version["policy_id"], "version": version["version"]},
            "model": {"id": model_id, "revision": "unknown"},
            "model_assessment": {k: v for k, v in (result.get("qwen_guard_gen") or {}).items()
                                 if k in ("safety", "categories", "refusal")},
            "timings_ms": {"total": elapsed, "model_reported": result.get("latency_ms")},
            "tc260": result.get("tc260"),
            "matched_rules": matched_rules,
        }
        if caller_context:
            payload["caller_context"] = caller_context
        if decision == "mask":
            payload["sanitized_content"] = redact(response if response is not None else prompt)
        if stream is not None and include_stream_tokens:
            payload["stream_diagnostic"] = {**stream, "mode": "offline_token_diagnostic"}
        if error:
            payload["error"] = {"code": error[1], "message": error[2], "retryable": error[0] >= 500}
        self.persist(application, key_id, prompt, response, request_id, source, endpoint, version, payload)
        if error:
            from fastapi import HTTPException
            raise HTTPException(error[0], payload["error"] | {"audit_id": audit_id, "decision": decision})
        return payload

    def stream_terminal(self, application, key_id, prompt, request_id, source, version,
                        result=None, error="stream_failed", elapsed_ms=0, response=""):
        """Persist terminal stream outcomes without retrying inference or storing raw output."""
        payload = dict(result) if result else {
            "request_id": request_id, "execution_status": "cancelled" if error == "client_disconnected" else "error",
            "decision": version["config"].get("failure_action", "block"), "is_safe": False,
            "risk_level": "indeterminate", "risk_score": None, "score_kind": "policy_score",
            "findings": [], "policy": {"id": version["policy_id"], "version": version["version"]},
            "model": {"id": "Qwen3Guard-Gen-0.6B", "revision": "unknown"},
            "timings_ms": {"total": 0}, "error": {"code": error, "message": "流式审核未完成", "retryable": True},
        }
        payload["audit_id"] = t.ident()
        payload["timings_ms"] = {"total": round(elapsed_ms, 2)}
        # Masked cumulative output cannot safely replace content already released.
        if payload["decision"] == "mask":
            payload.update(decision="block", is_safe=False)
        payload["action"] = payload["decision"]
        self.persist(application, key_id, prompt, response, request_id, source, "chat_terminal", version, payload)
        return payload

    def persist(self, application, key_id, prompt, response, request_id, source, endpoint, version, payload):
        audit_id = payload["audit_id"]
        decision, risk = payload["decision"], payload["risk_level"]
        stored_payload = {k: v for k, v in payload.items() if k not in ("sanitized_content", "stream_diagnostic")}
        if payload.get("stream_diagnostic"):
            diagnostic = payload["stream_diagnostic"]
            stored_payload["stream_diagnostic"] = {k: diagnostic.get(k) for k in (
                "mode", "is_safe", "overall_risk_level", "total_tokens_inspected", "cutoff_token_index", "latency_ms")}
        # Event, incident and outbox are committed together before a result is returned.
        with self.db.engine.begin() as conn:
            conn.execute(t.events.insert().values(
                id=audit_id, created_at=time.time(), request_id=request_id, project_id=application["project_id"],
                application_id=application["id"], key_id=key_id, source=source,
                environment=application["environment"], endpoint=endpoint, execution_status=payload["execution_status"],
                decision=decision, risk_level=risk, latency_ms=payload["timings_ms"]["total"], policy_version_id=version["id"],
                prompt_preview=redact(prompt)[:300], response_preview=redact(response or "")[:300],
                result=stored_payload))
            if self.cipher and source in ("production", "sandbox"):
                encoded = self.cipher.encrypt(json.dumps(
                    {"prompt": prompt, "response": response}, ensure_ascii=False).encode()).decode()
                conn.execute(t.event_payloads.insert().values(id=t.ident(), created_at=time.time(),
                    event_id=audit_id, content={"encrypted": encoded},
                    expires_at=time.time()+self.raw_retention_days*86400))
            if (decision in ("block", "review") and source in ("production", "sandbox")
                    and payload["execution_status"] != "cancelled"):
                incident_id = t.ident()
                conn.execute(t.incidents.insert().values(
                    id=incident_id, created_at=time.time(), project_id=application["project_id"],
                    event_id=audit_id, state="open", assignee="", severity="high" if risk == "unsafe" else "medium"))
                for hook in conn.execute(select(t.hooks).where(
                    t.hooks.c.project_id == application["project_id"], t.hooks.c.enabled.is_(True))).mappings():
                    conn.execute(t.deliveries.insert().values(
                        id=t.ident(), created_at=time.time(), webhook_id=hook["id"],
                        project_id=application["project_id"], state="pending", attempts=0,
                        next_attempt=time.time(), payload={"incident_id": incident_id,
                            "audit_id": audit_id, "request_id": request_id, "decision": decision, "risk_level": risk}))
