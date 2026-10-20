from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import time

from fastapi import HTTPException
from sqlalchemy import select

from . import db as t
from .network import post_json
from .security import redact

logger = logging.getLogger("qwenguard.tasks")


class TaskRunner:
    """Single coordinator with durable jobs, resumable item offsets and outbox."""
    def __init__(self, database, service, cipher, settings):
        self.db, self.service, self.cipher, self.settings = database, service, cipher, settings
        self.tasks = []
        self.last_cleanup = 0

    def start(self):
        # Deployment currently runs one coordinator. Never silently rerun an
        # interrupted external call; operators explicitly resume the job.
        with self.db.engine.begin() as conn:
            conn.execute(t.jobs.update().where(t.jobs.c.state == "running").values(
                state="interrupted", error_code="worker_restarted"))
        self.tasks = [asyncio.create_task(self.jobs_loop()), asyncio.create_task(self.hooks_loop())]

    async def close(self):
        for task in self.tasks:
            task.cancel()
        await asyncio.gather(*self.tasks, return_exceptions=True)

    async def jobs_loop(self):
        while True:
            try:
                if time.time() - self.last_cleanup >= 60:
                    with self.db.engine.begin() as conn:
                        conn.execute(t.event_payloads.delete().where(t.event_payloads.c.expires_at <= time.time()))
                    self.last_cleanup = time.time()
                job = self.db.one(select(t.jobs).where(t.jobs.c.state == "queued").order_by(t.jobs.c.created_at).limit(1))
                if job:
                    await self.run_job(job)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.error("evaluation coordinator failure type=%s", type(exc).__name__)
            await asyncio.sleep(1)

    async def run_job(self, job):
        with self.db.engine.begin() as conn:
            changed = conn.execute(t.jobs.update().where(
                t.jobs.c.id == job["id"], t.jobs.c.state == "queued").values(state="running"))
            if changed.rowcount != 1:
                return
        try:
            application = self.db.one(select(t.apps).where(t.apps.c.id == job["application_id"]))
            version = self.db.one(select(t.versions).where(t.versions.c.id == job["policy_version_id"]))
            target = self.db.one(select(t.endpoints).where(t.endpoints.c.id == job["endpoint_id"])) if job["endpoint_id"] else None
            items = (json.loads(self.cipher.decrypt(job["items"]["encrypted"].encode()))
                     if isinstance(job["items"], dict) else job["items"])
            prepared = {}
            for position in range(job["completed"], job["total"]):
                current = self.db.one(select(t.jobs).where(t.jobs.c.id == job["id"]))
                if current["cancel_requested"]:
                    self.set_state(job["id"], "cancelled")
                    return
                item = items[position]
                # Bounded microbatches use the same model and decision service.
                # Stochastic policies and external/generation jobs stay sequential.
                if (not target and not prepared and hasattr(self.service.models, "detect_many")
                        and version["config"].get("guard_gen_temperature", 0) <= .01):
                    group = items[position:position+8]
                    if all(i.get("mode", "text") == "text" for i in group):
                        pairs = [(i["prompt"], i.get("response")) for i in group]
                        if version["config"].get("pii_action") in ("mask", "audit"):
                            pairs = [(redact(p), redact(r) if r is not None else None) for p, r in pairs]
                        try:
                            started = time.perf_counter()
                            batch = await self.service.pool.run(
                                lambda: self.service.models.detect_many(pairs, version["config"]),
                                timeout=min(120, 8 * version["config"].get("timeout_seconds", 30)))
                            elapsed = (time.perf_counter() - started) * 1000
                            prepared = {position+n: (r, elapsed if r is not None else 0) for n, r in enumerate(batch)}
                        except Exception:
                            # Oversized batches and per-item validation failures
                            # retain the existing individual error/audit semantics.
                            prepared = {}
                try:
                    response = item.get("response")
                    comparison = None
                    if item.get("mode") == "generation_compare":
                        if target:
                            raise ValueError("comparison_requires_local_model")
                        cfg = {**version["config"], "llm_max_new_tokens": 64}
                        raw = await self.service.pool.run(lambda: self.service.models.raw_generation(
                            redact(item["prompt"]), cfg), timeout=120)
                        response = raw["final_response"]
                        if not response:
                            raise ValueError("empty_generation")
                        input_guard = await self.service.detect(application, None, item["prompt"], None,
                            t.ident(), source="evaluation", endpoint="dynamic_input", version=version)
                        stream = await self.service.pool.run(lambda: self.service.models.scan(
                            redact(item["prompt"]), redact(response), cfg), timeout=60)
                        comparison = {"raw_response": redact(response), "input_guard": input_guard,
                                      "stream_safe": stream["is_safe"]}
                    if target:
                        if not target["enabled"]:
                            raise ValueError("endpoint_disabled")
                        credential = self.cipher.decrypt(target["credential"].encode()).decode() if target["credential"] else ""
                        remote, _ = await asyncio.wait_for(post_json(
                            target["url"], {"model": target["model"], "messages": [
                                {"role": "user", "content": item["prompt"]}], "max_tokens": 256, "stream": False},
                            self.settings.private_hosts, credential), timeout=25)
                        response = remote["choices"][0]["message"]["content"]
                        if not isinstance(response, str) or not response.strip() or len(response) > 16000:
                            raise ValueError("invalid_response")
                    model_result, inference_ms = prepared.pop(position, (None, 0))
                    result = await self.service.detect(
                        application, None, item["prompt"], response, t.ident(),
                        source="evaluation", endpoint="evaluation", version=version,
                        _model_result=model_result, _inference_ms=inference_ms)
                    result["expected_unsafe"] = item.get("expected_unsafe")
                    result["passed"] = (
                        (result["decision"] == "block" if item["expected_unsafe"]
                         else result["decision"] in ("allow", "mask"))
                        if item.get("expected_unsafe") is not None else None)
                    result["response_preview"] = redact(response or "")[:300]
                    if comparison is not None:
                        comparison["output_guard"] = {k: result.get(k) for k in ("decision", "risk_level", "audit_id")}
                        comparison["blocked"] = (comparison["input_guard"]["decision"] != "allow"
                            or result["decision"] not in ("allow", "mask") or not comparison["stream_safe"])
                        comparison["guarded_response"] = ("该内容已被安全策略拦截。" if comparison["blocked"]
                            else result.get("sanitized_content", redact(response)))
                        result["comparison"] = comparison
                        # Input labels do not label generated replies. No invented compliance score.
                        result["passed"] = None
                        result["expected_unsafe"] = None
                    if target:
                        # A prompt label is not an independent label for a newly
                        # generated remote reply. Preserve provenance, not a score.
                        result["input_expected_unsafe"] = item.get("expected_unsafe")
                        result["expected_unsafe"] = None
                        result["passed"] = None
                except HTTPException as exc:
                    result = {"execution_status": "error", "error": exc.detail,
                              "expected_unsafe": item.get("expected_unsafe"), "passed": None}
                except Exception:
                    result = {"execution_status": "error", "error": {"code": "evaluation_item_failed"},
                              "expected_unsafe": item.get("expected_unsafe"), "passed": None}
                result["case"] = {k: item.get(k) for k in (
                    "case_id", "case_revision", "sub_code", "attack_method", "evaluation_target", "label_source", "suite")}
                with self.db.engine.begin() as conn:
                    conn.execute(t.job_items.insert().values(id=t.ident(), created_at=time.time(),
                        job_id=job["id"], position=position, result=result))
                    conn.execute(t.jobs.update().where(t.jobs.c.id == job["id"]).values(completed=position + 1))
                await asyncio.sleep(0)  # Yield to interactive requests.
            current = self.db.one(select(t.jobs).where(t.jobs.c.id == job["id"]))
            self.set_state(job["id"], "cancelled" if current["cancel_requested"] else "completed")
        except asyncio.CancelledError:
            self.set_state(job["id"], "interrupted", "worker_stopped")
            raise
        except Exception:
            self.set_state(job["id"], "failed", "job_failed")

    def set_state(self, job_id, state, error=None):
        with self.db.engine.begin() as conn:
            conn.execute(t.jobs.update().where(t.jobs.c.id == job_id).values(state=state, error_code=error))

    async def hooks_loop(self):
        while True:
            try:
                delivery = self.db.one(select(t.deliveries).where(
                    t.deliveries.c.state == "pending", t.deliveries.c.next_attempt <= time.time()
                ).order_by(t.deliveries.c.created_at).limit(1))
                if delivery:
                    await self.deliver(delivery)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.error("notification coordinator failure type=%s", type(exc).__name__)
            await asyncio.sleep(1)

    async def deliver(self, delivery):
        hook = self.db.one(select(t.hooks).where(t.hooks.c.id == delivery["webhook_id"]))
        attempts = delivery["attempts"] + 1
        status, state = None, "pending"
        if not hook or not hook["enabled"]:
            state = "cancelled"
        else:
            payload = {"delivery_id": delivery["id"], "timestamp": int(time.time()), **delivery["payload"]}
            canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            secret = self.cipher.decrypt(hook["secret"].encode()).decode()
            signature = hmac.new(secret.encode(), canonical.encode(), hashlib.sha256).hexdigest()
            # Signature is over canonical JSON; receivers canonicalize the parsed
            # object identically and deduplicate by delivery_id.
            try:
                _, status = await asyncio.wait_for(post_json(
                    hook["url"], payload, self.settings.private_hosts,
                    headers={"X-QG-Signature": signature, "X-QG-Delivery-Id": delivery["id"]},
                    expect_json=False), 25)
                state = "delivered"
            except Exception:
                state = "failed" if attempts >= 5 else "pending"
        with self.db.engine.begin() as conn:
            conn.execute(t.deliveries.update().where(t.deliveries.c.id == delivery["id"]).values(
                attempts=attempts, state=state, status_code=status,
                next_attempt=time.time() + min(300, 2 ** attempts)))
