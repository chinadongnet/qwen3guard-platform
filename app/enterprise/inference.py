"""Bounded execution: an HTTP timeout never releases a still-running GPU slot."""
from __future__ import annotations

import asyncio
import concurrent.futures
import threading
import time


class QueueFull(Exception):
    pass


class InferenceTimeout(Exception):
    pass


class InferencePool:
    def __init__(self, capacity=8):
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=1, thread_name_prefix="qg-inference")
        self.capacity = capacity
        self.pending = 0
        self.lock = threading.Lock()

    async def run(self, function, timeout=30):
        with self.lock:
            if self.pending >= self.capacity:
                raise QueueFull()
            self.pending += 1
        deadline = time.monotonic() + timeout

        def work():
            if time.monotonic() >= deadline:
                raise InferenceTimeout()
            return function()

        def finished(_):
            with self.lock:
                self.pending -= 1

        try:
            future = self.executor.submit(work)
        except Exception:
            finished(None)
            raise
        future.add_done_callback(finished)
        wrapped = asyncio.wrap_future(future)
        # Retrieve late exceptions even if the HTTP request is gone.
        wrapped.add_done_callback(lambda f: f.exception() if not f.cancelled() else None)
        try:
            return await asyncio.wait_for(asyncio.shield(wrapped), timeout)
        except TimeoutError as exc:
            future.cancel()  # Only succeeds while still queued.
            raise InferenceTimeout() from exc
        except asyncio.CancelledError:
            future.cancel()
            raise

    def close(self):
        self.executor.shutdown(wait=False, cancel_futures=True)


class LocalModels:
    def __init__(self):
        self.manager = None

    def load(self):
        from app.model_manager import model_manager
        model_manager.load_all()
        self.manager = model_manager

    def status(self):
        if not self.manager:
            return {"loaded": False}
        return self.manager.status()

    def detect(self, prompt, response, config):
        from app.config import RuntimeConfig
        allowed = RuntimeConfig.model_fields
        cfg = RuntimeConfig(**{k: v for k, v in config.items() if k in allowed})
        # PII actions are applied by the decision service using spans; avoid
        # conflating the configured action with the legacy hard-block heuristic.
        cfg.enable_pii_shield = False
        return self.manager.detect_with_gen(prompt, response, cfg)

    def generation(self, messages, max_tokens, temperature, stop):
        return self.manager.generate_incremental(messages, max_tokens, temperature, stop)

    def detect_many(self, items, config):
        from app.config import RuntimeConfig
        cfg = RuntimeConfig(**{k: v for k, v in config.items() if k in RuntimeConfig.model_fields})
        cfg.enable_pii_shield = False
        return self.manager.detect_with_gen_batch(items, cfg)

    def scan(self, prompt, response, config):
        from app.config import RuntimeConfig
        cfg = RuntimeConfig(**{k: v for k, v in config.items() if k in RuntimeConfig.model_fields})
        return self.manager.detect_stream_tokens(prompt, response, cfg)

    def raw_generation(self, prompt, config):
        from app.config import RuntimeConfig
        cfg = RuntimeConfig(**{k: v for k, v in config.items() if k in RuntimeConfig.model_fields})
        return self.manager.generate_llm_response(prompt, guarded=False, cfg=cfg)
