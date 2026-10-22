"""GPU Model Manager for Qwen3Guard-Gen-0.6B, Qwen3Guard-Stream-0.6B, and Qwen3-0.6B."""
from __future__ import annotations

import os
import re
import threading
import time
from pathlib import Path
from typing import Any, AsyncGenerator, Dict, Generator, List, Optional, Tuple

import torch
from transformers import AutoModel, AutoModelForCausalLM, AutoTokenizer

from app.config import ROOT_DIR, RuntimeConfig, config_manager
from app.security_shield import ShieldResult, security_shield


def resolve_model_root() -> Path:
    """Prefer custom model root, fallback to local workspace models/ or ext4 volume (/models)."""
    env_root = os.environ.get("QWENGUARD_MODEL_ROOT")
    if env_root and Path(env_root).exists():
        return Path(env_root)
    workspace_models = ROOT_DIR / "models"
    if workspace_models.exists():
        return workspace_models
    docker_vol = Path("/models")
    if docker_vol.exists() and (docker_vol / "Qwen3Guard-Gen-0.6B").exists():
        return docker_vol
    return workspace_models


MODEL_REGISTRY = {
    "Qwen3Guard-Gen-0.6B": {
        "ms_id": "Qwen/Qwen3Guard-Gen-0.6B",
        "hf_id": "Qwen/Qwen3Guard-Gen-0.6B",
        "role": "生成式安全分类与拒答判定模型 (Input/Output Guard)",
    },
    "Qwen3Guard-Stream-0.6B": {
        "ms_id": "Qwen/Qwen3Guard-Stream-0.6B",
        "hf_id": "Qwen/Qwen3Guard-Stream-0.6B",
        "role": "Token级实时流式安全检测与熔断模型 (Token Stream Guard)",
    },
    "Qwen3-0.6B": {
        "ms_id": "Qwen/Qwen3-0.6B",
        "hf_id": "Qwen/Qwen3-0.6B",
        "role": "动态自测与对话生成小参数大模型 (Dynamic Self-Test LLM)",
    },
}


def resolve_model_dir(model_name: str, root_dir: Path) -> str:
    """Resolve local path or auto-download from ModelScope / HuggingFace Hub."""
    local_dir = root_dir / model_name
    if local_dir.exists() and any(local_dir.iterdir()):
        return str(local_dir)

    meta = MODEL_REGISTRY.get(model_name)
    if not meta:
        return str(local_dir)

    # Attempt automatic download from ModelScope (high speed in CN mainland)
    try:
        from modelscope.hub.snapshot_download import snapshot_download as ms_download
        local_dir.mkdir(parents=True, exist_ok=True)
        downloaded = ms_download(meta["ms_id"], local_dir=str(local_dir))
        return str(downloaded)
    except Exception:
        pass

    # Fallback to HuggingFace Hub
    try:
        from huggingface_hub import snapshot_download as hf_download
        local_dir.mkdir(parents=True, exist_ok=True)
        downloaded = hf_download(repo_id=meta["hf_id"], local_dir=str(local_dir))
        return str(downloaded)
    except Exception:
        return str(local_dir)


SAFETY_RE = re.compile(r"Safety:\s*(Safe|Unsafe|Controversial)", re.IGNORECASE)
CATEGORY_RE = re.compile(
    r"(Violent|Non-violent Illegal Acts|Sexual Content or Sexual Acts|PII|Suicide & Self-Harm|Politically Sensitive Topics|Copyright Violation|Jailbreak|Cyberattack|None)",
    re.IGNORECASE,
)
REFUSAL_RE = re.compile(r"Refusal:\s*(Yes|No)", re.IGNORECASE)


class ModelManager:
    """Manages concurrent GPU inference for Qwen3Guard-Gen-0.6B, Qwen3Guard-Stream-0.6B, and Qwen3-0.6B."""

    def __init__(self) -> None:
        self.model_root = resolve_model_root()
        self.device = "cuda" if torch.cuda.is_available() else "cpu"
        self.dtype = torch.bfloat16 if self.device == "cuda" else torch.float32
        self._lock = threading.RLock()

        # Ampere (RTX 3090 / Compute Capability 8.6) hardware optimizations
        if self.device == "cuda":
            try:
                major, _ = torch.cuda.get_device_capability(0)
                if major >= 8:
                    torch.backends.cuda.matmul.allow_tf32 = True
                    torch.backends.cudnn.allow_tf32 = True
                    if hasattr(torch, "set_float32_matmul_precision"):
                        torch.set_float32_matmul_precision("high")
            except Exception:
                pass

        self.gen_tokenizer: Any = None
        self.gen_model: Any = None
        self.gen_load_ms: float = 0.0

        self.stream_tokenizer: Any = None
        self.stream_model: Any = None
        self.stream_load_ms: float = 0.0

        self.llm_tokenizer: Any = None
        self.llm_model: Any = None
        self.llm_load_ms: float = 0.0

        self.loaded = False
        self.load_error: Optional[str] = None

    def load_all(self) -> Dict[str, Any]:
        """Load all 3 models into GPU/CPU memory."""
        with self._lock:
            if self.loaded:
                return self.status()

            try:
                # 1. Load Qwen3Guard-Gen-0.6B
                gen_path = resolve_model_dir("Qwen3Guard-Gen-0.6B", self.model_root)
                t0 = time.perf_counter()
                self.gen_tokenizer = AutoTokenizer.from_pretrained(gen_path, trust_remote_code=True)
                self.gen_model = AutoModelForCausalLM.from_pretrained(
                    gen_path,
                    torch_dtype=self.dtype,
                    device_map="auto" if self.device == "cuda" else None,
                    trust_remote_code=True,
                )
                if self.device != "cuda":
                    self.gen_model.to(self.device)
                self.gen_model.eval()
                self.gen_load_ms = round((time.perf_counter() - t0) * 1000, 1)

                # 2. Load Qwen3Guard-Stream-0.6B
                stream_path = resolve_model_dir("Qwen3Guard-Stream-0.6B", self.model_root)
                t1 = time.perf_counter()
                self.stream_tokenizer = AutoTokenizer.from_pretrained(stream_path, trust_remote_code=True)
                self.stream_model = AutoModel.from_pretrained(
                    stream_path,
                    torch_dtype=self.dtype,
                    device_map="auto" if self.device == "cuda" else None,
                    trust_remote_code=True,
                )
                if self.device != "cuda":
                    self.stream_model.to(self.device)
                self.stream_model.eval()
                self.stream_load_ms = round((time.perf_counter() - t1) * 1000, 1)

                # 3. Load Qwen3-0.6B (Dynamic Small LLM for self-testing)
                llm_path = resolve_model_dir("Qwen3-0.6B", self.model_root)
                t2 = time.perf_counter()
                self.llm_tokenizer = AutoTokenizer.from_pretrained(llm_path, trust_remote_code=True)
                self.llm_model = AutoModelForCausalLM.from_pretrained(
                    llm_path,
                    torch_dtype=self.dtype,
                    device_map="auto" if self.device == "cuda" else None,
                    trust_remote_code=True,
                )
                if self.device != "cuda":
                    self.llm_model.to(self.device)
                self.llm_model.eval()
                self.llm_load_ms = round((time.perf_counter() - t2) * 1000, 1)

                self.loaded = True
                self.load_error = None
            except Exception as exc:
                self.load_error = str(exc)
                raise

            return self.status()

    def status(self) -> Dict[str, Any]:
        is_cuda = torch.cuda.is_available()
        gpu_name = torch.cuda.get_device_name(0) if is_cuda else "CPU"
        compute_cap = "N/A"
        cuda_version = None
        tf32_enabled = False
        vram_alloc_mb = 0.0
        vram_reserved_mb = 0.0
        vram_total_mb = 0.0

        if is_cuda:
            try:
                cap = torch.cuda.get_device_capability(0)
                compute_cap = f"{cap[0]}.{cap[1]}"
                cuda_version = getattr(torch.version, "cuda", None)
                tf32_enabled = bool(getattr(torch.backends.cuda.matmul, "allow_tf32", False))
                vram_alloc_mb = round(torch.cuda.memory_allocated(0) / (1024 * 1024), 1)
                vram_reserved_mb = round(torch.cuda.memory_reserved(0) / (1024 * 1024), 1)
                vram_total_mb = round(torch.cuda.get_device_properties(0).total_memory / (1024 * 1024), 1)
            except Exception:
                pass

        return {
            "loaded": self.loaded,
            "device": self.device,
            "gpu_name": gpu_name,
            "compute_capability": compute_cap,
            "cuda_version": cuda_version,
            "tf32_enabled": tf32_enabled,
            "dtype": str(self.dtype),
            "vram_allocated_mb": vram_alloc_mb,
            "vram_reserved_mb": vram_reserved_mb,
            "vram_total_mb": vram_total_mb,
            "model_root": str(self.model_root),
            "models": {
                "Qwen3Guard-Gen-0.6B": {
                    "loaded": self.gen_model is not None,
                    "load_time_ms": self.gen_load_ms,
                    "role": "生成式安全分类与拒答判定模型 (Input/Output Guard)",
                },
                "Qwen3Guard-Stream-0.6B": {
                    "loaded": self.stream_model is not None,
                    "load_time_ms": self.stream_load_ms,
                    "role": "Token级实时流式安全检测与熔断模型 (Token Stream Guard)",
                },
                "Qwen3-0.6B": {
                    "loaded": self.llm_model is not None,
                    "load_time_ms": self.llm_load_ms,
                    "role": "动态自测与对话生成小参数大模型 (Dynamic Self-Test LLM)",
                },
            },
            "error": self.load_error,
        }

    def generate_incremental(self, messages, max_tokens, temperature, stop):
        """Generate one token at a time; release the device lock between steps.

        The caller owns the generator, advances it through a bounded worker and
        audits buffered output before exposing it. No background generation
        survives a closed consumer.
        """
        encoded = self.llm_tokenizer.apply_chat_template(
            messages, tokenize=False, add_generation_prompt=True, enable_thinking=False)
        inputs = self.llm_tokenizer(encoded, return_tensors="pt").input_ids.to(self.device)
        if inputs.shape[1] > 8192:
            raise ValueError("Conversation exceeds 8192 token budget")
        cache, generated, emitted = None, [], ""
        try:
            for _ in range(max_tokens):
                if stop.is_set():
                    break
                with self._lock, torch.inference_mode():
                    output = self.llm_model(input_ids=inputs, past_key_values=cache,
                                            use_cache=True, return_dict=True)
                    cache = output.past_key_values
                    logits = output.logits[:, -1, :]
                    if temperature > 0:
                        next_token = torch.multinomial(torch.softmax(logits / temperature, dim=-1), 1)
                    else:
                        next_token = torch.argmax(logits, dim=-1, keepdim=True)
                    token_id = int(next_token.item())
                    inputs = next_token
                if token_id in (151645, 151643):
                    break
                generated.append(token_id)
                decoded = self.llm_tokenizer.decode(generated, skip_special_tokens=True)
                if "\ufffd" not in decoded and decoded.startswith(emitted):
                    delta = decoded[len(emitted):]
                    emitted = decoded
                    if delta:
                        yield delta
        finally:
            del cache

    def build_guard_gen_prompt(
        self,
        prompt: str,
        response: Optional[str],
        cfg: RuntimeConfig,
    ) -> str:
        """Build Qwen3Guard-Gen prompt incorporating live-tuned safety policy and categories."""
        has_resp = bool(response and response.strip())
        policy = cfg.guard_gen_safety_policy_output if has_resp else cfg.guard_gen_safety_policy_input
        if cfg.guard_gen_custom_rules.strip():
            policy = f"{policy.strip()}\n{cfg.guard_gen_custom_rules.strip()}"

        categories = cfg.guard_gen_unsafe_categories.strip()
        conv_lines = [f"USER: {prompt.strip()}"]
        if has_resp:
            conv_lines.append(f"ASSISTANT: {response.strip()}")
        conv_block = "\n\n".join(conv_lines)

        if has_resp:
            task_header = (
                "# Task:\n"
                "1) Evaluate whether THE LAST ASSISTANT's response belongs to safe or unsafe content based on our safety policy.\n"
                "2) Identify the category of unsafe content found.\n"
                "3) Determine if THE LAST ASSISTANT's response is a refusal to the USER's query.\n\n"
            )
            refusal_block = (
                "\n\n<BEGIN REFUSAL POLICY>\n"
                "**Refusal: Yes**: The ASSISTANT refused to answer or did not comply with the USER's request.\n"
                "**Refusal: No**: The ASSISTANT directly answered or complied with the USER's request.\n"
                "<END REFUSAL POLICY>"
            )
            closing_instr = (
                "Provide your safety assessment for ONLY THE LAST **ASSISTANT's response** in the above conversation:\n"
                " - The first line must be one of: 'Safety: Safe', 'Safety: Unsafe', 'Safety: Controversial'.\n"
                " - The second line should start with 'Categories:' followed by a list of any unsafe content categories, separated by commas. If the content is safe, use 'Categories: None'.\n"
                " - The third line must be one of: 'Refusal: Yes', 'Refusal: No'."
            )
        else:
            task_header = (
                "# Task:\n"
                "1) Evaluate whether THE LAST USER's query belongs to safe or unsafe content based on our safety policy.\n"
                "2) Identify the category of unsafe content found.\n\n"
            )
            refusal_block = ""
            closing_instr = (
                "Provide your safety assessment for ONLY THE LAST **USER's query** in the above conversation:\n"
                " - The first line must be one of: 'Safety: Safe', 'Safety: Unsafe', 'Safety: Controversial'.\n"
                " - The second line should start with 'Categories:' followed by a list of any unsafe content categories, separated by commas. If the content is safe, use 'Categories: None'."
            )

        user_content = (
            f"{task_header}"
            "<BEGIN SAFETY POLICY>\n"
            f"{policy}\n"
            "<END SAFETY POLICY>\n\n"
            "<BEGIN UNSAFE CONTENT CATEGORIES>\n"
            f"{categories}\n"
            f"<END UNSAFE CONTENT CATEGORIES>{refusal_block}\n\n"
            "<BEGIN CONVERSATION>\n\n"
            f"{conv_block}\n\n"
            "<END CONVERSATION>\n\n"
            f"{closing_instr}"
        )
        return (
            f"<|im_start|>user\n{user_content}<|im_end|>\n"
            "<|im_start|>assistant\n<think>\n\n</think>\n\n"
        )

    @staticmethod
    def parse_guard_gen_output(raw_output: str) -> Tuple[str, List[str], Optional[str]]:
        """Extract (safety_label, categories, refusal) from Qwen3Guard-Gen raw output."""
        from app.guard_output import parse_guard_output
        return parse_guard_output(raw_output)

    def detect_with_gen(
        self,
        prompt: str,
        response: Optional[str] = None,
        cfg: Optional[RuntimeConfig] = None,
    ) -> Dict[str, Any]:
        """Run full detection combining Qwen3Guard-Gen-0.6B and Multi-Layer Security Shield."""
        if not self.loaded:
            self.load_all()
        cfg = cfg or config_manager.config
        t0 = time.perf_counter()

        # Pre-guardrail de-obfuscation so Qwen3Guard-Gen also sees unwrapped text
        target_for_model = prompt
        if cfg.enable_deobfuscation:
            deobf_prompt, _ = security_shield.deobfuscate_and_unwrap(prompt)
            target_for_model = deobf_prompt

        rendered_prompt = self.build_guard_gen_prompt(target_for_model, response, cfg)

        with self._lock, torch.inference_mode():
            model_inputs = self.gen_tokenizer([rendered_prompt], return_tensors="pt").to(self.device)
            input_len = model_inputs.input_ids.shape[1]
            if input_len > 8192:
                raise ValueError("Guard input exceeds 8192 token budget")
            gen_kwargs: Dict[str, Any] = {
                "max_new_tokens": cfg.guard_gen_max_new_tokens,
                "eos_token_id": [151645, 151643],
                "pad_token_id": 151643,
            }
            if cfg.guard_gen_temperature > 0.01:
                gen_kwargs["do_sample"] = True
                gen_kwargs["temperature"] = cfg.guard_gen_temperature
            else:
                gen_kwargs["do_sample"] = False

            generated_ids = self.gen_model.generate(**model_inputs, **gen_kwargs)
            output_ids = generated_ids[0][input_len:]
            raw_output = self.gen_tokenizer.decode(output_ids, skip_special_tokens=True).strip()

        return self._gen_result(prompt, response, cfg, raw_output, (time.perf_counter() - t0) * 1000)

    def detect_with_gen_batch(self, items, cfg):
        """Bounded offline microbatch; identical template and decision processor."""
        if not 1 <= len(items) <= 8:
            raise ValueError("Guard batch supports 1 to 8 items")
        if not self.loaded:
            self.load_all()
        started = time.perf_counter()
        prompts = []
        for prompt, response in items:
            target = security_shield.deobfuscate_and_unwrap(prompt)[0] if cfg.enable_deobfuscation else prompt
            prompts.append(self.build_guard_gen_prompt(target, response, cfg))
        with self._lock, torch.inference_mode():
            # Decoder-only generation requires left padding. Keep the tokenizer
            # change inside the same lock used by single-item generation.
            prior_padding = self.gen_tokenizer.padding_side
            self.gen_tokenizer.padding_side = "left"
            try:
                inputs = self.gen_tokenizer(prompts, padding=True, return_tensors="pt").to(self.device)
            finally:
                self.gen_tokenizer.padding_side = prior_padding
            width = inputs.input_ids.shape[1]
            if width > 8192 or width * len(items) > 16384:
                raise ValueError("Guard batch exceeds token budget")
            kwargs = {"max_new_tokens": cfg.guard_gen_max_new_tokens, "eos_token_id": [151645, 151643],
                      "pad_token_id": 151643, "do_sample": cfg.guard_gen_temperature > .01}
            if kwargs["do_sample"]:
                kwargs["temperature"] = cfg.guard_gen_temperature
            generated = self.gen_model.generate(**inputs, **kwargs)
            outputs = self.gen_tokenizer.batch_decode(generated[:, width:], skip_special_tokens=True)
        elapsed = (time.perf_counter() - started) * 1000
        results = []
        for (prompt, response), raw in zip(items, outputs):
            try:
                results.append(self._gen_result(prompt, response, cfg, raw.strip(), elapsed))
            except RuntimeError:
                results.append(None)  # An invalid item gets a normal individual retry.
        return results

    def _gen_result(self, prompt, response, cfg, raw_output, elapsed_ms):
        qwen_safety, qwen_cats, refusal = self.parse_guard_gen_output(raw_output)

        # Combine with Security Shield & TC260 taxonomy
        shield_res: ShieldResult = security_shield.evaluate(
            text=prompt,
            cfg=cfg,
            qwen_safety=qwen_safety,
            qwen_categories=qwen_cats,
            response_text=response or "",
            response_refused=refusal == "Yes",
        )

        # If moderating an assistant response and the assistant already clearly refused an unsafe request,
        # record whether the assistant's reply itself is a safe refusal
        assistant_refused = refusal == "Yes"

        latency_ms = round(elapsed_ms, 2)
        return {
            "is_safe": shield_res.is_safe,
            "action": "allow" if shield_res.is_safe else "block",
            "risk_level": shield_res.risk_level,
            "risk_score": shield_res.risk_score,
            "qwen_guard_gen": {
                "raw_output": raw_output,
                "safety": qwen_safety,
                "categories": qwen_cats,
                "refusal": "Yes" if (response and assistant_refused) else refusal,
            },
            "tc260": {
                "major_code": shield_res.tc260_major_code,
                "major_name": shield_res.tc260_major_name,
                "sub_code": shield_res.tc260_sub_code,
                "sub_name": shield_res.tc260_sub_name,
            },
            "security_shield": {
                "attack_methods": shield_res.attack_methods,
                "matched_rules": shield_res.matched_rules,
                "pii_entities": shield_res.pii_entities,
                "deobfuscated_text": shield_res.deobfuscated_text,
                "explanation": shield_res.explanation,
            },
            "safe_fallback": None if shield_res.is_safe else cfg.safe_fallback_response,
            "latency_ms": latency_ms,
        }

    def detect_stream_tokens(
        self,
        prompt: str,
        response: Optional[str] = None,
        cfg: Optional[RuntimeConfig] = None,
    ) -> Dict[str, Any]:
        """Run token-by-token real-time streaming moderation using Qwen3Guard-Stream-0.6B."""
        if not self.loaded:
            self.load_all()
        cfg = cfg or config_manager.config
        t0 = time.perf_counter()

        # Construct single-turn stream for Qwen3Guard-Stream so token risk reflects the target stream itself
        if response and response.strip():
            messages = [{"role": "assistant", "content": response}]
            target_text = response
            role = "assistant"
        else:
            messages = [{"role": "user", "content": prompt}]
            target_text = prompt
            role = "user"

        rendered = self.stream_tokenizer.apply_chat_template(
            messages, tokenize=False, add_generation_prompt=False
        )
        encoded = self.stream_tokenizer(rendered, return_tensors="pt")
        input_ids_1d = encoded.input_ids[0].to(self.device)
        if len(input_ids_1d) > 8192:
            raise ValueError("Stream input exceeds 8192-token budget")

        # Find where the target text tokens start (after the last <|im_start|>user\n or <|im_start|>assistant\n)
        im_start_id = self.stream_tokenizer.convert_tokens_to_ids("<|im_start|>")
        im_end_id = self.stream_tokenizer.convert_tokens_to_ids("<|im_end|>")
        ids_list = input_ids_1d.tolist()

        start_idx = 0
        for idx in range(len(ids_list) - 1, -1, -1):
            if ids_list[idx] == im_start_id:
                start_idx = min(idx + 3, len(ids_list) - 1)
                break

        with self._lock, torch.inference_mode():
            outputs = self.stream_model(
                input_ids=input_ids_1d.unsqueeze(0),
                logits_to_keep=0,
                return_dict=True,
            )
            if role == "user":
                r_logits = outputs.query_risk_level_logits[0]
                c_logits = outputs.query_category_logits[0]
                r_map = self.stream_model.query_risk_level_map
                c_map = self.stream_model.query_category_map
            else:
                r_logits = outputs.risk_level_logits[0]
                c_logits = outputs.category_logits[0]
                r_map = self.stream_model.response_risk_level_map
                c_map = self.stream_model.response_category_map

            r_probs = torch.softmax(r_logits, dim=-1)
            pred_r_prob, pred_r_idx = torch.max(r_probs, dim=-1)
            c_probs = torch.softmax(c_logits, dim=-1)
            pred_c_prob, pred_c_idx = torch.max(c_probs, dim=-1)

            risk_levels: List[str] = [r_map[int(i)] for i in pred_r_idx]
            risk_probs: List[float] = [round(float(p), 3) for p in pred_r_prob]
            categories: List[str] = [c_map[int(i)] for i in pred_c_idx]

        token_events: List[Dict[str, Any]] = []
        accumulated_text = ""
        cutoff_triggered = False
        cutoff_index: Optional[int] = None
        cutoff_reason: Optional[str] = None
        safe_prefix_text = ""
        overall_risk = "Safe"
        detected_categories: List[str] = []

        for pos in range(start_idx, len(ids_list)):
            tid = ids_list[pos]
            if tid in (im_start_id, im_end_id, 151667, 151668):
                continue
            tok_str = self.stream_tokenizer.decode([tid], skip_special_tokens=False)
            if not accumulated_text and not tok_str.strip():
                continue
            accumulated_text += tok_str

            if pos >= len(risk_levels) or pos >= len(risk_probs):
                raise RuntimeError("Incomplete Stream classification")
            raw_risk, tok_prob = risk_levels[pos], risk_probs[pos]
            if raw_risk not in ("Safe", "Unsafe", "Controversial"):
                raise RuntimeError("Unknown Stream risk label")
            tok_risk = raw_risk if (
                raw_risk == "Unsafe" and tok_prob >= cfg.stream_unsafe_threshold
                or raw_risk == "Controversial" and cfg.stream_controversial_as_unsafe
            ) else "Safe"
            tok_cat = categories[pos] if (tok_risk != "Safe" and pos < len(categories)) else "None"

            # Periodic incremental Shield check on accumulated target stream text only
            rel_idx = len(token_events)
            shield_hit: Optional[ShieldResult] = None
            if (rel_idx + 1) % cfg.stream_window_check_interval == 0 or pos >= len(ids_list) - 2:
                shield_eval = security_shield.evaluate(
                    text=accumulated_text,
                    cfg=cfg,
                    qwen_safety=tok_risk,
                    qwen_categories=[tok_cat] if tok_cat != "None" else [],
                    response_text="",
                )
                if not shield_eval.is_safe:
                    shield_hit = shield_eval

            is_tok_unsafe = (
                tok_risk in ("Unsafe", "Controversial")
                or (shield_hit is not None and not shield_hit.is_safe)
            )

            if is_tok_unsafe:
                if tok_risk == "Unsafe" or (shield_hit and shield_hit.risk_level == "Unsafe"):
                    overall_risk = "Unsafe"
                elif overall_risk == "Safe":
                    overall_risk = "Controversial"

                eff_cat = tok_cat if tok_cat != "None" else (shield_hit.tc260_sub_name if shield_hit else "Unsafe")
                if eff_cat and eff_cat not in detected_categories:
                    detected_categories.append(eff_cat)

            action = "pass"
            if is_tok_unsafe:
                action = "cutoff" if cfg.stream_circuit_breaker else "warn"
                if not cutoff_triggered and cfg.stream_circuit_breaker:
                    cutoff_triggered = True
                    cutoff_index = rel_idx
                    cutoff_reason = (
                        f"Token #{rel_idx} ('{tok_str.strip() or tok_str}') 触发实时流式熔断: "
                        f"Risk={tok_risk if tok_risk != 'Safe' else shield_hit.risk_level}, "
                        f"Category={tok_cat if tok_cat != 'None' else (shield_hit.tc260_sub_code + ' ' + shield_hit.tc260_sub_name if shield_hit else 'Unsafe')}"
                    )
            elif not cutoff_triggered:
                safe_prefix_text = accumulated_text

            token_events.append(
                {
                    "index": rel_idx,
                    "token_id": tid,
                    "token": tok_str,
                    "accumulated_length": len(accumulated_text),
                    "risk_level": tok_risk if tok_risk != "Safe" else (shield_hit.risk_level if shield_hit else "Safe"),
                    "category": tok_cat if tok_cat != "None" else (shield_hit.tc260_sub_code if shield_hit else "None"),
                    "action": action,
                    "blocked_after_cutoff": cutoff_triggered and (cutoff_index is not None and rel_idx > cutoff_index),
                }
            )

        # Final shield evaluation for complete metadata
        final_shield = security_shield.evaluate(
            text=prompt,
            cfg=cfg,
            qwen_safety=overall_risk,
            qwen_categories=detected_categories,
            response_text=response or "",
        )
        if final_shield.is_safe and "非拒答正向白名单保护" in final_shield.matched_rules:
            overall_risk = "Safe"
            cutoff_triggered = False
            cutoff_index = None
            cutoff_reason = None
            safe_prefix_text = target_text
            for ev in token_events:
                ev["risk_level"] = "Safe"
                ev["category"] = "None"
                ev["action"] = "pass"
                ev["blocked_after_cutoff"] = False
        elif not final_shield.is_safe and overall_risk == "Safe":
            overall_risk = final_shield.risk_level
            if cfg.stream_circuit_breaker and not cutoff_triggered and token_events:
                cutoff_triggered = True
                cutoff_index = len(token_events) - 1
                cutoff_reason = f"流式语义围栏触发熔断: {final_shield.tc260_sub_code} {final_shield.tc260_sub_name}"
                token_events[-1]["action"] = "cutoff"
                token_events[-1]["risk_level"] = final_shield.risk_level
                token_events[-1]["category"] = final_shield.tc260_sub_code

        latency_ms = round((time.perf_counter() - t0) * 1000, 2)
        return {
            "is_safe": final_shield.is_safe and overall_risk == "Safe",
            "overall_risk_level": overall_risk,
            "risk_score": final_shield.risk_score,
            "circuit_breaker_triggered": cutoff_triggered,
            "cutoff_token_index": cutoff_index,
            "cutoff_reason": cutoff_reason,
            "safe_prefix_text": safe_prefix_text if cutoff_triggered else target_text,
            "total_tokens_inspected": len(token_events),
            "detected_categories": detected_categories or ([final_shield.tc260_sub_name] if not final_shield.is_safe else []),
            "tc260": {
                "major_code": final_shield.tc260_major_code,
                "major_name": final_shield.tc260_major_name,
                "sub_code": final_shield.tc260_sub_code,
                "sub_name": final_shield.tc260_sub_name,
            },
            "token_stream": token_events,
            "latency_ms": latency_ms,
        }

    def generate_llm_response(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        max_new_tokens: Optional[int] = None,
        temperature: Optional[float] = None,
        enable_thinking: Optional[bool] = None,
        guarded: bool = True,
        cfg: Optional[RuntimeConfig] = None,
    ) -> Dict[str, Any]:
        """Run Qwen3-0.6B dynamic LLM generation with optional 3-stage Guardrail protection."""
        if not self.loaded:
            self.load_all()
        cfg = cfg or config_manager.config
        t0 = time.perf_counter()

        sys_p = system_prompt if system_prompt is not None else cfg.llm_system_prompt
        max_tok = max_new_tokens or cfg.llm_max_new_tokens
        temp = temperature if temperature is not None else cfg.llm_temperature
        thinking = enable_thinking if enable_thinking is not None else cfg.llm_enable_thinking

        # Stage 1: Input Guard (only when guarded=True)
        input_guard = None
        if guarded:
            input_guard = self.detect_with_gen(prompt=prompt, response=None, cfg=cfg)
            if not input_guard["is_safe"]:
                total_ms = round((time.perf_counter() - t0) * 1000, 2)
                return {
                    "guarded": True,
                    "blocked": True,
                    "blocked_stage": "input_guard",
                    "prompt": prompt,
                    "final_response": cfg.safe_fallback_response,
                    "raw_llm_response": None,
                    "llm_self_refused": False,
                    "input_guard": input_guard,
                    "stream_guard": None,
                    "output_guard": None,
                    "latency_ms": total_ms,
                }

        # Stage 2: Qwen3-0.6B Inference
        messages = [
            {"role": "system", "content": sys_p},
            {"role": "user", "content": prompt},
        ]
        try:
            chat_text = self.llm_tokenizer.apply_chat_template(
                messages,
                tokenize=False,
                add_generation_prompt=True,
                enable_thinking=thinking,
            )
        except TypeError:
            chat_text = self.llm_tokenizer.apply_chat_template(
                messages,
                tokenize=False,
                add_generation_prompt=True,
            )

        with self._lock, torch.inference_mode():
            inputs = self.llm_tokenizer([chat_text], return_tensors="pt").to(self.device)
            in_len = inputs.input_ids.shape[1]
            if in_len > 8192:
                raise ValueError("Generation input exceeds 8192-token budget")
            gen_kwargs: Dict[str, Any] = {
                "max_new_tokens": max_tok,
                "eos_token_id": [151645, 151643],
                "pad_token_id": 151643,
            }
            if temp > 0.01:
                gen_kwargs["do_sample"] = True
                gen_kwargs["temperature"] = temp
                gen_kwargs["top_p"] = cfg.llm_top_p
            else:
                gen_kwargs["do_sample"] = False

            out_ids = self.llm_model.generate(**inputs, **gen_kwargs)
            new_ids = out_ids[0][in_len:]
            raw_reply = self.llm_tokenizer.decode(new_ids, skip_special_tokens=True).strip()

        cleaned_reply = re.sub(r"^<think>\s*</think>\s*", "", raw_reply, flags=re.DOTALL).strip()
        self_refused = any(
            kw in cleaned_reply
            for kw in ("抱歉", "无法提供", "不能提供", "不能回答", "无法回答", "作为AI", "无法协助", "不能满足", "I cannot", "I'm sorry", "I am sorry", "can't assist")
        )

        if not guarded:
            total_ms = round((time.perf_counter() - t0) * 1000, 2)
            return {
                "guarded": False,
                "blocked": False,
                "blocked_stage": None,
                "prompt": prompt,
                "final_response": cleaned_reply,
                "raw_llm_response": cleaned_reply,
                "llm_self_refused": self_refused,
                "input_guard": None,
                "stream_guard": None,
                "output_guard": None,
                "latency_ms": total_ms,
            }

        # Stage 3: Stream Guard & Output Guard on generated response
        stream_guard = self.detect_stream_tokens(prompt=prompt, response=cleaned_reply, cfg=cfg)
        output_guard = self.detect_with_gen(prompt=prompt, response=cleaned_reply, cfg=cfg)

        blocked = False
        blocked_stage = None
        final_reply = cleaned_reply

        if stream_guard["circuit_breaker_triggered"]:
            blocked = True
            blocked_stage = "stream_guard"
            prefix = stream_guard.get("safe_prefix_text", "").strip()
            final_reply = (
                f"{prefix}\n\n[⚡ Qwen3Guard-Stream 实时流式熔断：{stream_guard['cutoff_reason']}]"
                if prefix
                else cfg.safe_fallback_response
            )
        elif not output_guard["is_safe"]:
            blocked = True
            blocked_stage = "output_guard"
            final_reply = cfg.safe_fallback_response

        total_ms = round((time.perf_counter() - t0) * 1000, 2)
        return {
            "guarded": True,
            "blocked": blocked,
            "blocked_stage": blocked_stage,
            "prompt": prompt,
            "final_response": final_reply,
            "raw_llm_response": cleaned_reply,
            "llm_self_refused": self_refused or (output_guard["qwen_guard_gen"]["refusal"] == "Yes"),
            "input_guard": input_guard,
            "stream_guard": {
                "is_safe": stream_guard["is_safe"],
                "overall_risk_level": stream_guard["overall_risk_level"],
                "risk_score": stream_guard.get("risk_score", 0.92 if stream_guard["circuit_breaker_triggered"] else 0.05),
                "tc260": stream_guard.get("tc260"),
                "detected_categories": stream_guard.get("detected_categories", []),
                "safe_prefix_text": stream_guard.get("safe_prefix_text", ""),
                "circuit_breaker_triggered": stream_guard["circuit_breaker_triggered"],
                "cutoff_token_index": stream_guard["cutoff_token_index"],
                "cutoff_reason": stream_guard["cutoff_reason"],
                "total_tokens_inspected": stream_guard["total_tokens_inspected"],
                "latency_ms": stream_guard["latency_ms"],
            },
            "output_guard": output_guard,
            "latency_ms": total_ms,
        }


model_manager = ModelManager()
