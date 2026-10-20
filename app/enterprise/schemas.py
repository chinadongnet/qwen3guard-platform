from __future__ import annotations

from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from app.config import (DEFAULT_SAFETY_POLICY_INPUT, DEFAULT_SAFETY_POLICY_OUTPUT,
                        DEFAULT_UNSAFE_CATEGORIES, DEFAULT_CUSTOM_GUARD_RULES, DEFAULT_LLM_SYSTEM_PROMPT)


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class Login(StrictModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=False)
    username: str = Field(min_length=1, max_length=120)
    password: str = Field(min_length=1, max_length=256)

    @field_validator("username")
    @classmethod
    def normalize_username(cls, value):
        if not value.strip():
            raise ValueError("用户名不能为空")
        return value.strip()


class PasswordChange(StrictModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=False)
    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=8, max_length=256)
    confirm_password: str = Field(min_length=8, max_length=256)

    @model_validator(mode="after")
    def validate_password(self):
        if not self.new_password.strip():
            raise ValueError("密码不能为空白字符")
        if self.new_password != self.confirm_password:
            raise ValueError("两次输入的新密码不一致")
        return self


class Named(StrictModel):
    name: str = Field(min_length=1, max_length=120)


class Enabled(StrictModel):
    enabled: bool


class UserCreate(Login):
    password: str = Field(min_length=12, max_length=256)


class Membership(StrictModel):
    user_id: str
    role: Literal["admin", "operator", "developer", "auditor"]


class PolicyConfig(StrictModel):
    guard_gen_safety_policy_input: str = Field(default=DEFAULT_SAFETY_POLICY_INPUT, max_length=6000)
    guard_gen_safety_policy_output: str = Field(default=DEFAULT_SAFETY_POLICY_OUTPUT, max_length=6000)
    guard_gen_unsafe_categories: str = Field(default=DEFAULT_UNSAFE_CATEGORIES, max_length=4000)
    guard_gen_custom_rules: str = Field(default=DEFAULT_CUSTOM_GUARD_RULES, max_length=4000)
    guard_gen_max_new_tokens: int = Field(default=24, ge=8, le=128)
    guard_gen_temperature: float = Field(default=0, ge=0, le=1.5)
    stream_unsafe_threshold: float = Field(default=.5, ge=.05, le=.99)
    stream_controversial_as_unsafe: bool = True
    stream_circuit_breaker: bool = True
    stream_window_check_interval: int = Field(default=3, ge=1, le=32)
    category_weights: dict[str, float] = Field(default_factory=lambda: {
        "A.1": 1, "A.2": .9, "A.3": .85, "A.4": .9, "A.5": .85, "JAILBREAK": .95, "PII": .85})
    llm_system_prompt: str = Field(default=DEFAULT_LLM_SYSTEM_PROMPT, max_length=4000)
    llm_max_new_tokens: int = Field(default=160, ge=16, le=512)
    llm_temperature: float = Field(default=.6, ge=0, le=1.5)
    llm_top_p: float = Field(default=.9, ge=.1, le=1)
    llm_enable_thinking: bool = False
    safe_fallback_response: str = Field(default="该内容已被安全策略拦截。", min_length=1, max_length=2000)
    risk_threshold: float = Field(default=0.5, ge=0.05, le=0.99)
    controversial_as_unsafe: bool = True
    enable_deobfuscation: bool = True
    enable_jailbreak_shield: bool = True
    enable_tc260_semantic_shield: bool = True
    pii_action: Literal["block", "mask", "audit"] = "block"
    custom_block_keywords: list[str] = Field(default_factory=list, max_length=100)
    timeout_seconds: float = Field(default=30, ge=1, le=120)
    stream_window_chars: int = Field(default=48, ge=16, le=256)
    failure_action: Literal["block", "review"] = "block"

    @field_validator("category_weights")
    @classmethod
    def weights(cls, values):
        if any(k not in ("A.1", "A.2", "A.3", "A.4", "A.5", "JAILBREAK", "PII")
               or not 0 <= v <= 2 for k, v in values.items()):
            raise ValueError("风险权重无效")
        return values
    @field_validator("custom_block_keywords")
    @classmethod
    def keywords(cls, values):
        if any(not v.strip() or len(v) > 200 for v in values):
            raise ValueError("关键词须为 1～200 字符")
        return list(dict.fromkeys(values))


class PolicyCreate(Named):
    config: PolicyConfig = Field(default_factory=PolicyConfig)


class Publish(StrictModel):
    version: int = Field(ge=1)
    expected_current: int = Field(ge=0)


class ApplicationCreate(Named):
    environment: Literal["production", "sandbox"] = "sandbox"
    policy_id: str


class KeyCreate(Named):
    expires_days: int = Field(default=90, ge=1, le=365)
    rpm: int = Field(default=60, ge=1, le=10000)
    scopes: list[Literal["detect", "chat", "audit:read"]] = Field(default_factory=lambda: ["detect"])


class Message(StrictModel):
    role: Literal["system", "user", "assistant", "tool"]
    content: str = Field(min_length=1, max_length=16000)


class Detect(StrictModel):
    prompt: str = Field(default="", max_length=16000)
    response: str | None = Field(default=None, max_length=32000)
    messages: list[Message] = Field(default_factory=list, max_length=50)
    content_type: Literal["text"] = "text"
    include_stream_tokens: bool = False

    @model_validator(mode="after")
    def meaningful(self):
        if not self.prompt and not self.messages:
            raise ValueError("prompt 或 messages 至少提供一项")
        if sum(len(m.content) for m in self.messages) + len(self.prompt) + len(self.response or "") > 48000:
            raise ValueError("总内容不能超过 48000 字符")
        return self

    def context(self):
        context = "\n".join(f"{m.role}: {m.content}" for m in self.messages)
        return "\n".join(x for x in (context, self.prompt) if x)


class InputRequest(StrictModel):
    text: str = Field(min_length=1, max_length=16000)


class OutputRequest(StrictModel):
    prompt: str = Field(default="", max_length=16000)
    text: str = Field(min_length=1, max_length=32000)


class BatchRequest(StrictModel):
    items: list[Detect] = Field(min_length=1, max_length=50)


class Chat(StrictModel):
    messages: list[Message] = Field(min_length=1, max_length=50)
    model: Literal["Qwen3-0.6B-Guarded"] = "Qwen3-0.6B-Guarded"
    stream: bool = False
    max_tokens: int = Field(default=256, ge=1, le=512)
    temperature: float = Field(default=0.6, ge=0, le=1.5)
    guarded: Literal[True] = True

    @model_validator(mode="after")
    def limit(self):
        if sum(len(m.content) for m in self.messages) > 16000:
            raise ValueError("会话总长度不能超过 16000 字符")
        if not any(m.role == "user" for m in self.messages):
            raise ValueError("至少提供一条 user 消息")
        return self


class EndpointCreate(Named):
    url: str = Field(min_length=8, max_length=2048)
    model: str = Field(min_length=1, max_length=160)
    credential: str = Field(default="", max_length=512)


class EvaluationItem(StrictModel):
    prompt: str = Field(min_length=1, max_length=8000)
    response: str | None = Field(default=None, max_length=16000)
    expected_unsafe: bool | None = None
    case_id: str | None = Field(default=None, max_length=120)
    case_revision: int | None = None
    sub_code: str = Field(default="", max_length=40)
    attack_method: str = Field(default="", max_length=120)
    mode: Literal["text", "generation_compare"] = "text"
    evaluation_target: Literal["input", "output"] | None = None
    label_source: str = Field(default="caller", max_length=240)
    suite: str = Field(default="", max_length=120)


class EvaluationCreate(Named):
    application_id: str
    endpoint_id: str | None = None
    policy_version: int | None = Field(default=None, ge=1)
    items: list[EvaluationItem] = Field(min_length=1, max_length=5000)
    idempotency_key: str = Field(min_length=8, max_length=128)


class Review(StrictModel):
    state: Literal["open", "investigating", "resolved", "false_positive"]
    assignee: str = Field(default="", max_length=120)
    note: str = Field(min_length=1, max_length=2000)


class HookCreate(StrictModel):
    url: str = Field(min_length=8, max_length=2048)


class PolicyRef(BaseModel):
    id: str
    version: int


class ModelRef(BaseModel):
    id: str
    revision: str


class Finding(BaseModel):
    type: str
    start: int
    end: int


class DetectionResult(BaseModel):
    request_id: str
    audit_id: str
    execution_status: Literal["completed", "timeout", "error"]
    decision: Literal["allow", "block", "mask", "review"]
    action: Literal["allow", "block", "mask", "review"]
    is_safe: bool
    risk_level: str
    risk_score: float | None
    score_kind: Literal["policy_score"]
    findings: list[Finding]
    policy: PolicyRef
    model: ModelRef
    model_assessment: dict = Field(default_factory=dict)
    timings_ms: dict[str, float | None]
    tc260: dict | None = None
    matched_rules: list[str] = Field(default_factory=list)
    sanitized_content: str | None = None
    stream_diagnostic: dict | None = None


class LegacyResult(DetectionResult):
    allowed: bool
    sanitized_text: str
