"""Reproduce legacy label leakage without loading GPU models or modifying data."""
import ast
import json
import subprocess
import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from app.config import RuntimeConfig
from app.security_shield import SecurityShield


def verify():
    old_source = subprocess.check_output(
        ["git", "show", "305f664:app/security_shield.py"], cwd=ROOT).decode("utf-8")
    module = types.ModuleType("legacy_shield_evidence")
    sys.modules[module.__name__] = module
    # Execute definitions only; skip the old global instance and its data reads.
    parsed = ast.parse(old_source)
    parsed.body = [node for node in parsed.body if not (
        isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == "security_shield"
                                            for target in node.targets))]
    exec(compile(parsed, "<legacy-shield>", "exec"), module.__dict__)
    module.SecurityShield._load_reference_corpus = lambda self: None
    old, new = module.SecurityShield(), SecurityShield()
    prompt = "coverageprobe neutral sentence"
    cfg = RuntimeConfig(custom_block_keywords=[], custom_allow_keywords=[])
    key = old._norm_key(prompt)
    record = {"major_code": "A.1", "major_name": "fixture", "sub_code": "A.1.1",
              "sub_name": "fixture", "attack_method": "无指令攻击"}
    rows = []
    for shield in (old, new):
        shield._reference_unsafe_map = {key: record}
        shield._reference_benign_set = set()
    rows.append({"check": "unsafe_dataset_label_changes_safe_model_decision",
                 "legacy": old.evaluate(prompt, cfg, "Safe", []).is_safe,
                 "current": new.evaluate(prompt, cfg, "Safe", []).is_safe})
    for shield in (old, new):
        shield._reference_unsafe_map = {}
        shield._reference_benign_set = {key}
    rows.append({"check": "benign_dataset_label_overrides_unsafe_model_decision",
                 "legacy": old.evaluate(prompt, cfg, "Unsafe", []).is_safe,
                 "current": new.evaluate(prompt, cfg, "Unsafe", []).is_safe})
    assert rows[0]["legacy"] is False and rows[0]["current"] is True
    assert rows[1]["legacy"] is True and rows[1]["current"] is False
    manager = ast.parse(subprocess.check_output(
        ["git", "show", "305f664:app/model_manager.py"], cwd=ROOT).decode("utf-8"))
    assignment = next(n for n in ast.walk(manager) if isinstance(n, ast.Assign)
                      and any(isinstance(t, ast.Name) and t.id == "self_refused" for t in n.targets))
    mistaken = eval(compile(ast.Expression(assignment.value), "<legacy-refusal>", "eval"),
                   {"cleaned_reply": "抱歉，会议延后到明天，请更新日程。"})
    assert mistaken is True
    rows.append({"check": "apology_is_not_a_safety_refusal", "legacy_refusal_flag": mistaken,
                 "sample": "抱歉，会议延后到明天，请更新日程。",
                 "current": "No compliance score inferred from refusal keywords"})
    old._reference_benign_set = set()
    old._reference_unsafe_map = {}
    before = old.evaluate(prompt, cfg, "Unsafe", []).is_safe
    after = old.evaluate(prompt, cfg.model_copy(update={"custom_allow_keywords": ["coverageprobe"]}), "Unsafe", []).is_safe
    assert before == after == False
    rows.append({"check": "legacy_custom_allow_keywords_is_noop", "before_is_safe": before, "after_is_safe": after,
                 "reason": "Original keyword-matched branch contains pass only"})
    routes = ast.parse((ROOT/"app/legacy_main.py").read_text(encoding="utf-8"))
    stream = next(n for n in routes.body if isinstance(n, ast.AsyncFunctionDef) and n.name == "guard_stream_sse")
    scan_line = min(n.lineno for n in ast.walk(stream) if isinstance(n, ast.Call)
                    and isinstance(n.func, ast.Attribute) and n.func.attr == "detect_stream_tokens")
    yield_line = min(n.lineno for n in ast.walk(stream) if isinstance(n, ast.Yield))
    assert scan_line < yield_line
    rows.append({"check": "legacy_sse_computes_before_replay", "scan_line": scan_line,
                 "first_yield_line": yield_line, "current_mode": "offline_token_diagnostic"})
    return {"baseline_commit": "305f664", "scope": "Deterministic implementation probes, not model quality evaluation",
            "checks": rows}


if __name__ == "__main__":
    result = verify()
    (ROOT/"docs/legacy-semantics-evidence.json").write_text(json.dumps(result, ensure_ascii=False, indent=2)+"\n", encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False, indent=2))
