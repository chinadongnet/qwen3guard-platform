"""Project-scoped replacements for the original question bank and diagnostic tools."""
from __future__ import annotations

import csv
import io
import json
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Literal

from fastapi import APIRouter, Query, Request
from fastapi.responses import Response
from pydantic import Field
from sqlalchemy import select

from . import db as t, schemas as s
from .admin import (database, scoped_object, create_evaluation, evaluation_detail,
                    review_incident, OPERATE, EDIT)
from .inference import InferenceTimeout, QueueFull
from .security import project_access, global_admin, fail, redact, rate_limit
from .presets import POLICY_PRESETS

router = APIRouter(prefix="/api/admin/workbench", tags=["题库、调测与报告"])
ROOT = Path(__file__).resolve().parents[2]


def pack(request, value):
    return {"encrypted": request.app.state.cipher.encrypt(json.dumps(value, ensure_ascii=False).encode()).decode()}


def unpack(request, value):
    return json.loads(request.app.state.cipher.decrypt(value["encrypted"].encode()))


def download(value, name, fmt="json"):
    if fmt == "json":
        text, mime = json.dumps(value, ensure_ascii=False, indent=2), "application/json"
    elif fmt == "csv":
        out = io.StringIO()
        rows = value if isinstance(value, list) else value.get("items", [])
        columns = sorted({k for row in rows for k in row})
        writer = csv.DictWriter(out, fieldnames=columns)
        writer.writeheader()
        for row in rows:
            values = {}
            for key, val in row.items():
                val = json.dumps(val, ensure_ascii=False) if isinstance(val, (dict, list)) else str(val if val is not None else "")
                values[key] = "'" + val if val.lstrip().startswith(("=", "+", "-", "@")) else val
            writer.writerow(values)
        text, mime = "\ufeff" + out.getvalue(), "text/csv"
    else:
        text, mime = value, "text/markdown"
    return Response(text, media_type=mime, headers={"Content-Disposition": f'attachment; filename="{name}.{fmt}"'})


class Case(s.StrictModel):
    id: str = Field(default="", max_length=120)
    prompt: str = Field(min_length=1, max_length=8000)
    response: str | None = Field(default=None, max_length=16000)
    expected_unsafe: bool
    response_expected_unsafe: bool | None = None
    evaluation_target: Literal["input", "output"] = "input"
    label_source: str = Field(default="user", max_length=240)
    source_quality_result: str = Field(default="", max_length=120)
    sub_code: str = Field(default="BENIGN", max_length=40)
    sub_name: str = Field(default="", max_length=120)
    major_code: str = Field(default="", max_length=40)
    major_name: str = Field(default="", max_length=120)
    suite: str = Field(default="", max_length=120)
    attack_method: str = Field(default="无指令攻击", max_length=120)
    tag: str = Field(default="", max_length=120)


class Import(s.StrictModel):
    items: list[Case] = Field(min_length=1, max_length=5000)
    dataset: Literal["curated", "full", "custom"] = "custom"


class CaseUpdate(s.StrictModel):
    expected_revision: int = Field(ge=1)
    content: Case


def case_row(request, row):
    content = unpack(request, row["content"])
    expected = content.get("response_expected_unsafe") if content.get("evaluation_target") == "output" else content["expected_unsafe"]
    return {**content, "label_expected_unsafe": expected, "case_key": row["case_key"], "id": row["id"],
            "dataset": row["dataset"], "revision": row["revision"], "archived": row["archived"]}


def import_rows(request, project_id, actor, dataset, items):
    db = database(request)
    count = 0
    # Lock the project to serialize seed/import calls without overwriting edits.
    with db.engine.begin() as conn:
        conn.execute(select(t.projects.c.id).where(t.projects.c.id == project_id).with_for_update()).first()
        existing = set(conn.execute(select(t.cases.c.case_key).where(
            t.cases.c.project_id == project_id, t.cases.c.dataset == dataset)).scalars())
        for item in items:
            value = item.model_dump()
            key = value["id"] or t.ident()
            if key in existing:
                continue
            existing.add(key)
            case_id, content = t.ident(), pack(request, value)
            conn.execute(t.cases.insert().values(id=case_id, created_at=time.time(), project_id=project_id,
                dataset=dataset, case_key=key, revision=1, archived=False, content=content))
            conn.execute(t.case_history.insert().values(id=t.ident(), created_at=time.time(),
                case_id=case_id, revision=1, content=content, actor_id=actor["id"]))
            count += 1
    db.operation(actor["id"], "qbank.import", dataset, project_id, inserted=count, skipped=len(items)-count)
    return {"inserted": count, "skipped": len(items) - count}


@router.post("/banks/seed")
async def seed(request: Request, project_id: str, dataset: Literal["curated", "full"] = "curated"):
    actor = project_access(request, project_id, OPERATE)
    path = ROOT / "data" / ("tc260_cases.json" if dataset == "curated" else "tc260_full_1600.json")
    items = [Case.model_validate(item) for item in json.loads(path.read_text(encoding="utf-8"))["cases"]]
    return import_rows(request, project_id, actor, dataset, items)


@router.post("/cases/import")
async def import_cases(body: Import, request: Request, project_id: str):
    return import_rows(request, project_id, project_access(request, project_id, OPERATE), body.dataset, body.items)


@router.get("/cases")
async def list_cases(request: Request, project_id: str, dataset: str = "curated", search: str = "",
                     sub_code: str = "", attack_method: str = "", expected_unsafe: bool | None = None,
                     archived: bool = False, offset: int = Query(0, ge=0), limit: int = Query(30, ge=1, le=5000)):
    project_access(request, project_id)
    rows = database(request).all(select(t.cases).where(t.cases.c.project_id == project_id,
        t.cases.c.dataset == dataset, t.cases.c.archived.is_(archived)).order_by(t.cases.c.created_at))
    items = [case_row(request, row) for row in rows]
    items = [item for item in items if (not search or search.lower() in json.dumps(item, ensure_ascii=False).lower())
             and (not sub_code or item["sub_code"].startswith(sub_code))
             and (not attack_method or item["attack_method"] == attack_method)
             and (expected_unsafe is None or item["label_expected_unsafe"] == expected_unsafe)]
    return {"total": len(items), "items": items[offset:offset+limit],
            "stats": {"unsafe": sum(i["label_expected_unsafe"] is True for i in items),
                      "benign": sum(i["label_expected_unsafe"] is False for i in items),
                      "unlabeled": sum(i["label_expected_unsafe"] is None for i in items),
                      "subcategories": len({i["sub_code"] for i in items if i["sub_code"].startswith("A.")}),
                      "by_subcategory": dict(Counter(i["sub_code"] for i in items)),
                      "by_attack": dict(Counter(i["attack_method"] for i in items))}}


@router.get("/cases/export")
async def export_cases(request: Request, project_id: str, dataset: str = "curated"):
    result = await list_cases(request, project_id, dataset, offset=0, limit=5000)
    database(request).operation(request.state.user["id"], "qbank.export", dataset, project_id)
    return download(result, "question-bank")


@router.put("/cases/{case_id}")
async def update_case(case_id: str, body: CaseUpdate, request: Request):
    row = scoped_object(request, t.cases, case_id, OPERATE)
    value = body.content.model_dump()
    value["id"] = row["case_key"]
    content = pack(request, value)
    with database(request).engine.begin() as conn:
        changed = conn.execute(t.cases.update().where(t.cases.c.id == case_id,
            t.cases.c.revision == body.expected_revision).values(
                revision=body.expected_revision+1, content=content))
        if changed.rowcount != 1:
            fail(409, "revision_conflict", "题目已被修改，请刷新后重试")
        conn.execute(t.case_history.insert().values(id=t.ident(), created_at=time.time(),
            case_id=case_id, revision=body.expected_revision+1, content=content, actor_id=request.state.user["id"]))
    database(request).operation(request.state.user["id"], "qbank.update", case_id, row["project_id"])
    return {"revision": body.expected_revision+1}


@router.get("/cases/{case_id}/history")
async def case_versions(case_id: str, request: Request):
    scoped_object(request, t.cases, case_id)
    rows = database(request).all(select(t.case_history).where(t.case_history.c.case_id == case_id)
                                .order_by(t.case_history.c.revision.desc()))
    return {"items": [{**row, "content": unpack(request, row["content"])} for row in rows]}


@router.put("/cases/{case_id}/archived")
async def archive_case(case_id: str, body: s.Enabled, request: Request):
    row = scoped_object(request, t.cases, case_id, OPERATE)
    with database(request).engine.begin() as conn:
        conn.execute(t.cases.update().where(t.cases.c.id == case_id).values(archived=body.enabled))
    database(request).operation(request.state.user["id"], "qbank.archive", case_id, row["project_id"], archived=body.enabled)
    return {"ok": True}


class BankEvaluation(s.StrictModel):
    application_id: str
    dataset: Literal["curated", "full", "custom"] = "curated"
    case_ids: list[str] = Field(default_factory=list, max_length=5000)
    policy_version: int | None = None
    idempotency_key: str = Field(min_length=8, max_length=128)
    mode: Literal["text", "generation_compare"] = "text"
    target: Literal["auto", "input", "output"] = "auto"
    sample_count: int | None = Field(default=None, ge=1, le=5000)


@router.post("/banks/evaluate", status_code=202)
async def evaluate_bank(body: BankEvaluation, request: Request, project_id: str):
    project_access(request, project_id, OPERATE)
    data = await list_cases(request, project_id, body.dataset, offset=0, limit=5000)
    items = data["items"]
    if body.case_ids:
        selected = set(body.case_ids)
        items = [i for i in items if i["id"] in selected]
        if {i["id"] for i in items} != selected:
            fail(404, "case_missing", "所选题目不存在、已归档或不属于该题库")
    if not items:
        fail(422, "empty_bank", "题库没有可评测题目，请先导入")
    if body.sample_count:
        items = items[:body.sample_count]
    if body.mode == "generation_compare" and len(items) > 50:
        fail(422, "generation_batch_limit", "批量生成对比单任务最多 50 条，请选择题目或设置样本量")
    def target(item):
        return item.get("evaluation_target", "input") if body.target == "auto" else body.target
    if any(target(i) == "output" and not i.get("response") for i in items):
        fail(422, "response_missing", "输出审核需要每道题均有回复内容，请选择有回复的题目")
    target_label = {"auto":"按标注对象审核", "input":"输入审核", "output":"输出审核"}[body.target]
    payload = s.EvaluationCreate(name=f"{body.dataset} {target_label}回归（{len(items)} 条）",
        application_id=body.application_id, policy_version=body.policy_version,
        idempotency_key=body.idempotency_key, items=[
            s.EvaluationItem(prompt=i["prompt"], response=(i.get("response") or None) if target(i) == "output" else None,
                expected_unsafe=(i.get("response_expected_unsafe") if target(i) == "output"
                                 else i["expected_unsafe"] if i.get("evaluation_target", "input") == "input" else None),
                case_id=i["case_key"], case_revision=i["revision"],
                sub_code=i["sub_code"], attack_method=i["attack_method"], mode=body.mode,
                evaluation_target=target(i), label_source=i.get("label_source", "legacy_suite_derived"),
                suite=i.get("suite", "")) for i in items])
    return await create_evaluation(payload, request, project_id)


@router.get("/presets")
async def presets(request: Request, project_id: str):
    project_access(request, project_id)
    names = ["标准回归配置", "政务 / 金融严格配置", "教育 / 学术防误报配置", "流式诊断配置"]
    items = []
    for index, preset in enumerate(POLICY_PRESETS.values()):
        cfg = {k: v for k, v in preset["config"].items() if k in s.PolicyConfig.model_fields}
        items.append({"id": preset["id"], "name": names[index], "config": s.PolicyConfig(**cfg).model_dump()})
    return {"items": items, "defaults": s.PolicyConfig().model_dump(),
            "notice": "预设是可调配置，不保证准确率、合规率或延迟；保存为策略草稿后评测发布。"}


class Lab(s.StrictModel):
    application_id: str
    prompt: str = Field(min_length=1, max_length=8000)
    response: str | None = Field(default=None, max_length=16000)
    config: s.PolicyConfig | None = None


def lab_context(body, request):
    app = scoped_object(request, t.apps, body.application_id, OPERATE)
    rate_limit(database(request), "lab:" + app["project_id"], 10)
    if not app["enabled"]:
        fail(403, "application_disabled", "应用已停用")
    return app, request.app.state.service.policy(app)


async def bounded(request, function, timeout=60):
    try:
        return await request.app.state.pool.run(function, timeout=timeout)
    except QueueFull:
        fail(503, "inference_overloaded", "推理队列已满")
    except InferenceTimeout:
        fail(504, "inference_timeout", "实验超过时限")
    except ValueError:
        fail(422, "input_not_supported", "实验内容超过模型预算或格式不支持")
    except Exception:
        fail(503, "experiment_failed", "实验未完成，请检查模型状态")


def save_run(request, app, kind, value):
    row = database(request).insert(t.lab_runs, project_id=app["project_id"], application_id=app["id"],
                                   kind=kind, content=pack(request, value))
    database(request).operation(request.state.user["id"], "lab."+kind, row["id"], app["project_id"])
    return {"run_id": row["id"], **value}


@router.post("/prompt-preview")
async def prompt_preview(body: Lab, request: Request):
    app, version = lab_context(body, request)
    from app.config import RuntimeConfig
    from app.prompting import build_guard_gen_prompt
    cfg = (body.config or s.PolicyConfig(**version["config"])).model_dump()
    return {"rendered_prompt": build_guard_gen_prompt(body.prompt, body.response, RuntimeConfig(**cfg)),
            "policy_version": version["version"]}


@router.post("/ab-test")
async def ab_test(body: Lab, request: Request):
    app, version = lab_context(body, request)
    if body.config is None:
        fail(422, "candidate_required", "请提供候选配置")
    async def run(cfg):
        result = await bounded(request, lambda: request.app.state.models.detect(
            redact(body.prompt), redact(body.response) if body.response else None, cfg), cfg["timeout_seconds"])
        from .security import pii_findings
        findings = pii_findings(body.response if body.response is not None else body.prompt)
        decision = "allow" if result["is_safe"] else "block"
        if findings and cfg["pii_action"] == "block":
            decision = "block"
        elif findings and cfg["pii_action"] == "mask" and decision == "allow":
            decision = "mask"
        return {**result, "decision": decision, "findings": findings, "is_safe": decision == "allow"}
    baseline_cfg = s.PolicyConfig(**version["config"]).model_dump()
    candidate_cfg = body.config.model_dump()
    baseline, candidate = await run(baseline_cfg), await run(candidate_cfg)
    return save_run(request, app, "ab_test", {"baseline": baseline, "candidate": candidate,
        "baseline_version": version["version"], "candidate_config": candidate_cfg,
        "notice": "实验结果不发布策略、不计生产指标；输入脱敏后比较相同内容。"})


@router.post("/token-scan")
async def token_scan(body: Lab, request: Request):
    app, version = lab_context(body, request)
    cfg = (body.config or s.PolicyConfig(**version["config"])).model_dump()
    result = await bounded(request, lambda: request.app.state.models.scan(
        redact(body.prompt), redact(body.response) if body.response else None, cfg), cfg["timeout_seconds"])
    return save_run(request, app, "token_scan", {"result": result, "mode": "offline_token_diagnostic",
        "notice": "完整文本上的真实 Stream 模型 Token 诊断；逐项展示是回放，不是在线生成时序。"})


@router.post("/compare-generation")
async def compare_generation(body: Lab, request: Request):
    app, version = lab_context(body, request)
    if body.config is not None:
        fail(422, "published_policy_required", "生成对比使用已发布策略；候选配置请先进行 A/B 调测")
    cfg = s.PolicyConfig(**version["config"]).model_dump()
    raw = await bounded(request, lambda: request.app.state.models.raw_generation(redact(body.prompt), cfg), 120)
    text = raw.get("final_response", "")
    if not text:
        fail(503, "empty_generation", "模型没有生成可审核文本")
    input_result = await request.app.state.service.detect(app, None, body.prompt, None,
        request.state.request_id, source="evaluation", endpoint="lab_compare_input", version=version)
    output_result = await request.app.state.service.detect(app, None, body.prompt, text,
        request.state.request_id, source="evaluation", endpoint="lab_compare_output", version=version)
    scan = await bounded(request, lambda: request.app.state.models.scan(body.prompt, text, cfg), cfg["timeout_seconds"])
    blocked = input_result["decision"] != "allow" or output_result["decision"] not in ("allow", "mask") or not scan["is_safe"]
    return save_run(request, app, "compare_generation", {"raw_response": redact(text),
        "guarded_response": cfg["safe_fallback_response"] if blocked else output_result.get("sanitized_content", redact(text)),
        "blocked": blocked, "input_guard": input_result, "output_guard": output_result, "stream_guard": scan,
        "policy_version": version["version"],
        "notice": "授权实验室中的同一生成结果前后对比；原始输出不作为业务网关返回，不以拒答关键词推断合规。"})


@router.get("/runs")
async def runs(request: Request, project_id: str):
    project_access(request, project_id)
    rows = database(request).all(select(t.lab_runs).where(t.lab_runs.c.project_id == project_id)
                                .order_by(t.lab_runs.c.created_at.desc()).limit(50))
    return {"items": [{k: v for k, v in row.items() if k != "content"} for row in rows]}


@router.get("/runs/{run_id}")
async def run_detail(run_id: str, request: Request):
    row = scoped_object(request, t.lab_runs, run_id)
    return {**{k: v for k, v in row.items() if k != "content"}, "result": unpack(request, row["content"])}


@router.post("/detections/{event_id}/promote")
async def promote(event_id: str, body: Case, request: Request):
    event = scoped_object(request, t.events, event_id, OPERATE)
    # Explicit edited sample/label, never silently infer ground truth from model output.
    body.id = "audit-" + event_id
    return import_rows(request, event["project_id"], request.state.user, "custom", [body])


@router.get("/detections/{event_id}/original")
async def original(event_id: str, request: Request):
    event = scoped_object(request, t.events, event_id, ("admin", "operator", "auditor"))
    record = database(request).one(select(t.event_payloads).where(
        t.event_payloads.c.event_id == event_id, t.event_payloads.c.expires_at > time.time()))
    if not record:
        fail(410, "original_unavailable", "该记录未保留原文或已超过保留期限；脱敏审计仍可查询")
    database(request).operation(request.state.user["id"], "audit.original_read", event_id, event["project_id"])
    return {"event_id": event_id, "expires_at": record["expires_at"], **unpack(request, record["content"])}


@router.post("/detections/{event_id}/review")
async def review_detection(event_id: str, body: s.Review, request: Request):
    event = scoped_object(request, t.events, event_id, OPERATE)
    db = database(request)
    with db.engine.begin() as conn:
        conn.execute(select(t.events.c.id).where(t.events.c.id == event_id).with_for_update()).first()
        incident = conn.execute(select(t.incidents).where(t.incidents.c.event_id == event_id)).mappings().first()
        if not incident:
            incident = {"id": t.ident()}
            conn.execute(t.incidents.insert().values(id=incident["id"], created_at=time.time(),
                project_id=event["project_id"], event_id=event_id, state="open", assignee="", severity="medium"))
    return await review_incident(incident["id"], body, request)


class AuditSelection(s.StrictModel):
    ids: list[str] = Field(min_length=1, max_length=500)
    archived: bool = True


@router.post("/audit/archive")
async def archive_audit(body: AuditSelection, request: Request, project_id: str):
    actor = project_access(request, project_id, EDIT)
    db = database(request)
    rows = db.all(select(t.events.c.id).where(t.events.c.project_id == project_id, t.events.c.id.in_(body.ids)))
    if {r["id"] for r in rows} != set(body.ids):
        fail(404, "not_found", "包含不存在或无权处理的记录")
    with db.engine.begin() as conn:
        for row in rows:
            conn.execute(t.audit_archives.delete().where(t.audit_archives.c.event_id == row["id"]))
            if body.archived:
                conn.execute(t.audit_archives.insert().values(id=t.ident(), created_at=time.time(),
                    event_id=row["id"], project_id=project_id, actor_id=actor["id"]))
    db.operation(actor["id"], "audit.archive" if body.archived else "audit.restore", project_id, project_id, count=len(rows))
    return {"affected": len(rows), "notice": "归档可恢复；保留原始审计和指标，不清空账本"}


@router.get("/audit/export")
async def export_audit(request: Request, project_id: str, format: Literal["json", "csv"] = "json",
                       application_id: str = "", key_id: str = "", source: str = "", decision: str = ""):
    actor = project_access(request, project_id, ("admin", "operator", "auditor"))
    stmt = select(t.events).where(t.events.c.project_id == project_id)
    for column, value in ((t.events.c.application_id, application_id), (t.events.c.key_id, key_id),
                          (t.events.c.source, source), (t.events.c.decision, decision)):
        if value:
            stmt = stmt.where(column == value)
    rows = database(request).all(stmt.order_by(t.events.c.created_at).limit(10001))
    if len(rows) > 10000:
        fail(422, "export_limit", "请按应用或凭证缩小导出范围（上限 10000 条）")
    database(request).operation(actor["id"], "audit.export", project_id, project_id, count=len(rows))
    return download(rows, "audit", format)


def breakdown(results, key):
    from .quality import summarize
    groups = defaultdict(list)
    for row in results:
        result = row["result"]
        groups[(result.get("case") or {}).get(key) or "未分类"].append(result)
    return [{"label": label, "total": len(rows), **summarize(rows),
             "passed": sum(r.get("passed") is True for r in rows)} for label, rows in groups.items()]


@router.get("/reports/{job_id}")
async def report(job_id: str, request: Request):
    value = await evaluation_detail(job_id, request)
    value["by_subcategory"] = breakdown(value["results"], "sub_code")
    value["by_attack"] = breakdown(value["results"], "attack_method")
    value["by_target"] = breakdown(value["results"], "evaluation_target")
    value["by_suite"] = breakdown(value["results"], "suite")
    return value


@router.get("/reports/{job_id}/export")
async def export_report(job_id: str, request: Request, format: Literal["json", "csv", "md"] = "md"):
    value = await report(job_id, request)
    database(request).operation(request.state.user["id"], "report.export", job_id, value["project_id"])
    if format == "md":
        text = "# 审核评测报告\n\n" + "\n".join(f"- {key}: {value[key]}" for key in
            ("id", "name", "state", "total", "completed", "dataset_hash", "policy_version_id"))
        text += "\n\n自动评测，非独立合规认证。\n\n## 指标\n\n```json\n" + json.dumps(value["metrics"], ensure_ascii=False, indent=2) + "\n```\n"
        for title, field in (("审核对象", "by_target"), ("来源题库", "by_suite"),
                             ("风险分类", "by_subcategory"), ("攻击方法", "by_attack")):
            text += f"\n## {title}\n\n| 类别 | 样本 | 已标注 | 通过 | 错误 |\n|---|---:|---:|---:|---:|\n"
            text += "\n".join(f"| {r['label'].replace('|', '/')} | {r['total']} | {r['labeled']} | {r['passed']} | {r['errors']} |" for r in value[field])
        return download(text, "evaluation-report", "md")
    return download(value if format == "json" else [r["result"] for r in value["results"]], "evaluation-report", format)


@router.get("/history/benchmark")
async def historical(request: Request):
    global_admin(request)
    data = json.loads((ROOT / "data/benchmark_latest.json").read_text(encoding="utf-8"))
    # Retain the original report as historical evidence, never as current metrics.
    return {"historical_only": True, "notice": "旧版报告曾受样本匹配覆盖影响，不能代表当前模型独立准确率。",
            "report": data}


@router.post("/deobfuscate")
async def deobfuscate(body: s.InputRequest, request: Request, project_id: str):
    project_access(request, project_id, OPERATE)
    from app.security_shield import security_shield
    text, methods = security_shield.deobfuscate_and_unwrap(body.text)
    return {"text": redact(text), "methods": methods, "notice": "文本转换，不代表安全判定"}


@router.get("/audit/summary")
async def audit_summary(request: Request, project_id: str, source: str = "production"):
    project_access(request, project_id)
    from sqlalchemy import func, case
    rows = database(request).all(select(t.events.c.key_id, func.count().label("total"),
        func.sum(case((t.events.c.decision == "block", 1), else_=0)).label("blocked"),
        func.sum(case((t.events.c.execution_status != "completed", 1), else_=0)).label("errors")
        ).where(t.events.c.project_id == project_id, t.events.c.source == source).group_by(t.events.c.key_id))
    keys = database(request).all(select(t.keys.c.id, t.keys.c.prefix, t.keys.c.name)
        .join(t.apps, t.apps.c.id == t.keys.c.application_id).where(t.apps.c.project_id == project_id))
    lookup = {k["id"]: k for k in keys}
    return {"source": source, "items": [{**r, "key_name": lookup.get(r["key_id"], {}).get("name", "控制台 / 无凭证"),
        "key_prefix": lookup.get(r["key_id"], {}).get("prefix", "")} for r in rows]}
