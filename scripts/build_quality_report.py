"""Independently reconcile every result and produce an honest acceptance report."""
from collections import Counter
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from app.enterprise.quality import summarize
from scripts.quality_acceptance import code_manifest

DIR=ROOT/"docs/quality-acceptance"


def load(name):
    return json.loads((DIR/name).read_text(encoding="utf-8"))


def pct(value):
    return "—" if value is None else f"{100*value:.2f}%"


def main():
    run="postrules"
    manifest=load(f"{run}-manifest.json")
    assert manifest["code_sha256"]==code_manifest(), "Runtime source changed; do not claim a single frozen implementation"
    changes=load("postrules-full-changes.json")
    live=load("postrule-live-verification.json")
    assert live["all_passed"] and live["production_items"]==0
    assert len(live["checks"])==len(changes)==9
    assert {c["case_id"] for c in changes}=={c["case_id"] for c in live["checks"]}
    expected_decisions={c["case_id"]:c["after"] for c in changes}
    assert all(c["passed"] and c["live"]==c["replayed"]==expected_decisions[c["case_id"]]
               for c in live["checks"])
    summary={}
    lines=[
        "# 全量模型质量验收",
        "",
        "本报告区分评测功能验收与模型质量达标。指标是当前模型和策略与原始标签的一致性，"
        "不是独立合规认证。原表存在可确认的标签问题；不自动改标签抬高分数。",
        "",
        "## 数据与审核对象",
        "",
        "- 完整库 1607 条：1000 条回复审核（源表 523 合格、477 不合格）"
        "；607 条输入审核（307 应拒答、300 非拒答）。",
        "- 精选库 142 条全部包含于完整库；两次运行不能算作 1749 个独立样本。",
        "- 原题目、回复和旧标签保留。恢复的质检标签通过新题目版本保存，"
        "来源为原始 Excel 的质检列；输入与回复标签不混用。",
        "- 权重、代码、题目快照及策略版本指纹见目录内 JSON。当前策略："
        f"v{manifest['policy_version']['version']}；Controversial 按配置拦截，PII 动作为 block。",
        "- 全部样本已完成真实 GPU 推理。随后只修复输出规则的局部纠错语境判断，"
        "用同一份不可变模型分类进行全量复判，并对变化样本做真实 GPU 回归。"
        "复判任务明确标记复用模型结果，未冒充第二轮全量 GPU 推理；模板、模型解析、反混淆与权重未变。",
        "",
        "## 实测结果",
        "",
        "| 数据集 | 完成 | 准确率 | 召回率 | 正常放行率 | F1 | FP / FN | 技术错误 |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    reports={}
    for dataset in ("curated","full"):
        report=load(f"{run}-{dataset}-report.json")
        cases=load(f"{run}-{dataset}-cases.json")
        source_report=load(f"source-validated-{dataset}-report.json")
        assert source_report["state"]=="completed"
        assert source_report["completed"]==source_report["total"]==len(cases)
        assert source_report["metrics"]["errors"]==0
        assert report["state"]=="completed" and report["completed"]==len(cases)==report["total"]
        assert sorted(r["position"] for r in report["results"])==list(range(len(cases)))
        assert len({r["id"] for r in report["results"]})==len(cases)
        rows=[r["result"] for r in report["results"]]
        by_key={c["case_key"]:c for c in cases}
        assert len(by_key)==len(cases)
        for row in rows:
            case=by_key[row["case"]["case_id"]]
            target=case.get("evaluation_target","input")
            label=case.get("response_expected_unsafe") if target=="output" else case["expected_unsafe"]
            assert row["case"]["case_revision"]==case["revision"]
            assert row["case"]["evaluation_target"]==target
            assert row["expected_unsafe"]==label
        metrics=summarize(rows,len(cases))
        assert metrics==report["metrics"]
        counted=Counter((r["expected_unsafe"],r["decision"]=="block") for r in rows
                        if r["execution_status"]=="completed" and r["decision"] in ("block","allow","mask"))
        assert [metrics[k] for k in ("tp","tn","fp","fn")]==[
            counted[(True,True)],counted[(False,False)],counted[(False,True)],counted[(True,False)]]
        # Raw model classification is separate from custom rules and PII policy.
        model_rows=[{**r,"decision":("block" if r.get("model_assessment",{}).get("safety") in
                     ("Unsafe","Controversial") else "allow")}
                    for r in rows if r.get("model_assessment",{}).get("safety") in ("Safe","Unsafe","Controversial")]
        model_metrics=summarize(model_rows,len(cases))
        reasons=Counter()
        for r in rows:
            if r.get("passed") is not False:continue
            raw=r.get("model_assessment",{}).get("safety")
            if raw=="Safe" and r.get("decision")=="block":
                reasons["policy_or_rule_disagreement"]+=1
            elif raw=="Controversial":
                reasons["controversial_policy_vs_label"]+=1
            else:
                reasons["model_vs_source_label"]+=1
        summary[dataset]={"metrics":metrics,"raw_model_metrics":model_metrics,
                          "mismatch_sources":dict(reasons),"by_target":report["by_target"],
                          "by_suite":report["by_suite"],"job_id":report["id"],
                          "results_reconciled":True,
                          "original_gpu_metrics":source_report["metrics"]}
        reports[dataset]=report
        m=metrics
        lines.append(f"| {dataset} | {report['completed']}/{report['total']} | {pct(m['accuracy'])} | "
                     f"{pct(m['recall'])} | {pct(m['benign_pass_rate'])} | {pct(m['f1'])} | "
                     f"{m['fp']} / {m['fn']} | {m['errors']} |")
    lines += ["", "FP/FN 均按源标签计算。错误、待复核与未完成项不会计为正常放行；"
              "准确率之外另提供完整通过率、评分覆盖率。不是所有标签不一致都能认定为模型错误。",
              "", "## 完整库按审核对象分层", "",
              "| 对象 | 样本 | 准确率 | 召回率 | 正常放行率 | FP | FN | 错误 |",
              "|---|---:|---:|---:|---:|---:|---:|---:|"]
    for g in reports["full"]["by_target"]:
        lines.append(f"| {g['label']} | {g['total']} | {pct(g['accuracy'])} | {pct(g['recall'])} | "
                     f"{pct(g['benign_pass_rate'])} | {g['fp']} | {g['fn']} | {g['errors']} |")
    lines += ["", "## 本次直接修复的功能", "",
              "1. 原始 Excel 质检列被忽略：恢复来源标签、审核对象及可追溯版本，保留原数据。",
              "2. 输入标签被错误用于回复：题库支持自动/输入/输出模式；外部模型新生成回复无独立标签时不计算准确率。",
              "3. 排版和解码形态被当作恶意证据：Markdown、列表、普通填空等不单独推翻 Safe 判断。",
              "4. 仅提及歧视即拦截：去除纯主题名规则；保留明确自定义拦截词、PII 和恶意指令证据。",
              "5. Controversial 开关被类别映射绕过：分类映射不再覆盖该配置。",
              "6. 安全拒答被敏感词拦截：模型同时给出 Safe 与 Refusal: Yes 时，不再用话题/注入正则否定该拒答；"
              "明确禁用词和 PII 仍执行。普通“抱歉”不再由关键词推断拒答。",
              "7. 分类解析遗漏 Unethical Acts、大小写和子串错误：使用明确字段解析并保留原始模型分类。",
              "8. 执行错误和 review 的计分：补充覆盖率与完整通过率，逐题及分层统计独立核对。",
              "9. 大题库报告不可用：逐题表分页、异常筛选、原始证据展开；按输入/输出与来源题库分层。",
              "10. 离线串行吞吐：增加最多 8 条、16384 padding token 的受控批量推理，"
              "与在线检测共用队列、解析、规则和审计；过大批次退回单条，单条异常保留错误语义。",
              "11. 模型 Safe 的反歧视、辟谣、举报内容引用敏感主题被误拦："
              "只对输出正则增加同句否定/批判语境处理；跨句、转折后的独立危险陈述仍检测，"
              "不能覆盖 Unsafe 模型结论、明确禁用词或 PII。",
              "12. 盗窃规则的正则 alternation 缺少括号，令“技巧”只约束最后一个分支："
              "修复分组后，普通主题提及不再直接拦截，明确技巧请求仍命中。",
              "",
              "最后一轮后处理修复共改变完整库 9 条决策：8 条原误拦转为放行；"
              "bank_1208 的概念性问句也转为放行，但原标签为应拒答，因此计为新增 1 个 FN。"
              "两类变化均保留，没有仅挑选改善分数的变化。精选库结果不变。",
              "", "## 验证与边界", "",
              "- 自动化回归 59 项通过；真实 GPU 单条/批量 8 条对照一致。",
              "- 真实 GPU 专项验证：正常排版放行、危险输入阻断、安全拒答放行、普通道歉不被判为拒答；生产统计未被污染。",
              "- 最终规则变更影响的 9 条样本已全部重新执行真实 GPU 推理，9/9 与复判一致。",
              "- 完整库所有位置、题目版本、标注对象、标签及混淆矩阵已逐项对账。"
              "源标签并非本次模型生成，不进入线上决策。",
              "- 基线及早期输入模式报告因标注对象错误已标记“诊断作废”，保留证据，不能比较为准确率提升。",
              "- 本次全量覆盖 Gen + 规则/PII 决策链路的文本输入与已有回复审核；"
              "Stream/动态生成只有功能回归，不声称所有可能生成内容、客户 API 或多模态均通过质量认证。",
              "- 分类分组是按题库标签汇总二分类结果，不代表模型具有 31 类独立精确分类能力。",
              "", "## 尚不能宣布模型质量达标的原因", "",
              "当前仍有源标签不一致。部分是模型漏检或争议策略差异，部分是源标注本身的问题。"
              "例如 bank_435 的操作性危险回复被原表标为合格，bank_1597 的舞弊请求被放在非拒答库。"
              "这些样本保留原始分数并单独列入复核，不将其自动改为与模型一致。",
              "",
              "下一步需要由业务审核人员复核不一致样本，确定领域阈值，形成独立 holdout；"
              "再评估提示词候选、规则改进或更大模型/微调。没有修改模型权重、按题目 ID 放行、"
              "把已知题库内容写成白名单，或用错误评分制造通过结论。",
              "", "## 可复现证据", "",
              "- [源标签恢复](quality-acceptance/label-provenance.json)",
              "- [完整库报告](quality-acceptance/source-validated-full-report.json)",
              "- [完整库不一致样本](quality-acceptance/source-validated-full-failures.json)",
              "- [规则修复复判报告](quality-acceptance/postrules-full-report.json)",
              "- [复判不一致样本](quality-acceptance/postrules-full-failures.json)",
              "- [精选库报告](quality-acceptance/source-validated-curated-report.json)",
              "- [批量一致性](quality-acceptance/batch-parity.json)",
              "- [真实 GPU 专项回归](quality-acceptance/functional-gpu-probes.json)",
              "- [规则变化样本 GPU 复测](quality-acceptance/postrule-live-verification.json)",
              "- [模型文件指纹](quality-acceptance/model-fingerprints.json)",
              "- [固定版本与快照清单](quality-acceptance/source-validated-manifest.json)",
              "- [最终规则版本及复判来源](quality-acceptance/postrules-manifest.json)",
              ""]
    (DIR/"summary.json").write_text(json.dumps(summary,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    (ROOT/"docs/model-quality-acceptance.md").write_text("\n".join(lines),encoding="utf-8")
    print(json.dumps({k:v["metrics"] for k,v in summary.items()},ensure_ascii=False))


if __name__=="__main__":
    main()
