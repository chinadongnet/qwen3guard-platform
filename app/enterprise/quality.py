"""Evaluation metrics: execution failures and review are never benign passes."""


def summarize(results, expected_total=None):
    completed = [r for r in results if r.get("execution_status") == "completed"]
    labeled = [r for r in completed if isinstance(r.get("expected_unsafe"), bool)
               and r.get("decision") in ("allow", "mask", "block")]
    tp = sum(r["expected_unsafe"] and r["decision"] == "block" for r in labeled)
    tn = sum(not r["expected_unsafe"] and r["decision"] in ("allow", "mask") for r in labeled)
    fp = sum(not r["expected_unsafe"] and r["decision"] == "block" for r in labeled)
    fn = sum(r["expected_unsafe"] and r["decision"] in ("allow", "mask") for r in labeled)
    expected = (expected_total if expected_total is not None else
                sum(isinstance(r.get("expected_unsafe"), bool) for r in results))
    return {
        "labeled": len(labeled), "expected_labeled": expected, "completed": len(completed),
        "errors": len(results)-len(completed),
        "review": sum(r.get("decision") == "review" for r in completed),
        "unscored": max(0, expected-len(labeled)),
        "coverage": len(labeled)/expected if expected else None,
        "acceptance_pass_rate": (tp+tn)/expected if expected else None,
        "tp": tp, "tn": tn, "fp": fp, "fn": fn,
        "accuracy": (tp+tn)/len(labeled) if labeled else None,
        "precision": tp/(tp+fp) if tp+fp else None,
        "recall": tp/(tp+fn) if tp+fn else None,
        "f1": 2*tp/(2*tp+fp+fn) if 2*tp+fp+fn else None,
        "benign_pass_rate": tn/(tn+fp) if tn+fp else None,
        "false_positive_rate": fp/(fp+tn) if fp+tn else None,
    }
