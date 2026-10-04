from __future__ import annotations

from collections import defaultdict


def _capability(name: str) -> str:
    name = name.lower()
    if "graphql" in name: return "graphql"
    if "grpc" in name: return "grpc"
    if "openapi" in name: return "openapi"
    if "websocket" in name: return "websocket"
    if "identity" in name or "workflow" in name: return "workflow_identity"
    return "generic_http"


def capability_quality(results: list[dict]) -> dict:
    buckets: dict[str, dict[str, int]] = defaultdict(lambda: {"tp":0,"fp":0,"tn":0,"fn":0})
    for row in results:
        capability = _capability(str(row.get("name", "unknown")))
        expected = bool(row.get("classification", {}).get("expected_signal"))
        observed = bool(row.get("classification", {}).get("observed_signal"))
        key = "tp" if expected and observed else "fn" if expected else "fp" if observed else "tn"
        buckets[capability][key] += 1
    out = {}
    for capability, counts in sorted(buckets.items()):
        tp,fp,tn,fn=(counts[k] for k in ("tp","fp","tn","fn"))
        out[capability]={**counts,"support":tp+fp+tn+fn,"positive_support":tp+fn,"negative_support":tn+fp,
            "precision":round(tp/max(1,tp+fp),4),"recall":round(tp/max(1,tp+fn),4),
            "specificity":round(tn/max(1,tn+fp),4),"false_positive_rate":round(fp/max(1,fp+tn),4)}
    return out


def quality_gate(summary: dict, *, min_precision: float=0.90, min_recall: float=0.90, max_fpr: float=0.10) -> dict:
    quality=summary.get("quality",{}); capabilities=summary.get("capability_quality",{})
    checks={"precision":float(quality.get("precision",0.0))>=min_precision,
            "recall":float(quality.get("recall",0.0))>=min_recall,
            "false_positive_rate":float(quality.get("false_positive_rate",1.0))<=max_fpr,
            "all_cases_pass":int(summary.get("failed",1))==0}
    per_capability={}
    for name,metrics in capabilities.items():
        cap_checks={}
        if int(metrics.get("positive_support",0)):
            cap_checks["recall"]=float(metrics.get("recall",0.0))>=min_recall
            cap_checks["precision"]=float(metrics.get("precision",0.0))>=min_precision
        if int(metrics.get("negative_support",0)):
            cap_checks["false_positive_rate"]=float(metrics.get("false_positive_rate",1.0))<=max_fpr
        per_capability[name]={"passed":all(cap_checks.values()) if cap_checks else True,"checks":cap_checks}
    checks["all_capabilities_pass"]=all(v["passed"] for v in per_capability.values())
    return {"passed":all(checks.values()),"checks":checks,"per_capability":per_capability,
            "thresholds":{"min_precision":min_precision,"min_recall":min_recall,"max_fpr":max_fpr}}
