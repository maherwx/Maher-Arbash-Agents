from __future__ import annotations


def compare_quality(current: dict, baseline: dict, *, tolerance: float = 0.0) -> dict:
    """Fail-closed comparison for benchmark quality metrics across revisions."""
    c=current.get("quality",{}); b=baseline.get("quality",{})
    metrics={}
    for name in ("precision","recall","specificity"):
        cv=float(c.get(name,0.0)); bv=float(b.get(name,0.0))
        metrics[name]={"current":cv,"baseline":bv,"delta":round(cv-bv,4),"passed":cv+tolerance>=bv}
    cf=float(c.get("false_positive_rate",1.0)); bf=float(b.get("false_positive_rate",1.0))
    metrics["false_positive_rate"]={"current":cf,"baseline":bf,"delta":round(cf-bf,4),"passed":cf<=bf+tolerance}
    return {"passed":all(x["passed"] for x in metrics.values()),"tolerance":tolerance,"metrics":metrics}
