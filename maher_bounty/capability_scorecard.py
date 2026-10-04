from __future__ import annotations

from collections import defaultdict

CAPABILITIES=("graphql","grpc","openapi","websocket","workflow_identity","generic_http")


def _cap(name: str) -> str:
    n=name.lower()
    if "graphql" in n:return "graphql"
    if "grpc" in n:return "grpc"
    if "openapi" in n:return "openapi"
    if "websocket" in n:return "websocket"
    if "workflow" in n or "identity" in n:return "workflow_identity"
    return "generic_http"


def build_scorecard(summary: dict) -> dict:
    buckets=defaultdict(lambda:{"cases":0,"passed":0,"positive":0,"negative":0})
    for row in summary.get("results",[]):
        cap=_cap(str(row.get("name",""))); b=buckets[cap]; b["cases"]+=1
        b["passed"]+=int(bool(row.get("passed")))
        expected=bool(row.get("classification",{}).get("expected_signal"))
        b["positive" if expected else "negative"]+=1
    quality=summary.get("capability_quality",{})
    scores={}
    for cap in CAPABILITIES:
        b=buckets[cap]; q=quality.get(cap,{})
        pass_rate=b["passed"]/max(1,b["cases"])
        precision=float(q.get("precision",1.0 if not b["positive"] else 0.0))
        recall=float(q.get("recall",1.0 if not b["positive"] else 0.0))
        specificity=float(q.get("specificity",1.0 if not b["negative"] else 0.0))
        score=round(100*(.35*pass_rate+.25*precision+.25*recall+.15*specificity),2)
        scores[cap]={**b,"pass_rate":round(pass_rate,4),"precision":precision,"recall":recall,"specificity":specificity,"score":score}
    overall=round(sum(x["score"] for x in scores.values())/len(scores),2)
    return {"overall_score":overall,"capabilities":scores,"minimum_capability_score":min(x["score"] for x in scores.values())}
