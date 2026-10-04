from __future__ import annotations


def _grade(value: float) -> str:
    if value >= 0.9: return "very_high"
    if value >= 0.8: return "high"
    if value >= 0.65: return "moderate"
    return "low"


def build_evidence_report(*, priorities: dict | None = None, provenance: dict | None = None,
                          anomalies: dict | None = None, workflow_divergences: dict | None = None) -> dict:
    priority_map={str(x.get("key")):x for x in (priorities or {}).get("targets",[])}; chains=list((provenance or {}).get("chains",[])); items=[]
    for chain in chains:
        start=str(chain.get("start")); matching=priority_map.get(start); chain_conf=float(chain.get("score") or 0); priority_conf=float((matching or {}).get("confidence") or 0)
        hop_conf=[float(h.get("confidence") or 0) for h in chain.get("hops",[])]; weakest=min(hop_conf,default=chain_conf); mean=sum(hop_conf)/len(hop_conf) if hop_conf else chain_conf
        combined=chain_conf if not matching else (chain_conf*0.7+priority_conf*0.3)
        items.append({"title":f"Evidence chain {chain.get('id')}","start":start,"end":chain.get("end"),"confidence":round(chain_conf,4),"confidence_grade":_grade(combined),"combined_confidence":round(combined,4),"weakest_hop_confidence":round(weakest,4),"mean_hop_confidence":round(mean,4),"priority_score":matching.get("score") if matching else None,"priority_confidence":matching.get("confidence") if matching else None,"priority_reasons":matching.get("reasons",[]) if matching else [],"evidence_kinds":chain.get("evidence_kinds",[]),"steps":chain.get("hops",[])})
    items.sort(key=lambda x:(-(float(x.get("priority_score") or 0)),-float(x.get("combined_confidence") or 0),x.get("title") or ""))
    grades={g:sum(1 for x in items if x["confidence_grade"]==g) for g in ("very_high","high","moderate","low")}
    return {"schema_version":"1.1","item_count":len(items),"items":items[:1000],"summary":{"anomaly_count":(anomalies or {}).get("anomaly_count",0),"workflow_divergence_count":(workflow_divergences or {}).get("divergence_count",0),"provenance_chain_count":(provenance or {}).get("chain_count",0),"priority_target_count":(priorities or {}).get("target_count",0),"confidence_grades":grades}}
