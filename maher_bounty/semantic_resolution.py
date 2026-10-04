from __future__ import annotations


def rank_call_candidates(caller: dict, symbol: str, candidates: list[dict]) -> list[dict]:
    """Rank ambiguous cross-file call targets using language, file, route, and data-access context."""
    caller_file=str(caller.get("file") or ""); caller_lang=str(caller.get("language") or "")
    caller_reads=set(caller.get("reads",[])); caller_writes=set(caller.get("writes",[])); ranked=[]
    for candidate in candidates:
        score=.35; reasons=["name_match"]
        if candidate.get("language")==caller_lang: score+=.12; reasons.append("same_language")
        if str(candidate.get("file") or "").rsplit("/",1)[0]==caller_file.rsplit("/",1)[0] and "/" in caller_file: score+=.10; reasons.append("same_module")
        overlap=(caller_reads|caller_writes)&(set(candidate.get("reads",[]))|set(candidate.get("writes",[])))
        if overlap: score+=min(.20,.05*len(overlap)); reasons.append("data_context")
        if candidate.get("route_bindings") and caller.get("route_bindings"): score+=.08; reasons.append("route_context")
        ranked.append({"id":candidate.get("id"),"symbol":symbol,"confidence":round(min(score,.99),3),"reasons":reasons})
    return sorted(ranked,key=lambda x:(-x["confidence"],str(x["id"])))


def build_semantic_model(ir: dict, *, minimum_confidence: float=.55, minimum_margin: float=.08) -> dict:
    functions={str(f.get("id")):f for f in ir.get("functions",[])}; resolutions=[]; deferred=[]
    for item in ir.get("unresolved_calls",[]):
        caller=functions.get(str(item.get("caller")),{}); symbol=str(item.get("symbol") or "")
        candidates=[functions[c] for c in item.get("candidates",[]) if c in functions]
        ranked=rank_call_candidates(caller,symbol,candidates)
        if not ranked: deferred.append({**item,"reason":"no_candidates"}); continue
        best=ranked[0]; runner=ranked[1]["confidence"] if len(ranked)>1 else 0.0; margin=best["confidence"]-runner
        if best["confidence"]>=minimum_confidence and margin>=minimum_margin:
            resolutions.append({"caller":item.get("caller"),"symbol":symbol,"resolved":best["id"],"candidates":ranked,"confidence":best["confidence"],"margin":round(margin,3)})
        else:
            deferred.append({**item,"ranked_candidates":ranked,"reason":"insufficient_confidence_or_margin"})
    return {"schema_version":"1.0","resolution_count":len(resolutions),"deferred_count":len(deferred),"call_resolutions":resolutions,"deferred":deferred}
