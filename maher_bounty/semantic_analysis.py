from __future__ import annotations

from collections import defaultdict


def build_semantic_model(ir: dict) -> dict:
    """Enrich Unified IR with symbol resolution, call ambiguity and semantic coupling metrics."""
    functions=list(ir.get("functions", []))
    by_name=defaultdict(list)
    by_file=defaultdict(list)
    for fn in functions:
        by_name[str(fn.get("name"))].append(fn)
        by_file[str(fn.get("file"))].append(fn)

    symbols=[]
    for fn in functions:
        symbols.append({
            "id":fn.get("id"),
            "kind":"function",
            "name":fn.get("name"),
            "language":fn.get("language"),
            "file":fn.get("file"),
            "line":fn.get("line"),
            "arity":len(fn.get("parameters", [])),
            "async":bool(fn.get("async_function")),
            "route_bound":bool(fn.get("route_bindings")),
        })

    resolutions=[]
    for caller in functions:
        for raw in caller.get("calls", []):
            short=str(raw).split(".")[-1]
            candidates=by_name.get(short, [])
            ranked=[]
            for target in candidates:
                score=0.45
                reasons=["name-match"]
                if target.get("file")==caller.get("file"):
                    score+=0.30; reasons.append("same-file")
                if target.get("language")==caller.get("language"):
                    score+=0.15; reasons.append("same-language")
                if target.get("id")==caller.get("id"):
                    score-=0.35; reasons.append("self-call-penalty")
                ranked.append({"target":target.get("id"),"confidence":round(max(0,min(0.99,score)),3),"reasons":reasons})
            ranked.sort(key=lambda x:-x["confidence"])
            resolutions.append({
                "caller":caller.get("id"),"symbol":raw,
                "candidate_count":len(ranked),"candidates":ranked[:10],
                "resolved": ranked[0]["target"] if ranked and (len(ranked)==1 or ranked[0]["confidence"]-ranked[1]["confidence"]>=0.2) else None,
            })

    coupling=[]
    for fn in functions:
        reads=set(fn.get("reads", [])); writes=set(fn.get("writes", [])); params=set(fn.get("parameters", []))
        coupling.append({
            "function":fn.get("id"),
            "fan_out":len(set(fn.get("calls", []))),
            "state_touch_count":len(reads|writes),
            "parameter_state_overlap":len(params & (reads|writes)),
            "complexity":int(fn.get("complexity") or 1),
            "semantic_weight":round((int(fn.get("complexity") or 1)*0.35)+(len(set(fn.get("calls", [])))*0.25)+(len(reads|writes)*0.15)+(2.0 if fn.get("route_bindings") else 0),2),
        })
    coupling.sort(key=lambda x:-x["semantic_weight"])

    return {
        "schema_version":"1.0",
        "symbol_count":len(symbols),
        "symbols":symbols,
        "call_resolution_count":len(resolutions),
        "call_resolutions":resolutions,
        "semantic_coupling":coupling,
        "hot_functions":coupling[:100],
    }
