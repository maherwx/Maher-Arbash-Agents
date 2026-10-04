from __future__ import annotations

from collections import defaultdict
from urllib.parse import urlparse


def _host(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:
        return ""


def fuse_static_runtime(static_result: dict, runtime_result: dict) -> dict:
    """Correlate static route/call/data-flow evidence with observed runtime protocol signals."""
    ir=static_result.get("ir", static_result)
    flow=static_result.get("flow", {})
    runtime_signals=runtime_result.get("protocols",{}).get("signals",runtime_result.get("signals",[]))
    routes=[]
    for fn in ir.get("functions",[]):
        for route in fn.get("route_bindings",[]):
            routes.append({"function":fn.get("id"),"file":fn.get("file"),"path":str(route.get("path") or route.get("route") or ""),"kind":route.get("kind"),"language":fn.get("language")})
    matches=[]; unmatched_runtime=[]
    for signal in runtime_signals:
        metadata=signal.get("metadata") or {}; url=str(metadata.get("url") or signal.get("url") or ""); path=urlparse(url).path if url else ""
        candidates=[]
        for route in routes:
            rp=route["path"]
            if rp and path and (rp==path or path.startswith(rp.rstrip("/")+"/") or rp in path):
                candidates.append(route)
        if not candidates:
            unmatched_runtime.append({"protocol":signal.get("protocol"),"url":url,"host":_host(url)})
            continue
        for route in candidates:
            f=flow.get("functions",{}).get(str(route["function"]),{})
            matches.append({"protocol":signal.get("protocol"),"url":url,"host":_host(url),"function":route["function"],"file":route["file"],"language":route["language"],"route":route["path"],"transitive_reads":f.get("transitive_reads",[]),"transitive_writes":f.get("transitive_writes",[])})
    matched_functions={m["function"] for m in matches}
    return {"schema_version":"1.0","route_count":len(routes),"runtime_signal_count":len(runtime_signals),"match_count":len(matches),"matched_function_count":len(matched_functions),"matches":matches,"unmatched_runtime":unmatched_runtime}
