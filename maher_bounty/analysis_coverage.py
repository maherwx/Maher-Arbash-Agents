from __future__ import annotations


def measure_analysis_coverage(ir: dict, flow: dict | None=None) -> dict:
    functions=list(ir.get("functions",[])); calls=sum(len(f.get("calls",[])) for f in functions)
    resolved=len(ir.get("call_edges",[])); unresolved=len(ir.get("unresolved_calls",[]))
    denominator=max(1,resolved+unresolved)
    languages=sorted({str(f.get("language") or "unknown") for f in functions})
    with_rw=sum(1 for f in functions if f.get("reads") or f.get("writes"))
    routes=sum(1 for f in functions if f.get("route_bindings"))
    flow_functions=len((flow or {}).get("functions",{}))
    return {
        "schema_version":"1.0","function_count":len(functions),"language_count":len(languages),"languages":languages,
        "declared_call_count":calls,"resolved_edge_count":resolved,"unresolved_call_count":unresolved,
        "call_resolution_rate":round(resolved/denominator,4),"functions_with_data_access":with_rw,
        "data_access_coverage":round(with_rw/max(1,len(functions)),4),"route_function_count":routes,
        "flow_function_count":flow_functions,"flow_coverage":round(flow_functions/max(1,len(functions)),4),
    }


def coverage_gate(metrics: dict, *, min_resolution: float=.60, min_flow: float=.90) -> dict:
    checks={"call_resolution":float(metrics.get("call_resolution_rate",0))>=min_resolution,"flow_coverage":float(metrics.get("flow_coverage",0))>=min_flow,"has_functions":int(metrics.get("function_count",0))>0}
    return {"passed":all(checks.values()),"checks":checks,"thresholds":{"min_resolution":min_resolution,"min_flow":min_flow}}
