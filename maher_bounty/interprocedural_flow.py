from __future__ import annotations

from collections import defaultdict, deque


def build_flow_graph(ir: dict) -> dict:
    """Build conservative interprocedural read/write propagation over resolved calls."""
    functions={str(f.get("id")):f for f in ir.get("functions",[]) if f.get("id")}
    outgoing=defaultdict(list); incoming=defaultdict(list)
    for edge in ir.get("call_edges",[]):
        src=str(edge.get("from") or ""); dst=str(edge.get("to") or "")
        if src in functions and dst in functions:
            outgoing[src].append(dst); incoming[dst].append(src)
    summaries={}
    for fid,fn in functions.items():
        summaries[fid]={"direct_reads":sorted(set(fn.get("reads",[]))),"direct_writes":sorted(set(fn.get("writes",[]))),"transitive_reads":set(fn.get("reads",[])),"transitive_writes":set(fn.get("writes",[])),"callees":sorted(set(outgoing[fid])),"callers":sorted(set(incoming[fid]))}
    changed=True; rounds=0; limit=max(1,len(functions)*2)
    while changed and rounds<limit:
        changed=False; rounds+=1
        for fid,item in summaries.items():
            before=(len(item["transitive_reads"]),len(item["transitive_writes"]))
            for callee in item["callees"]:
                target=summaries[callee]; item["transitive_reads"].update(target["transitive_reads"]); item["transitive_writes"].update(target["transitive_writes"])
            if before!=(len(item["transitive_reads"]),len(item["transitive_writes"])):changed=True
    output={}
    for fid,item in summaries.items():
        output[fid]={**item,"transitive_reads":sorted(item["transitive_reads"]),"transitive_writes":sorted(item["transitive_writes"])}
    return {"schema_version":"1.0","function_count":len(functions),"edge_count":sum(len(x) for x in outgoing.values()),"fixpoint_rounds":rounds,"functions":output}


def trace_variable(ir: dict, variable: str) -> dict:
    graph=build_flow_graph(ir); touched=[]
    for fid,item in graph["functions"].items():
        if variable in item["transitive_reads"] or variable in item["transitive_writes"]:
            touched.append({"function":fid,"reads":variable in item["transitive_reads"],"writes":variable in item["transitive_writes"]})
    return {"variable":variable,"function_count":len(touched),"functions":touched}
