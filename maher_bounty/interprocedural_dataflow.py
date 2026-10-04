from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, asdict


@dataclass(slots=True)
class FlowEdge:
    source: str
    target: str
    kind: str
    symbol: str | None
    confidence: float
    provenance: dict

    def as_dict(self) -> dict:
        return asdict(self)


def build_interprocedural_dataflow(ir: dict) -> dict:
    functions={fn["id"]:fn for fn in ir.get("functions", [])}
    edges:list[FlowEdge]=[]
    nodes:dict[str,dict]={}

    def add_node(node_id:str, kind:str, **attrs):
        nodes.setdefault(node_id, {"id":node_id,"kind":kind,**attrs})

    def add_edge(src:str,dst:str,kind:str,symbol:str|None,confidence:float,**prov):
        edges.append(FlowEdge(src,dst,kind,symbol,confidence,prov))

    for fn in functions.values():
        add_node(fn["id"],"function",language=fn.get("language"),file=fn.get("file"),name=fn.get("name"),line=fn.get("line"),complexity=fn.get("complexity"),route_bindings=fn.get("route_bindings",[]))
        for idx,p in enumerate(fn.get("parameters", [])):
            pid=f'{fn["id"]}:param:{idx}:{p}'
            add_node(pid,"parameter",name=p,index=idx,function_id=fn["id"])
            add_edge(pid,fn["id"],"parameter_of",p,1.0,file=fn.get("file"),line=fn.get("line"))
        for name in fn.get("reads", []):
            vid=f'{fn["id"]}:read:{name}'
            add_node(vid,"variable_read",name=name,function_id=fn["id"])
            add_edge(vid,fn["id"],"read_in",name,0.95,file=fn.get("file"),line=fn.get("line"))
        for name in fn.get("writes", []):
            vid=f'{fn["id"]}:write:{name}'
            add_node(vid,"variable_write",name=name,function_id=fn["id"])
            add_edge(fn["id"],vid,"writes",name,0.95,file=fn.get("file"),line=fn.get("line"))

    for edge in ir.get("call_edges", []):
        caller=functions.get(edge.get("from"))
        callee=functions.get(edge.get("to"))
        if not caller or not callee:
            continue
        symbol=edge.get("symbol")
        add_edge(caller["id"],callee["id"],"calls",symbol,0.99,origin="unified_ir")
        caller_params=list(caller.get("parameters", []))
        caller_reads=set(caller.get("reads", []))
        callee_params=list(callee.get("parameters", []))
        for idx,param in enumerate(callee_params):
            target=f'{callee["id"]}:param:{idx}:{param}'
            if idx < len(caller_params):
                src=f'{caller["id"]}:param:{idx}:{caller_params[idx]}'
                add_edge(src,target,"argument_flow",caller_params[idx],0.72,reason="positional-parameter correspondence",call_symbol=symbol)
            for read in caller_reads:
                if read == param or read.lower() == str(param).lower():
                    src=f'{caller["id"]}:read:{read}'
                    add_edge(src,target,"argument_flow",read,0.88,reason="matching caller read and callee parameter",call_symbol=symbol)

    outgoing=defaultdict(list)
    for e in edges:
        outgoing[e.source].append(e.as_dict())

    route_sources=[fn["id"] for fn in functions.values() if fn.get("route_bindings")]
    reachable={}
    for start in route_sources:
        seen={start}; q=deque([(start,0)]); reached=[]
        while q:
            current,depth=q.popleft()
            if depth>=6:
                continue
            for e in outgoing.get(current, []):
                nxt=e["target"]
                if nxt not in seen:
                    seen.add(nxt)
                    q.append((nxt,depth+1))
                    reached.append({"node":nxt,"depth":depth+1,"via":e["kind"],"confidence":e["confidence"]})
        reachable[start]=reached

    return {
        "schema_version":"1.1",
        "node_count":len(nodes),
        "edge_count":len(edges),
        "nodes":list(nodes.values()),
        "edges":[e.as_dict() for e in edges],
        "route_entrypoints":route_sources,
        "reachable_from_routes":reachable,
    }


def summarize_flow_paths(graph: dict, *, min_confidence: float = 0.7) -> dict:
    edges=[e for e in graph.get("edges", []) if float(e.get("confidence",0)) >= min_confidence]
    by_kind=defaultdict(int)
    for e in edges:
        by_kind[e.get("kind","unknown")]+=1
    route_reach=graph.get("reachable_from_routes", {})
    return {
        "qualified_edge_count":len(edges),
        "edge_kinds":dict(sorted(by_kind.items())),
        "route_entrypoint_count":len(route_reach),
        "max_reachable_nodes":max((len(v) for v in route_reach.values()), default=0),
    }
