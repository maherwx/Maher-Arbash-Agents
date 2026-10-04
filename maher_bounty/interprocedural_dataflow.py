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
    """
    Build a conservative, explainable interprocedural data-flow graph from Unified IR.

    The graph links:
      function -> parameter
      read/write variable relations
      call-site -> callee
      caller parameters/reads -> callee parameters when arity/symbol evidence supports it

    This is intentionally evidence-preserving: uncertain edges carry lower confidence.
    """
    functions={fn["id"]:fn for fn in ir.get("functions", [])}
    edges:list[FlowEdge]=[]
    nodes:dict[str,dict]={}

    def add_node(node_id:str, kind:str, **attrs):
        nodes.setdefault(node_id, {"id":node_id,"kind":kind,**attrs})

    def add_edge(source:str,target:str,kind:str,symbol:str|None,confidence:float,**prov):
        edges.append(FlowEdge(source,target,kind,symbol,confidence,prov))

    by_name=defaultdict(list)
    for fn in functions.values():
        by_name[fn.get("name")].append(fn)
        add_node(fn["id"],"function",language=fn.get("language"),file=fn.get("file"),name=fn.get("name"),line=fn.get("line"),complexity=fn.get("complexity"))
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

    resolved_calls=[]
    for edge in ir.get("call_edges", []):
        caller=functions.get(edge.get("from"))
        callee=functions.get(edge.get("to"))
        if not caller or not callee:
            continue
        symbol=edge.get("symbol")
        add_edge(caller["id"],callee["id"],"calls",symbol,0.99,source="unified_ir")
        resolved_calls.append((caller,callee,symbol))

        caller_params=list(caller.get("parameters", []))
        caller_reads=set(caller.get("reads", []))
        callee_params=list(callee.get("parameters", []))
        for idx,param in enumerate(callee_params):
            target=f'{callee["id"]}:param:{idx}:{param}'
            if idx < len(caller_params):
                source=f'{caller["id"]}:param:{idx}:{caller_params[idx]}'
                add_edge(source,target,"argument_flow",caller_params[idx],0.72,reason="positional-parameter correspondence",call_symbol=symbol)
            for read in caller_reads:
                if read == param or read.lower() == param.lower():
                    source=f'{caller["id"]}:read:{read}'
                    add_edge(source,target,"argument_flow",read,0.88,reason="matching caller read and callee parameter",call_symbol=symbol)

    incoming=defaultdict(list)
    outgoing=defaultdict(list)
    for e in edges:
        item=e.as_dict()
        outgoing[e.source].append(item)
        incoming[e.target].append(item)

    route_sources=[]
    for fn in functions.values():
        if fn.get("route_bindings"):
            route_sources.append(fn["id"])

    reachable={}
    for start in route_sources:
        seen={start}
        q=deque([(start,0)])
        reached=[]
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
        "schema_version":"1.0",
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
