from __future__ import annotations

import hashlib
from dataclasses import dataclass, asdict


@dataclass(slots=True)
class IRFunction:
    id: str
    language: str
    file: str
    name: str
    line: int | None
    async_function: bool
    parameters: list[str]
    calls: list[str]
    reads: list[str]
    writes: list[str]
    complexity: int
    route_bindings: list[dict]

    def as_dict(self) -> dict:
        return asdict(self)


def _stable_id(language: str, file: str, name: str, line: int | None) -> str:
    material=f"{language}\0{file}\0{name}\0{line or 0}"
    return "fn:" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:20]


def from_python_ast(result: dict) -> dict:
    route_index={}
    for r in result.get("route_functions", []):
        route_index.setdefault((r.get("file"), r.get("function")), []).append({"kind":"http_route","method":None,"path":None,"decorators":r.get("decorators", [])})
    functions=[]
    for fn in result.get("functions", []):
        functions.append(IRFunction(_stable_id("python",fn.get("file",""),fn.get("name",""),fn.get("line")),"python",fn.get("file",""),fn.get("name",""),fn.get("line"),bool(fn.get("async_function")),list(fn.get("parameters",[])),list(fn.get("calls",[])),list(fn.get("reads",[])),list(fn.get("writes",[])),int(fn.get("complexity") or 1),route_index.get((fn.get("file"),fn.get("name")),[])).as_dict())
    return {"language":"python","functions":functions}


def from_jsts_ast(result: dict) -> dict:
    route_by_file={}
    for r in result.get("route_handlers", []):
        route_by_file.setdefault(r.get("file"), []).append({"kind":"http_route","method":r.get("method"),"path":r.get("path"),"line":r.get("line")})
    functions=[]
    for fn in result.get("functions", []):
        bindings=[r for r in route_by_file.get(fn.get("file"),[]) if r.get("line") is None or fn.get("line") is None or abs(int(r["line"])-int(fn["line"]))<=20]
        functions.append(IRFunction(_stable_id("javascript_typescript",fn.get("file",""),fn.get("name",""),fn.get("line")),"javascript_typescript",fn.get("file",""),fn.get("name",""),fn.get("line"),bool(fn.get("async")),list(fn.get("params",[])),list(fn.get("calls",[])),list(fn.get("reads",[])),list(fn.get("writes",[])),int(fn.get("complexity") or 1),bindings).as_dict())
    return {"language":"javascript_typescript","functions":functions}


def from_structural_ir(result: dict) -> dict:
    return {"language":result.get("language","unknown"),"functions":list(result.get("functions",[]))}


def _semantic_confidence(item: dict) -> float:
    """Return the resolver's confidence without inventing a stronger score.

    Older semantic models stored confidence on the winning candidate, while
    newer models may store it directly on the resolution. Preserve either
    representation and fall back conservatively only when neither exists.
    """
    direct=item.get("confidence")
    if direct is not None:
        return float(direct)
    resolved=item.get("resolved")
    for candidate in item.get("candidates", []):
        candidate_id=candidate.get("target", candidate.get("id"))
        if candidate_id==resolved and candidate.get("confidence") is not None:
            return float(candidate["confidence"])
    return 0.5


def merge_ir(*documents: dict, semantic_model: dict | None = None) -> dict:
    functions=[]
    for doc in documents:
        functions.extend(doc.get("functions", []))
    by_name={}
    for fn in functions:
        by_name.setdefault(fn.get("name"), []).append(fn)

    semantic_lookup={}
    for item in (semantic_model or {}).get("call_resolutions", []):
        if item.get("resolved"):
            semantic_lookup[(item.get("caller"), item.get("symbol"))]=item

    call_edges=[]; unresolved=[]; seen=set()
    for fn in functions:
        for callee in fn.get("calls", []):
            semantic=semantic_lookup.get((fn.get("id"), callee))
            if semantic:
                target=semantic.get("resolved")
                confidence=_semantic_confidence(semantic)
                key=(fn["id"],target,callee)
                if key not in seen:
                    seen.add(key)
                    call_edges.append({"from":fn["id"],"to":target,"kind":"calls","symbol":callee,"confidence":confidence,"resolution":"semantic"})
                continue
            short=callee.split(".")[-1]; candidates=by_name.get(short, [])
            if len(candidates)==1:
                target=candidates[0]["id"]; key=(fn["id"],target,callee)
                if key not in seen:
                    seen.add(key)
                    call_edges.append({"from":fn["id"],"to":target,"kind":"calls","symbol":callee,"confidence":0.75,"resolution":"unique-name"})
            else:
                candidate_ids=[str(x.get("id")) for x in candidates if x.get("id")]
                unresolved.append({"from":fn["id"],"caller":fn["id"],"symbol":callee,"candidate_count":len(candidate_ids),"candidates":candidate_ids})
    route_functions=[fn for fn in functions if fn.get("route_bindings")]
    return {"schema_version":"1.3","function_count":len(functions),"languages":sorted({fn.get("language") for fn in functions}),"functions":functions,"call_edges":call_edges,"unresolved_calls":unresolved,"route_function_count":len(route_functions),"route_functions":route_functions,"semantic_resolution_used":bool(semantic_model)}
