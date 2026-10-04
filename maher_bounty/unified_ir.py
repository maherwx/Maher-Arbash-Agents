from __future__ import annotations

import hashlib
from dataclasses import dataclass, asdict
from typing import Iterable


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
        route_index.setdefault((r.get("file"), r.get("function")), []).append({
            "kind":"http_route",
            "method":None,
            "path":None,
            "decorators":r.get("decorators", []),
        })
    functions=[]
    for fn in result.get("functions", []):
        functions.append(IRFunction(
            id=_stable_id("python", fn.get("file",""), fn.get("name",""), fn.get("line")),
            language="python",
            file=fn.get("file",""),
            name=fn.get("name",""),
            line=fn.get("line"),
            async_function=bool(fn.get("async_function")),
            parameters=list(fn.get("parameters", [])),
            calls=list(fn.get("calls", [])),
            reads=list(fn.get("reads", [])),
            writes=list(fn.get("writes", [])),
            complexity=int(fn.get("complexity") or 1),
            route_bindings=route_index.get((fn.get("file"), fn.get("name")), []),
        ).as_dict())
    return {"language":"python","functions":functions}


def from_jsts_ast(result: dict) -> dict:
    route_by_file={}
    for r in result.get("route_handlers", []):
        route_by_file.setdefault(r.get("file"), []).append({
            "kind":"http_route",
            "method":r.get("method"),
            "path":r.get("path"),
            "line":r.get("line"),
        })
    functions=[]
    for fn in result.get("functions", []):
        bindings=[]
        for r in route_by_file.get(fn.get("file"), []):
            if r.get("line") is None or fn.get("line") is None or abs(int(r["line"])-int(fn["line"])) <= 20:
                bindings.append(r)
        functions.append(IRFunction(
            id=_stable_id("javascript_typescript", fn.get("file",""), fn.get("name",""), fn.get("line")),
            language="javascript_typescript",
            file=fn.get("file",""),
            name=fn.get("name",""),
            line=fn.get("line"),
            async_function=bool(fn.get("async")),
            parameters=list(fn.get("params", [])),
            calls=list(fn.get("calls", [])),
            reads=list(fn.get("reads", [])),
            writes=list(fn.get("writes", [])),
            complexity=int(fn.get("complexity") or 1),
            route_bindings=bindings,
        ).as_dict())
    return {"language":"javascript_typescript","functions":functions}


def merge_ir(*documents: dict) -> dict:
    functions=[]
    for doc in documents:
        functions.extend(doc.get("functions", []))

    by_name={}
    for fn in functions:
        by_name.setdefault(fn.get("name"), []).append(fn)

    call_edges=[]
    unresolved=[]
    for fn in functions:
        for callee in fn.get("calls", []):
            short=callee.split(".")[-1]
            candidates=by_name.get(short, [])
            if len(candidates)==1:
                call_edges.append({"from":fn["id"],"to":candidates[0]["id"],"kind":"calls","symbol":callee})
            else:
                unresolved.append({"from":fn["id"],"symbol":callee,"candidate_count":len(candidates)})

    route_functions=[fn for fn in functions if fn.get("route_bindings")]
    return {
        "schema_version":"1.0",
        "function_count":len(functions),
        "languages":sorted({fn.get("language") for fn in functions}),
        "functions":functions,
        "call_edges":call_edges,
        "unresolved_calls":unresolved,
        "route_function_count":len(route_functions),
        "route_functions":route_functions,
    }
