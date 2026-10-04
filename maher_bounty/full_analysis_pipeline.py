from __future__ import annotations

import json
from pathlib import Path

from .unified_ir import merge_ir
from .semantic_resolution import build_semantic_model
from .interprocedural_flow import build_flow_graph
from .analysis_coverage import measure_analysis_coverage, coverage_gate
from .static_runtime_fusion import fuse_static_runtime


def _semantic_input(ir: dict) -> dict:
    functions=ir.get("functions",[]); by_name={}
    for fn in functions: by_name.setdefault(str(fn.get("name") or ""),[]).append(str(fn.get("id")))
    unresolved=[]
    for item in ir.get("unresolved_calls",[]):
        symbol=str(item.get("symbol") or ""); short=symbol.split(".")[-1]
        unresolved.append({"caller":item.get("caller") or item.get("from"),"symbol":symbol,"candidates":list(item.get("candidates") or by_name.get(short,[]))})
    return {**ir,"unresolved_calls":unresolved}


def analyze_full(*documents: dict, runtime: dict | None=None, semantic_model: dict | None=None, out_dir: str | Path | None=None, min_resolution: float=.60, min_flow: float=.90) -> dict:
    """End-to-end static analysis with automatic semantic retry and optional runtime fusion."""
    first=merge_ir(*documents)
    semantic=semantic_model or build_semantic_model(_semantic_input(first))
    ir=merge_ir(*documents,semantic_model=semantic) if semantic.get("resolution_count",0) else first
    flow=build_flow_graph(ir); coverage=measure_analysis_coverage(ir,flow); gate=coverage_gate(coverage,min_resolution=min_resolution,min_flow=min_flow)
    static={"ir":ir,"flow":flow}; fusion=fuse_static_runtime(static,runtime or {}) if runtime is not None else {"match_count":0,"matches":[],"unmatched_runtime":[]}
    result={"schema_version":"2.0","ir":ir,"semantic":semantic,"flow":flow,"coverage":coverage,"coverage_gate":gate,"runtime_fusion":fusion,"ready":bool(gate["passed"])}
    if out_dir is not None:
        out=Path(out_dir); out.mkdir(parents=True,exist_ok=True)
        for name,payload in {"unified-ir.json":ir,"semantic-resolution.json":semantic,"interprocedural-flow.json":flow,"analysis-coverage.json":coverage,"coverage-gate.json":gate,"static-runtime-fusion.json":fusion,"full-analysis-summary.json":result}.items():
            (out/name).write_text(json.dumps(payload,ensure_ascii=False,indent=2,sort_keys=True),encoding="utf-8")
    return result
