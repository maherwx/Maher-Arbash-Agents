from __future__ import annotations

import json
from pathlib import Path

from .unified_ir import merge_ir
from .semantic_resolution import build_semantic_model
from .interprocedural_flow import build_flow_graph
from .analysis_coverage import measure_analysis_coverage, coverage_gate
from .static_runtime_fusion import fuse_static_runtime


def analyze_ir_documents(*documents: dict, semantic_model: dict | None = None, runtime_result: dict | None = None, out_dir: str | Path | None = None, min_resolution: float = .60, min_flow: float = .90) -> dict:
    """Run IR, automatic semantic resolution, flow, coverage, and optional runtime fusion."""
    initial_ir=merge_ir(*documents)
    generated_semantic=build_semantic_model(initial_ir)
    effective_semantic=semantic_model if semantic_model is not None else generated_semantic
    ir=merge_ir(*documents,semantic_model=effective_semantic)
    flow=build_flow_graph(ir)
    coverage=measure_analysis_coverage(ir,flow)
    gate=coverage_gate(coverage,min_resolution=min_resolution,min_flow=min_flow)
    result={
        "schema_version":"1.1",
        "ir":ir,
        "semantic_model":effective_semantic,
        "semantic_generated":semantic_model is None,
        "flow":flow,
        "coverage":coverage,
        "coverage_gate":gate,
        "ready":bool(gate["passed"]),
    }
    if runtime_result is not None:
        result["runtime_fusion"]=fuse_static_runtime(result,runtime_result)
    if out_dir is not None:
        out=Path(out_dir); out.mkdir(parents=True,exist_ok=True)
        artifacts={
            "unified-ir.json":ir,
            "semantic-resolution.json":effective_semantic,
            "interprocedural-flow.json":flow,
            "analysis-coverage.json":coverage,
            "coverage-gate.json":gate,
            "advanced-analysis-summary.json":result,
        }
        if "runtime_fusion" in result:
            artifacts["static-runtime-fusion.json"]=result["runtime_fusion"]
        for name,payload in artifacts.items():
            (out/name).write_text(json.dumps(payload,ensure_ascii=False,indent=2,sort_keys=True),encoding="utf-8")
    return result
