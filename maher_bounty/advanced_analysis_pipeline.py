from __future__ import annotations

import json
from pathlib import Path

from .unified_ir import merge_ir
from .interprocedural_flow import build_flow_graph
from .analysis_coverage import measure_analysis_coverage, coverage_gate


def analyze_ir_documents(*documents: dict, semantic_model: dict | None = None, out_dir: str | Path | None = None, min_resolution: float = .60, min_flow: float = .90) -> dict:
    """Run the advanced static-analysis stages as one deterministic pipeline."""
    ir=merge_ir(*documents, semantic_model=semantic_model)
    flow=build_flow_graph(ir)
    coverage=measure_analysis_coverage(ir,flow)
    gate=coverage_gate(coverage,min_resolution=min_resolution,min_flow=min_flow)
    result={
        "schema_version":"1.0",
        "ir":ir,
        "flow":flow,
        "coverage":coverage,
        "coverage_gate":gate,
        "ready":bool(gate["passed"]),
    }
    if out_dir is not None:
        out=Path(out_dir); out.mkdir(parents=True,exist_ok=True)
        artifacts={"unified-ir.json":ir,"interprocedural-flow.json":flow,"analysis-coverage.json":coverage,"coverage-gate.json":gate,"advanced-analysis-summary.json":result}
        for name,payload in artifacts.items():
            (out/name).write_text(json.dumps(payload,ensure_ascii=False,indent=2,sort_keys=True),encoding="utf-8")
    return result
