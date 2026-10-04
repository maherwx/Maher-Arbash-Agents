from __future__ import annotations

from .capability_scorecard import build_scorecard


def evaluate_readiness(*, benchmark: dict, analysis: dict, minimum_capability_score: float=90.0) -> dict:
    scorecard=build_scorecard(benchmark)
    checks={
        "benchmark_quality":bool(benchmark.get("quality_gate",{}).get("passed")),
        "all_benchmark_cases":int(benchmark.get("failed",1))==0,
        "analysis_coverage":bool(analysis.get("coverage_gate",{}).get("passed")),
        "analysis_ready":bool(analysis.get("ready")),
        "capability_floor":float(scorecard.get("minimum_capability_score",0.0))>=minimum_capability_score,
    }
    return {"passed":all(checks.values()),"checks":checks,"scorecard":scorecard,"thresholds":{"minimum_capability_score":minimum_capability_score}}
