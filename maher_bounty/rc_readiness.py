from __future__ import annotations


def assess_release_candidate(*, analysis: dict, artifacts: dict, benchmark: dict | None=None, performance: dict | None=None) -> dict:
    checks={
        "analysis_ready":bool(analysis.get("ready")),
        "coverage_gate":bool(analysis.get("coverage_gate",{}).get("passed")),
        "artifact_integrity":bool(artifacts.get("passed")),
    }
    if benchmark is not None:
        checks["benchmark_quality"]=bool(benchmark.get("quality_gate",{}).get("passed"))
        checks["benchmark_zero_failures"]=int(benchmark.get("failed",1))==0
    if performance is not None:
        checks["performance_guard"]=bool(performance.get("passed"))
    passed=all(checks.values())
    return {"schema_version":"1.0","status":"ready" if passed else "not_ready","passed":passed,"checks":checks,"failed_checks":[k for k,v in checks.items() if not v]}
