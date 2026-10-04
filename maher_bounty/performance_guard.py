from __future__ import annotations

import time
import tracemalloc
from collections.abc import Callable


def measure(operation: Callable[[], object]) -> dict:
    tracemalloc.start(); start=time.perf_counter()
    try:
        value=operation()
        elapsed=time.perf_counter()-start
        _,peak=tracemalloc.get_traced_memory()
        return {"elapsed_seconds":round(elapsed,6),"peak_bytes":int(peak),"result":value}
    finally:
        tracemalloc.stop()


def compare_performance(current: dict, baseline: dict, *, time_factor: float=1.50, memory_factor: float=1.50) -> dict:
    ct=float(current.get("elapsed_seconds",float("inf"))); bt=max(float(baseline.get("elapsed_seconds",0.0)),1e-9)
    cm=int(current.get("peak_bytes",2**63-1)); bm=max(int(baseline.get("peak_bytes",0)),1)
    checks={"time":ct<=bt*time_factor,"memory":cm<=bm*memory_factor}
    return {"passed":all(checks.values()),"checks":checks,"ratios":{"time":round(ct/bt,4),"memory":round(cm/bm,4)},"limits":{"time_factor":time_factor,"memory_factor":memory_factor}}
