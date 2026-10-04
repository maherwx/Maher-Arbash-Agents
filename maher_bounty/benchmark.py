from __future__ import annotations

import json
import tempfile
from dataclasses import dataclass, asdict
from pathlib import Path

from .traffic_pipeline import analyze_traffic


@dataclass(slots=True)
class BenchmarkCase:
    name: str
    har: dict
    expected_min_records: int = 1
    expected_protocols: tuple[str, ...] = ()
    expected_priority_min: int = 0

    def as_dict(self) -> dict:
        return asdict(self)


def default_cases() -> list[BenchmarkCase]:
    return [
        BenchmarkCase(
            name="baseline_http",
            har={"log":{"entries":[{
                "request":{"method":"GET","url":"https://bench.test/health","headers":[]},
                "response":{"status":200,"headers":[],"content":{"text":"ok"}},
            }]}},
            expected_min_records=1,
        ),
        BenchmarkCase(
            name="graphql_signal",
            har={"log":{"entries":[{
                "request":{
                    "method":"POST","url":"https://bench.test/graphql",
                    "headers":[{"name":"Content-Type","value":"application/json"}],
                    "postData":{"text":"{\"query\":\"query Viewer { viewer { id } }\"}"},
                },
                "response":{
                    "status":200,
                    "headers":[{"name":"Content-Type","value":"application/json"}],
                    "content":{"text":"{\"data\":{\"viewer\":{\"id\":\"1\"}}}"},
                },
            }]}},
            expected_min_records=1,
            expected_protocols=("graphql",),
            expected_priority_min=1,
        ),
    ]


def run_benchmark(out_dir: str | Path, cases: list[BenchmarkCase] | None = None) -> dict:
    out=Path(out_dir)
    out.mkdir(parents=True,exist_ok=True)
    cases=cases or default_cases()
    results=[]

    with tempfile.TemporaryDirectory() as td:
        root=Path(td)
        for idx,case in enumerate(cases,1):
            source=root/f"{idx:03d}-{case.name}.har"
            source.write_text(json.dumps(case.har),encoding="utf-8")
            case_out=out/case.name
            result=analyze_traffic(source,kind="har",out_dir=case_out,db_path=out/"benchmark-research.db")

            observed_protocols={str(x.get("protocol")) for x in result.get("protocols",{}).get("signals",[])}
            checks={
                "record_count": result.get("record_count",0) >= case.expected_min_records,
                "protocols": all(p in observed_protocols for p in case.expected_protocols),
                "priority_count": result.get("priorities",{}).get("target_count",0) >= case.expected_priority_min,
            }
            results.append({
                "name":case.name,
                "passed":all(checks.values()),
                "checks":checks,
                "observed":{
                    "records":result.get("record_count",0),
                    "protocols":sorted(observed_protocols),
                    "priority_targets":result.get("priorities",{}).get("target_count",0),
                    "provenance_chains":result.get("provenance",{}).get("chain_count",0),
                    "evidence_items":result.get("evidence_report",{}).get("item_count",0),
                },
            })

    passed=sum(1 for x in results if x["passed"])
    summary={
        "schema_version":"1.0",
        "case_count":len(results),
        "passed":passed,
        "failed":len(results)-passed,
        "pass_rate":round(passed/max(1,len(results)),4),
        "results":results,
    }
    (out/"benchmark-summary.json").write_text(json.dumps(summary,indent=2),encoding="utf-8")
    return summary
