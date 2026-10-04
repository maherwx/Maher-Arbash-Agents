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
    expected_workflow_divergence_min: int = 0
    expected_no_protocols: bool = False

    def as_dict(self) -> dict:
        return asdict(self)


def _entry(url: str, *, method: str = "GET", status: int = 200, started: str = "2026-01-01T00:00:00Z", headers=None, body: str | None = None) -> dict:
    request={"method":method,"url":url,"headers":headers or []}
    if body is not None:
        request["postData"]={"text":body}
    return {"startedDateTime":started,"request":request,"response":{"status":status,"headers":[],"content":{"text":"ok"}}}


def default_cases() -> list[BenchmarkCase]:
    baseline=BenchmarkCase(
        name="baseline_http",
        har={"log":{"entries":[_entry("https://bench.test/health")]}},
        expected_min_records=1,
        expected_no_protocols=True,
    )
    graphql=BenchmarkCase(
        name="graphql_signal",
        har={"log":{"entries":[{
            "startedDateTime":"2026-01-01T00:00:00Z",
            "request":{"method":"POST","url":"https://bench.test/graphql","headers":[{"name":"Content-Type","value":"application/json"}],"postData":{"text":"{\"query\":\"query Viewer { viewer { id } }\"}"}},
            "response":{"status":200,"headers":[{"name":"Content-Type","value":"application/json"}],"content":{"text":"{\"data\":{\"viewer\":{\"id\":\"1\"}}}"},
        }]}},
        expected_min_records=1,
        expected_protocols=("graphql",),
        expected_priority_min=1,
    )
    # Two cookie identities traverse the same transition with different outcomes.
    workflow=BenchmarkCase(
        name="identity_workflow_divergence",
        har={"log":{"entries":[
            _entry("https://bench.test/start",started="2026-01-01T00:00:00Z",headers=[{"name":"Cookie","value":"session=alpha"}]),
            _entry("https://bench.test/account",status=200,started="2026-01-01T00:00:01Z",headers=[{"name":"Cookie","value":"session=alpha"}]),
            _entry("https://bench.test/start",started="2026-01-01T00:00:02Z",headers=[{"name":"Cookie","value":"session=beta"}]),
            _entry("https://bench.test/account",status=403,started="2026-01-01T00:00:03Z",headers=[{"name":"Cookie","value":"session=beta"}]),
        ]}},
        expected_min_records=4,
        expected_workflow_divergence_min=1,
        expected_priority_min=1,
    )
    return [baseline,graphql,workflow]


def run_benchmark(out_dir: str | Path, cases: list[BenchmarkCase] | None = None) -> dict:
    out=Path(out_dir); out.mkdir(parents=True,exist_ok=True); cases=cases or default_cases(); results=[]
    tp=fp=tn=fn=0
    with tempfile.TemporaryDirectory() as td:
        root=Path(td)
        for idx,case in enumerate(cases,1):
            source=root/f"{idx:03d}-{case.name}.har"; source.write_text(json.dumps(case.har),encoding="utf-8"); case_out=out/case.name
            result=analyze_traffic(source,kind="har",out_dir=case_out,db_path=out/"benchmark-research.db")
            observed_protocols={str(x.get("protocol")) for x in result.get("protocols",{}).get("signals",[])}
            divergence_count=int(result.get("workflow_divergences",{}).get("divergence_count",0)); priority_count=int(result.get("priorities",{}).get("target_count",0))
            checks={
                "record_count":result.get("record_count",0)>=case.expected_min_records,
                "protocols":all(p in observed_protocols for p in case.expected_protocols),
                "priority_count":priority_count>=case.expected_priority_min,
                "workflow_divergence":divergence_count>=case.expected_workflow_divergence_min,
                "negative_protocol_control":not observed_protocols if case.expected_no_protocols else True,
            }
            expected_signal=bool(case.expected_protocols or case.expected_workflow_divergence_min or case.expected_priority_min)
            observed_signal=bool(observed_protocols or divergence_count or priority_count)
            if expected_signal and observed_signal: tp+=1
            elif expected_signal and not observed_signal: fn+=1
            elif not expected_signal and observed_signal: fp+=1
            else: tn+=1
            results.append({"name":case.name,"passed":all(checks.values()),"checks":checks,"classification":{"expected_signal":expected_signal,"observed_signal":observed_signal},"observed":{"records":result.get("record_count",0),"protocols":sorted(observed_protocols),"workflow_divergences":divergence_count,"priority_targets":priority_count,"provenance_chains":result.get("provenance",{}).get("chain_count",0),"evidence_items":result.get("evidence_report",{}).get("item_count",0)}})
    passed=sum(1 for x in results if x["passed"]); precision=tp/max(1,tp+fp); recall=tp/max(1,tp+fn); specificity=tn/max(1,tn+fp)
    summary={"schema_version":"1.1","case_count":len(results),"passed":passed,"failed":len(results)-passed,"pass_rate":round(passed/max(1,len(results)),4),"quality":{"true_positive":tp,"false_positive":fp,"true_negative":tn,"false_negative":fn,"precision":round(precision,4),"recall":round(recall,4),"specificity":round(specificity,4)},"results":results}
    (out/"benchmark-summary.json").write_text(json.dumps(summary,indent=2),encoding="utf-8"); return summary
