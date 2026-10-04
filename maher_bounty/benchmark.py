from __future__ import annotations

import json
import tempfile
from dataclasses import dataclass, asdict
from pathlib import Path

from .benchmark_quality import capability_quality, quality_gate
from .benchmark_adversarial import adversarial_cases
from .benchmark_scale import scaled_negative_cases
from .benchmark_positive import scaled_positive_cases
from .benchmark_workflows import workflow_cases
from .benchmark_stress import stress_cases
from .benchmark_noise import protocol_noise_cases
from .traffic_pipeline import analyze_traffic

@dataclass(slots=True)
class BenchmarkCase:
    name: str; har: dict; expected_min_records: int = 1
    expected_protocols: tuple[str,...] = (); expected_priority_min: int = 0
    expected_workflow_divergence_min: int = 0; expected_no_protocols: bool = False
    def as_dict(self)->dict: return asdict(self)

def _entry(url:str,*,method:str="GET",status:int=200,started:str="2026-01-01T00:00:00Z",headers=None,body:str|None=None,response_headers=None,response_body:str="ok")->dict:
    request={"method":method,"url":url,"headers":headers or []}
    if body is not None: request["postData"]={"text":body}
    return {"startedDateTime":started,"request":request,"response":{"status":status,"headers":response_headers or [],"content":{"text":response_body}}}

def default_cases()->list[BenchmarkCase]:
    cases=[
        BenchmarkCase("baseline_http",{"log":{"entries":[_entry("https://bench.test/health")]}},expected_no_protocols=True),
        BenchmarkCase("ordinary_json_api",{"log":{"entries":[_entry("https://bench.test/api/users",headers=[{"name":"Accept","value":"application/json"}],response_headers=[{"name":"Content-Type","value":"application/json"}],response_body='{"users":[]}')]}},expected_no_protocols=True),
        BenchmarkCase("graphql_signal",{"log":{"entries":[_entry("https://bench.test/graphql",method="POST",headers=[{"name":"Content-Type","value":"application/json"}],body='{"query":"query Viewer { viewer { id } }"}',response_headers=[{"name":"Content-Type","value":"application/json"}],response_body='{"data":{"viewer":{"id":"1"}}}')]}},expected_protocols=("graphql",),expected_priority_min=1),
        BenchmarkCase("grpc_signal",{"log":{"entries":[_entry("https://bench.test/pkg.Service/Method",method="POST",headers=[{"name":"Content-Type","value":"application/grpc"}],response_headers=[{"name":"grpc-status","value":"0"}])]}},expected_protocols=("grpc",),expected_priority_min=1),
        BenchmarkCase("openapi_signal",{"log":{"entries":[_entry("https://bench.test/openapi.json",response_body='{"openapi":"3.1.0","paths":{}}')]}},expected_protocols=("openapi",),expected_priority_min=1),
        BenchmarkCase("websocket_signal",{"log":{"entries":[_entry("wss://bench.test/socket",headers=[{"name":"Upgrade","value":"websocket"}])]}},expected_protocols=("websocket",),expected_priority_min=1),
    ]
    same=[_entry("https://bench.test/start",started="2026-01-01T00:00:00Z",headers=[{"name":"Cookie","value":"session=alpha"}]),_entry("https://bench.test/account",status=200,started="2026-01-01T00:00:01Z",headers=[{"name":"Cookie","value":"session=alpha"}]),_entry("https://bench.test/start",started="2026-01-01T00:00:02Z",headers=[{"name":"Cookie","value":"session=beta"}]),_entry("https://bench.test/account",status=200,started="2026-01-01T00:00:03Z",headers=[{"name":"Cookie","value":"session=beta"}])]
    divergent=[dict(x) for x in same]; divergent[-1]={**divergent[-1],"response":{**divergent[-1]["response"],"status":403}}
    cases += [BenchmarkCase("identity_same_outcome",{"log":{"entries":same}},expected_min_records=4,expected_no_protocols=True),BenchmarkCase("identity_workflow_divergence",{"log":{"entries":divergent}},expected_min_records=4,expected_workflow_divergence_min=1,expected_priority_min=1)]
    cases.extend(adversarial_cases(BenchmarkCase,_entry))
    cases.extend(scaled_negative_cases(BenchmarkCase,_entry,count=36))
    cases.extend(scaled_positive_cases(BenchmarkCase,_entry))
    cases.extend(workflow_cases(BenchmarkCase,_entry))
    cases.extend(stress_cases(BenchmarkCase,_entry))
    cases.extend(protocol_noise_cases(BenchmarkCase,_entry))
    return cases

def run_benchmark(out_dir:str|Path,cases:list[BenchmarkCase]|None=None)->dict:
    out=Path(out_dir); out.mkdir(parents=True,exist_ok=True); cases=cases or default_cases(); results=[]; tp=fp=tn=fn=0
    with tempfile.TemporaryDirectory() as td:
        root=Path(td)
        for idx,case in enumerate(cases,1):
            source=root/f"{idx:03d}-{case.name}.har"; source.write_text(json.dumps(case.har),encoding="utf-8")
            result=analyze_traffic(source,kind="har",out_dir=out/case.name,db_path=out/"benchmark-research.db")
            protocols={str(x.get("protocol")) for x in result.get("protocols",{}).get("signals",[])}; div=int(result.get("workflow_divergences",{}).get("divergence_count",0)); pri=int(result.get("priorities",{}).get("target_count",0))
            checks={"record_count":result.get("record_count",0)>=case.expected_min_records,"protocols":all(p in protocols for p in case.expected_protocols),"priority_count":pri>=case.expected_priority_min,"workflow_divergence":div>=case.expected_workflow_divergence_min,"negative_protocol_control":not protocols if case.expected_no_protocols else True}
            expected=bool(case.expected_protocols or case.expected_workflow_divergence_min or case.expected_priority_min); observed=bool(protocols or div or pri)
            if expected and observed: tp+=1
            elif expected: fn+=1
            elif observed: fp+=1
            else: tn+=1
            results.append({"name":case.name,"passed":all(checks.values()),"checks":checks,"classification":{"expected_signal":expected,"observed_signal":observed},"observed":{"records":result.get("record_count",0),"protocols":sorted(protocols),"workflow_divergences":div,"priority_targets":pri,"provenance_chains":result.get("provenance",{}).get("chain_count",0),"evidence_items":result.get("evidence_report",{}).get("item_count",0)}})
    passed=sum(x["passed"] for x in results); precision=tp/max(1,tp+fp); recall=tp/max(1,tp+fn); specificity=tn/max(1,tn+fp); fpr=fp/max(1,fp+tn)
    summary={"schema_version":"1.9","case_count":len(results),"passed":passed,"failed":len(results)-passed,"pass_rate":round(passed/max(1,len(results)),4),"quality":{"true_positive":tp,"false_positive":fp,"true_negative":tn,"false_negative":fn,"precision":round(precision,4),"recall":round(recall,4),"specificity":round(specificity,4),"false_positive_rate":round(fpr,4)},"results":results}
    summary["capability_quality"]=capability_quality(results); summary["quality_gate"]=quality_gate(summary)
    (out/"benchmark-summary.json").write_text(json.dumps(summary,indent=2),encoding="utf-8"); return summary
