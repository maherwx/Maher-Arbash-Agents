from __future__ import annotations

import hashlib
import json
from pathlib import Path

REQUIRED=("unified-ir.json","interprocedural-flow.json","analysis-coverage.json","coverage-gate.json","advanced-analysis-summary.json")


def validate_artifacts(directory: str | Path) -> dict:
    root=Path(directory); results=[]
    for name in REQUIRED:
        path=root/name
        item={"name":name,"exists":path.is_file(),"valid_json":False,"sha256":None,"bytes":0}
        if path.is_file():
            raw=path.read_bytes(); item["bytes"]=len(raw); item["sha256"]=hashlib.sha256(raw).hexdigest()
            try:
                payload=json.loads(raw.decode("utf-8")); item["valid_json"]=isinstance(payload,dict)
            except (UnicodeDecodeError,json.JSONDecodeError): pass
        item["passed"]=item["exists"] and item["valid_json"] and item["bytes"]>1
        results.append(item)
    return {"passed":all(x["passed"] for x in results),"required_count":len(REQUIRED),"passed_count":sum(x["passed"] for x in results),"artifacts":results}
