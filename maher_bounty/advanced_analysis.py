from __future__ import annotations

import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path
from urllib.parse import parse_qsl, urlparse


def _endpoint_rows(inventory: dict) -> list[dict]:
    rows=[]
    for item in inventory.get("endpoints", []):
        value=item.get("value") if isinstance(item,dict) else item
        if not value:
            continue
        try:
            p=urlparse(value)
        except ValueError:
            continue
        rows.append({
            "url":value,
            "scheme":p.scheme,
            "host":p.hostname,
            "path":p.path or "/",
            "parameters":[k for k,_ in parse_qsl(p.query,keep_blank_values=True)],
            "extension":Path(p.path).suffix.lower(),
        })
    return rows


def build_application_intelligence(target: str, inventory: dict) -> dict:
    rows=_endpoint_rows(inventory)
    paths=Counter(r["path"] for r in rows)
    params=Counter(p for r in rows for p in r["parameters"])
    js=sorted({r["url"] for r in rows if r["extension"] in {".js",".mjs"}})
    api=sorted({r["url"] for r in rows if any(x in r["path"].lower() for x in ("/api/","/graphql","/v1/","/v2/","/v3/","openapi","swagger"))})
    auth=sorted({r["url"] for r in rows if any(x in r["path"].lower() for x in ("login","signin","logout","auth","oauth","token","session","account","profile","password"))})
    upload=sorted({r["url"] for r in rows if any(x in r["path"].lower() for x in ("upload","attachment","import","file"))})
    identifiers=sorted({p for p in params if any(x in p.lower() for x in ("id","user","account","order","project","tenant","org","role"))})
    return {
        "target":target,
        "endpoint_count":len(rows),
        "unique_paths":len(paths),
        "parameter_count":sum(params.values()),
        "unique_parameters":sorted(params),
        "identifier_parameters":identifiers,
        "javascript_assets":js[:500],
        "api_candidates":api[:500],
        "auth_state_candidates":auth[:250],
        "upload_candidates":upload[:250],
        "high_frequency_paths":paths.most_common(100),
        "research_queues":{
            "javascript":js[:500],
            "api":api[:500],
            "authentication":auth[:250],
            "object_access":[r["url"] for r in rows if set(r["parameters"]) & set(identifiers)][:500],
            "file_handling":upload[:250],
        },
    }


def normalize_evidence(active_testing: dict) -> list[dict]:
    normalized=[]
    for f in active_testing.get("findings", []):
        title=str(f.get("title") or "Untitled finding").strip()
        target=str(f.get("target") or active_testing.get("target") or "").strip()
        sources=sorted(set(f.get("sources") or ([f.get("source")] if f.get("source") else [])))
        fingerprint=hashlib.sha256(f"{title.lower()}|{target.lower()}".encode()).hexdigest()[:20]
        normalized.append({
            **f,
            "fingerprint":fingerprint,
            "sources":sources,
            "source_count":len(sources),
            "evidence_present":bool(f.get("evidence")),
        })
    return normalized


def validate_evidence(findings: list[dict]) -> dict:
    buckets=defaultdict(list)
    for f in findings:
        buckets[f["fingerprint"]].append(f)
    accepted=[]; review=[]; rejected=[]
    for fp, group in buckets.items():
        f=dict(group[0])
        sources=sorted({s for g in group for s in g.get("sources",[])})
        explicit=any(bool(g.get("validated")) for g in group)
        evidence=any(bool(g.get("evidence_present")) for g in group)
        score=0.0
        if evidence: score+=0.35
        if explicit: score+=0.35
        if len(sources)>=2: score+=0.20
        if str(f.get("severity","info")).lower() in {"medium","high","critical"}: score+=0.10
        f.update({"sources":sources,"independent_sources":len(sources),"validation_score":round(min(score,1.0),2)})
        if score>=0.7:
            f["validation_state"]="evidence-backed"
            accepted.append(f)
        elif score>=0.35:
            f["validation_state"]="needs-review"
            review.append(f)
        else:
            f["validation_state"]="insufficient-evidence"
            rejected.append(f)
    return {"evidence_backed":accepted,"needs_review":review,"rejected":rejected,"counts":{"evidence_backed":len(accepted),"needs_review":len(review),"rejected":len(rejected)}}


def build_agent_workstreams(intelligence: dict, validation: dict) -> dict:
    return {
        "surface_mapping":{"priority":"high","items":intelligence.get("endpoint_count",0)},
        "javascript_analysis":{"priority":"high","items":len(intelligence.get("javascript_assets",[]))},
        "api_analysis":{"priority":"high","items":len(intelligence.get("api_candidates",[]))},
        "auth_session_analysis":{"priority":"high","items":len(intelligence.get("auth_state_candidates",[]))},
        "object_access_analysis":{"priority":"high","items":len(intelligence.get("research_queues",{}).get("object_access",[]))},
        "file_handling_analysis":{"priority":"medium","items":len(intelligence.get("upload_candidates",[]))},
        "evidence_correlation":{"priority":"critical","items":sum(validation.get("counts",{}).values())},
        "independent_validation":{"priority":"critical","items":len(validation.get("evidence_backed",[]))+len(validation.get("needs_review",[]))},
    }


def write_advanced_artifacts(out_dir: str | Path, intelligence: dict, validation: dict, workstreams: dict) -> None:
    root=Path(out_dir); root.mkdir(parents=True,exist_ok=True)
    (root/"application-intelligence.json").write_text(json.dumps(intelligence,ensure_ascii=False,indent=2),encoding="utf-8")
    (root/"validated-evidence.json").write_text(json.dumps(validation,ensure_ascii=False,indent=2),encoding="utf-8")
    (root/"agent-workstreams.json").write_text(json.dumps(workstreams,ensure_ascii=False,indent=2),encoding="utf-8")
