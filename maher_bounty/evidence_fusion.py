from __future__ import annotations

from collections import defaultdict
from urllib.parse import urlparse


def _host(value: str) -> str:
    try:
        return (urlparse(value).hostname or "").lower()
    except Exception:
        return ""


def normalize_source(label: str, payload: dict) -> dict:
    signals=[]
    raw=payload.get("signals") or payload.get("protocols",{}).get("signals",[])
    for item in raw:
        protocol=str(item.get("protocol") or "").lower().strip()
        metadata=item.get("metadata") or {}
        url=str(metadata.get("url") or item.get("url") or item.get("key") or "")
        host=_host(url)
        if protocol and host:
            signals.append({"protocol":protocol,"host":host,"url":url,"key":str(item.get("key") or ""),"source":label})
    return {"source":label,"signals":signals}


def fuse_sources(*sources: dict) -> dict:
    """Fuse normalized independent evidence without promoting single-source claims."""
    buckets=defaultdict(lambda:{"sources":set(),"items":[]})
    for source in sources:
        label=str(source.get("source") or "unknown")
        normalized=normalize_source(label,source)
        for item in normalized["signals"]:
            key=(item["host"],item["protocol"])
            buckets[key]["sources"].add(label)
            buckets[key]["items"].append(item)
    agreements=[]; disagreements=[]
    by_host=defaultdict(set)
    for (host,protocol),bucket in buckets.items():
        by_host[host].add(protocol)
        labels=sorted(bucket["sources"])
        if len(labels)>=2:
            agreements.append({"host":host,"protocol":protocol,"sources":labels,"source_count":len(labels),"evidence_count":len(bucket["items"]),"confidence":round(min(0.99,0.72+0.08*len(labels)),2)})
    for host,protocols in sorted(by_host.items()):
        if len(protocols)>1:
            disagreements.append({"host":host,"protocols":sorted(protocols),"reason":"independent sources observed different protocol classes; retain both until corroborated"})
    agreements.sort(key=lambda x:(-x["source_count"],x["host"],x["protocol"]))
    return {"source_count":len({str(s.get("source") or "unknown") for s in sources}),"agreement_count":len(agreements),"disagreement_count":len(disagreements),"agreements":agreements,"disagreements":disagreements}
