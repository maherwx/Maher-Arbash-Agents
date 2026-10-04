from __future__ import annotations

from collections import defaultdict
from urllib.parse import urlparse


def _host(value: str) -> str:
    try:
        return (urlparse(value).hostname or "").lower()
    except Exception:
        return ""


def correlate_evidence(*sources: dict) -> dict:
    """Correlate independently observed protocol/evidence signals by host and protocol.

    This is deliberately conservative: a correlation is promoted only when at least
    two independent source labels support the same (host, protocol) key.
    """
    buckets=defaultdict(lambda:{"sources":set(),"items":[]})
    for source_index,source in enumerate(sources):
        label=str(source.get("source") or f"source-{source_index}")
        signals=source.get("signals") or source.get("protocols",{}).get("signals",[])
        for signal in signals:
            protocol=str(signal.get("protocol") or "").lower()
            metadata=signal.get("metadata") or {}
            value=str(metadata.get("url") or signal.get("key") or "")
            host=_host(value)
            if not protocol or not host:
                continue
            key=(host,protocol)
            buckets[key]["sources"].add(label)
            buckets[key]["items"].append(signal)
    correlations=[]
    for (host,protocol),bucket in sorted(buckets.items()):
        labels=sorted(bucket["sources"])
        if len(labels)<2:
            continue
        correlations.append({"host":host,"protocol":protocol,"source_count":len(labels),"sources":labels,"evidence_count":len(bucket["items"]),"confidence":round(min(0.99,0.70+0.10*len(labels)),2)})
    return {"correlation_count":len(correlations),"correlations":correlations}
