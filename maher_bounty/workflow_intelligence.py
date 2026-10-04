from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, asdict
from urllib.parse import urlparse


@dataclass(slots=True)
class Transition:
    source: str
    target: str
    method: str
    status: int | None
    identity: str | None
    tenant: str | None
    observations: int = 1

    def as_dict(self) -> dict:
        return asdict(self)


def _state(record: dict) -> str:
    url = urlparse(str(record.get("url", "")))
    path = url.path or "/"
    method = str(record.get("method", "GET")).upper()
    return f"{method} {url.netloc}{path}"


def build_workflow_model(records: list[dict]) -> dict:
    """Infer state transitions from ordered HTTP observations without replaying traffic."""
    sessions = defaultdict(list)
    for idx, record in enumerate(records):
        session = str(record.get("session") or record.get("identity") or "anonymous")
        order = record.get("timestamp") or record.get("sequence") or idx
        sessions[session].append((order, idx, record))

    transition_counts = Counter()
    transition_meta: dict[tuple, dict] = {}
    state_counts = Counter()

    for session, items in sessions.items():
        items.sort(key=lambda x: (str(x[0]), x[1]))
        previous = None
        for _, _, record in items:
            current = _state(record)
            state_counts[current] += 1
            if previous is not None:
                key = (
                    previous,
                    current,
                    str(record.get("method", "GET")).upper(),
                    record.get("status"),
                    record.get("identity"),
                    record.get("tenant"),
                )
                transition_counts[key] += 1
                transition_meta[key] = {"session": session}
            previous = current

    transitions = []
    for key, count in transition_counts.items():
        source, target, method, status, identity, tenant = key
        transitions.append(Transition(source, target, method, status, identity, tenant, count).as_dict())

    incoming = Counter(t["target"] for t in transitions)
    outgoing = Counter(t["source"] for t in transitions)
    entry_states = [s for s in state_counts if incoming[s] == 0]
    terminal_states = [s for s in state_counts if outgoing[s] == 0]
    branch_states = [s for s, n in outgoing.items() if n > 1]

    return {
        "session_count": len(sessions),
        "state_count": len(state_counts),
        "transition_count": len(transitions),
        "states": [{"id": s, "observations": n, "incoming": incoming[s], "outgoing": outgoing[s]} for s, n in state_counts.most_common()],
        "transitions": sorted(transitions, key=lambda x: (-x["observations"], x["source"], x["target"])),
        "entry_states": sorted(entry_states),
        "terminal_states": sorted(terminal_states),
        "branch_states": sorted(branch_states),
    }


def compare_identity_workflows(model: dict) -> dict:
    """Find structurally equivalent transitions whose observed outcomes differ by identity/tenant."""
    groups = defaultdict(list)
    for t in model.get("transitions", []):
        groups[(t["source"], t["target"], t["method"])].append(t)

    divergences = []
    for (source, target, method), rows in groups.items():
        contexts = {(r.get("identity"), r.get("tenant")) for r in rows}
        statuses = {r.get("status") for r in rows}
        if len(contexts) > 1 and len(statuses) > 1:
            divergences.append({
                "source": source,
                "target": target,
                "method": method,
                "contexts": [{"identity": r.get("identity"), "tenant": r.get("tenant"), "status": r.get("status"), "observations": r.get("observations")} for r in rows],
                "signal": "identity_or_tenant_workflow_divergence",
                "priority": "high",
            })
    return {"divergence_count": len(divergences), "divergences": divergences}
