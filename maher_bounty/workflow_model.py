from __future__ import annotations

from collections import defaultdict

STATE_WORDS = ("draft","pending","created","verified","approved","rejected","active","disabled","cancelled","canceled","paid","refunded","completed","failed","invited","accepted")


def infer_workflows(inventory: dict) -> list[dict]:
    """Infer possible state-oriented route families from collected endpoint names."""
    families = defaultdict(lambda: {"states": set(), "routes": set()})
    for item in inventory.get("endpoints", []) or []:
        value = item.get("value", "") if isinstance(item, dict) else str(item)
        low = value.lower()
        matched = [s for s in STATE_WORDS if s in low]
        if not matched:
            continue
        base = low
        for state in matched:
            base = base.replace(state, "{state}")
        fam = families[base]
        fam["states"].update(matched)
        fam["routes"].add(value)
    out = []
    for key, data in families.items():
        out.append({
            "family": key,
            "observed_states": sorted(data["states"]),
            "routes": sorted(data["routes"])[:50],
            "research_questions": [
                "Are state transitions enforced consistently across roles and interfaces?",
                "Can equivalent actions be reached through alternate routes with different validation?",
                "Do stale or legacy routes enforce the same state invariants?",
            ],
        })
    return sorted(out, key=lambda x: (-len(x["observed_states"]), x["family"]))[:100]
