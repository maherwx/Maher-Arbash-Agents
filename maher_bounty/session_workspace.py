from __future__ import annotations

from dataclasses import dataclass, field

@dataclass
class TestIdentity:
    name: str
    role: str = "unknown"
    tenant: str = "default"
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    metadata: dict = field(default_factory=dict)

class SessionWorkspace:
    """In-memory identity/session model for controlled comparative research."""
    def __init__(self):
        self.identities: dict[str, TestIdentity] = {}

    def add(self, identity: TestIdentity):
        self.identities[identity.name] = identity

    def matrix(self) -> list[dict]:
        names = sorted(self.identities)
        rows = []
        for source in names:
            for target in names:
                a, b = self.identities[source], self.identities[target]
                rows.append({
                    "source": source,
                    "target": target,
                    "same_role": a.role == b.role,
                    "same_tenant": a.tenant == b.tenant,
                    "source_role": a.role,
                    "target_role": b.role,
                    "source_tenant": a.tenant,
                    "target_tenant": b.tenant,
                })
        return rows
