from __future__ import annotations

from urllib.parse import urlparse


def _values(raw) -> list[str]:
    if not isinstance(raw, list):
        return []
    values = []
    for item in raw:
        if isinstance(item, str):
            values.append(item)
        elif isinstance(item, dict):
            value = item.get("url") or item.get("host") or item.get("value") or item.get("asset")
            if isinstance(value, str):
                values.append(value)
    return values


def _parsed_rule(raw: str):
    value = raw.strip().lower()
    wildcard = value.startswith("*.")
    if wildcard:
        value = value[2:]
    parsed = urlparse(value if "://" in value else "//" + value)
    host = (parsed.hostname or "").rstrip(".")
    if host.startswith("*."):
        wildcard = True
        host = host[2:]
    if not host:
        return None
    scheme = parsed.scheme.lower() if parsed.scheme.lower() in {"http", "https"} else "https"
    try:
        port = parsed.port
    except ValueError:
        return None
    return host, wildcard, scheme, port


def _host_from_url(value: str) -> str | None:
    raw = value.strip()
    parsed = urlparse(raw if "://" in raw else "https://" + raw)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        return None
    if parsed.username is not None or parsed.password is not None:
        return None
    return parsed.hostname.lower().rstrip(".")


def _matches(host: str, pattern: tuple[str, bool]) -> bool:
    base, wildcard = pattern
    if not wildcard:
        return host == base
    return host != base and host.endswith("." + base)


def is_in_scope_url(value: str, scope: dict | None = None, *, target: str | None = None) -> bool:
    """Return whether an HTTP(S) URL is explicitly in scope; exclusions always win."""
    if not isinstance(value, str):
        return False
    if value != value.strip():
        return False
    host = _host_from_url(value)
    if not host:
        return False

    scope = scope if isinstance(scope, dict) else {}
    allow_values = _values(scope.get("assets"))
    if target:
        allow_values.append(target)
    allowed = []
    for raw in allow_values:
        parsed = _parsed_rule(raw)
        if parsed:
            allowed.append((parsed[0], parsed[1]))
    if not any(_matches(host, pattern) for pattern in allowed):
        return False

    excluded = []
    for raw in _values(scope.get("out_of_scope")):
        parsed = _parsed_rule(raw)
        if parsed:
            excluded.append((parsed[0], parsed[1]))
    return not any(_matches(host, pattern) for pattern in excluded)


def filter_in_scope_urls(values, scope: dict | None = None, *, target: str | None = None) -> tuple[list[str], list[str]]:
    """Split URL candidates into allowed and rejected lists while preserving order."""
    allowed, rejected, seen = [], [], set()
    for value in values:
        if not isinstance(value, str) or not value.strip():
            continue
        candidate = value
        if candidate not in seen:
            seen.add(candidate)
            (allowed if is_in_scope_url(candidate, scope, target=target) else rejected).append(candidate)
    return allowed, rejected


def scope_seed_targets(scope: dict | None, *, target: str | None = None) -> list[str]:
    """Return distinct enumeration seeds without rewriting explicit URL assets."""
    scope = scope if isinstance(scope, dict) else {}
    values = _values(scope.get("assets"))
    if target:
        values.insert(0, target)
    excluded = []
    for raw in _values(scope.get("out_of_scope")):
        parsed = _parsed_rule(raw)
        if parsed:
            excluded.append((parsed[0], parsed[1]))
    seeds, seen = [], set()
    for raw in values:
        parsed = _parsed_rule(raw)
        if not parsed:
            continue
        host, wildcard, scheme, port = parsed
        if any(_matches(host, pattern) for pattern in excluded):
            continue
        if wildcard:
            authority = f"[{host}]" if ":" in host else host
            if port:
                authority = f"{authority}:{port}"
            seed = f"{scheme}://{authority}"
        else:
            seed = raw
        if seed not in seen:
            seen.add(seed)
            seeds.append(seed)
    return seeds


def scope_target_urls(scope: dict | None, inventory: dict | None, *, target: str | None = None) -> tuple[list[str], list[str]]:
    """Return in-scope URL strings verbatim; parsing is used only for authorization."""
    scope = scope if isinstance(scope, dict) else {}
    inventory = inventory if isinstance(inventory, dict) else {}
    candidates = []
    asset_values = _values(scope.get("assets"))
    for raw in asset_values:
        parsed = _parsed_rule(raw)
        if parsed and not parsed[1]:
            candidates.append(raw if "://" in raw else f"{parsed[2]}://{raw}")
    if target:
        parsed_target = _parsed_rule(target)
        candidates.append(target if "://" in target else (f"{parsed_target[2]}://{target}" if parsed_target else target))
    for row in inventory.get("hosts", []):
        value = row if isinstance(row, str) else row.get("value") or row.get("host") if isinstance(row, dict) else None
        if isinstance(value, str) and value.strip() and not value.strip().startswith("*."):
            # Host-only inventory rows need a scheme; URL rows remain byte-for-byte intact.
            candidates.append(value if "://" in value else "https://" + value)
    for row in inventory.get("endpoints", []):
        value = row if isinstance(row, str) else row.get("value") or row.get("url") if isinstance(row, dict) else None
        if isinstance(value, str):
            candidates.append(value)

    fallback_target = target if not asset_values else None
    return filter_in_scope_urls(candidates, scope, target=fallback_target)
