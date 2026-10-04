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


def _host_rule(raw: str):
    value = raw.strip().lower()
    if not value:
        return None
    wildcard = value.startswith("*.")
    if wildcard:
        value = value[2:]
    parsed = urlparse(value if "://" in value else "//" + value)
    host = (parsed.hostname or "").rstrip(".")
    if host.startswith("*."):
        wildcard = True
        host = host[2:]
    return (host, wildcard) if host else None


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
    host = _host_from_url(value)
    if not host:
        return False

    scope = scope if isinstance(scope, dict) else {}
    allow_values = _values(scope.get("assets"))
    if target:
        allow_values.append(target)
    allowed = [p for raw in allow_values if (p := _host_rule(raw))]
    if not any(_matches(host, pattern) for pattern in allowed):
        return False

    excluded = [p for raw in _values(scope.get("out_of_scope")) if (p := _host_rule(raw))]
    return not any(_matches(host, pattern) for pattern in excluded)


def filter_in_scope_urls(values, scope: dict | None = None, *, target: str | None = None) -> tuple[list[str], list[str]]:
    """Split URL candidates into allowed and rejected lists while preserving order."""
    allowed, rejected, seen = [], [], set()
    for value in values:
        if not isinstance(value, str) or not value.strip():
            continue
        candidate = value.strip()
        if candidate not in seen:
            seen.add(candidate)
            (allowed if is_in_scope_url(candidate, scope, target=target) else rejected).append(candidate)
    return allowed, rejected
