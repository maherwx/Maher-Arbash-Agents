from __future__ import annotations


def scaled_negative_cases(BenchmarkCase, entry, count: int = 36):
    """Deterministic benign controls used to pressure-test false-positive behavior."""
    cases = []
    templates = (
        ("json", "/api/items/{i}", '{"items":[],"page":%d}'),
        ("docs", "/docs/topic/{i}", "ordinary documentation page %d"),
        ("health", "/health/{i}", "ok-%d"),
        ("search", "/search?q=item-{i}", '{"results":[],"query":"item-%d"}'),
    )
    for i in range(count):
        kind, path, body = templates[i % len(templates)]
        response_headers = [{"name":"Content-Type","value":"application/json"}] if kind in {"json","search"} else []
        cases.append(BenchmarkCase(
            f"scaled_negative_{kind}_{i:02d}",
            {"log":{"entries":[entry(
                "https://bench.test" + path.format(i=i),
                headers=[{"name":"Accept","value":"application/json"}] if response_headers else [],
                response_headers=response_headers,
                response_body=body % i,
            )]}},
            expected_no_protocols=True,
        ))
    return cases
