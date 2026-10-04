from __future__ import annotations


def stress_cases(BenchmarkCase, entry):
    """Larger mixed HAR controls for stability, ordering, and signal isolation."""
    cases=[]
    for i in range(6):
        entries=[]
        for j in range(30):
            entries.append(entry(
                f"https://bench.test/stress/{i}/item/{j}",
                started=f"2026-01-02T00:{i:02d}:{j:02d}Z",
                response_headers=[{"name":"Content-Type","value":"application/json"}],
                response_body='{"ok":true,"item":%d}' % j,
            ))
        cases.append(BenchmarkCase(f"stress_benign_{i:02d}",{"log":{"entries":entries}},expected_min_records=30,expected_no_protocols=True))

    for i in range(6):
        entries=[]
        for j in range(24):
            entries.append(entry(
                f"https://bench.test/mixed/{i}/item/{j}",
                started=f"2026-01-02T01:{i:02d}:{j:02d}Z",
                response_headers=[{"name":"Content-Type","value":"application/json"}],
                response_body='{"ok":true,"item":%d}' % j,
            ))
        entries.append(entry(
            f"https://bench.test/mixed/{i}/graphql",method="POST",
            started=f"2026-01-02T01:{i:02d}:24Z",
            headers=[{"name":"Content-Type","value":"application/json"}],
            body='{"query":"query Stress%d { viewer { id } }"}' % i,
            response_headers=[{"name":"Content-Type","value":"application/json"}],
            response_body='{"data":{"viewer":{"id":"1"}}}',
        ))
        entries.append(entry(
            f"https://bench.test/mixed/{i}/pkg.Service/Method",method="POST",
            started=f"2026-01-02T01:{i:02d}:25Z",
            headers=[{"name":"Content-Type","value":"application/grpc"}],
            response_headers=[{"name":"grpc-status","value":"0"}],
        ))
        cases.append(BenchmarkCase(f"stress_mixed_{i:02d}",{"log":{"entries":entries}},expected_min_records=26,expected_protocols=("graphql","grpc"),expected_priority_min=1))
    return cases
