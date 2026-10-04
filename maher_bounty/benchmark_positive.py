from __future__ import annotations


def scaled_positive_cases(BenchmarkCase, entry):
    """Diverse deterministic positive controls for protocol and workflow recall."""
    cases = []
    for i in range(8):
        cases.append(BenchmarkCase(
            f"positive_graphql_{i:02d}",
            {"log":{"entries":[entry(
                f"https://bench.test/gql/{i}", method="POST",
                headers=[{"name":"Content-Type","value":"application/json"}],
                body='{"query":"query Viewer%d { viewer { id } }"}' % i,
                response_headers=[{"name":"Content-Type","value":"application/json"}],
                response_body='{"data":{"viewer":{"id":"%d"}}}' % i,
            )]}}, expected_protocols=("graphql",), expected_priority_min=1))
    for i in range(8):
        cases.append(BenchmarkCase(
            f"positive_grpc_{i:02d}",
            {"log":{"entries":[entry(
                f"https://bench.test/pkg.Service/Method{i}", method="POST",
                headers=[{"name":"Content-Type","value":"application/grpc+proto" if i % 2 else "application/grpc"}],
                response_headers=[{"name":"grpc-status","value":"0"}],
            )]}}, expected_protocols=("grpc",), expected_priority_min=1))
    for i in range(6):
        cases.append(BenchmarkCase(
            f"positive_openapi_{i:02d}",
            {"log":{"entries":[entry(
                f"https://bench.test/spec/{i}.json",
                response_headers=[{"name":"Content-Type","value":"application/json"}],
                response_body='{"openapi":"3.1.0","info":{"title":"S%d","version":"1"},"paths":{"/health":{}}}' % i,
            )]}}, expected_protocols=("openapi",), expected_priority_min=1))
    for i in range(6):
        cases.append(BenchmarkCase(
            f"positive_websocket_{i:02d}",
            {"log":{"entries":[entry(
                f"wss://stream{i}.bench.test/events",
                headers=[{"name":"Upgrade","value":"websocket"}],
            )]}}, expected_protocols=("websocket",), expected_priority_min=1))
    return cases
