from __future__ import annotations


def adversarial_cases(BenchmarkCase, entry):
    return [
        BenchmarkCase(
            "graphql_path_but_not_graphql",
            {"log":{"entries":[entry(
                "https://bench.test/graphql",
                method="POST",
                headers=[{"name":"Content-Type","value":"application/json"}],
                body='{"message":"query status for customer"}',
                response_body='{"ok":true}',
            )]}},
            expected_no_protocols=True,
        ),
        BenchmarkCase(
            "grpc_word_but_plain_json",
            {"log":{"entries":[entry(
                "https://bench.test/api/grpc-status",
                headers=[{"name":"Accept","value":"application/json"}],
                response_headers=[{"name":"Content-Type","value":"application/json"}],
                response_body='{"grpc-status":"documentation-only"}',
            )]}},
            expected_no_protocols=True,
        ),
        BenchmarkCase(
            "swagger_word_in_business_text",
            {"log":{"entries":[entry(
                "https://bench.test/articles/branding",
                response_headers=[{"name":"Content-Type","value":"application/json"}],
                response_body='{"title":"Swagger as a product name","body":"ordinary content"}',
            )]}},
            expected_no_protocols=True,
        ),
        BenchmarkCase(
            "websocket_word_without_ws_url",
            {"log":{"entries":[entry(
                "https://bench.test/docs/realtime",
                response_body="This page explains websocket concepts without opening a socket.",
            )]}},
            expected_no_protocols=True,
        ),
        BenchmarkCase(
            "ordinary_403_not_identity_divergence",
            {"log":{"entries":[entry(
                "https://bench.test/private",
                status=403,
                headers=[{"name":"Cookie","value":"session=alpha"}],
            )]}},
            expected_no_protocols=True,
        ),
        BenchmarkCase(
            "ordinary_429_not_protocol_signal",
            {"log":{"entries":[entry(
                "https://bench.test/api/search",
                status=429,
                response_headers=[{"name":"Retry-After","value":"60"}],
            )]}},
            expected_no_protocols=True,
        ),
    ]
