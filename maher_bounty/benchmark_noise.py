from __future__ import annotations


def protocol_noise_cases(BenchmarkCase, entry):
    """Benign traffic containing protocol vocabulary but no real protocol signal."""
    cases=[]
    words=("graphql","grpc","swagger","openapi","websocket","mutation","subscription","grpc-status")
    for i in range(16):
        word=words[i % len(words)]
        cases.append(BenchmarkCase(
            f"noise_vocab_{i:02d}",
            {"log":{"entries":[entry(
                f"https://bench.test/help/{word}/{i}",
                headers=[{"name":"Accept","value":"text/html"}],
                response_headers=[{"name":"Content-Type","value":"text/html"}],
                response_body=f"<html><body>Documentation article discussing {word} as plain text example {i}.</body></html>",
            )]}}, expected_no_protocols=True))
    return cases
