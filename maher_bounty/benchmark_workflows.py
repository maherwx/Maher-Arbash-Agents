from __future__ import annotations


def workflow_cases(BenchmarkCase, entry):
    """Multi-step identity controls that exercise correlation beyond single requests."""
    cases=[]
    for i in range(10):
        alpha=f"session=alpha-{i}"; beta=f"session=beta-{i}"
        same=[
            entry(f"https://bench.test/wf/{i}/start",started=f"2026-01-01T00:00:{i*4:02d}Z",headers=[{"name":"Cookie","value":alpha}]),
            entry(f"https://bench.test/wf/{i}/account",status=200,started=f"2026-01-01T00:00:{i*4+1:02d}Z",headers=[{"name":"Cookie","value":alpha}]),
            entry(f"https://bench.test/wf/{i}/start",started=f"2026-01-01T00:00:{i*4+2:02d}Z",headers=[{"name":"Cookie","value":beta}]),
            entry(f"https://bench.test/wf/{i}/account",status=200,started=f"2026-01-01T00:00:{i*4+3:02d}Z",headers=[{"name":"Cookie","value":beta}]),
        ]
        cases.append(BenchmarkCase(f"workflow_equal_{i:02d}",{"log":{"entries":same}},expected_min_records=4,expected_no_protocols=True))

    for i in range(10):
        alpha=f"session=owner-{i}"; beta=f"session=peer-{i}"
        base=i*4
        divergent=[
            entry(f"https://bench.test/div/{i}/start",started=f"2026-01-01T00:01:{base:02d}Z",headers=[{"name":"Cookie","value":alpha}]),
            entry(f"https://bench.test/div/{i}/resource",status=200,started=f"2026-01-01T00:01:{base+1:02d}Z",headers=[{"name":"Cookie","value":alpha}]),
            entry(f"https://bench.test/div/{i}/start",started=f"2026-01-01T00:01:{base+2:02d}Z",headers=[{"name":"Cookie","value":beta}]),
            entry(f"https://bench.test/div/{i}/resource",status=403,started=f"2026-01-01T00:01:{base+3:02d}Z",headers=[{"name":"Cookie","value":beta}]),
        ]
        cases.append(BenchmarkCase(f"workflow_divergent_{i:02d}",{"log":{"entries":divergent}},expected_min_records=4,expected_workflow_divergence_min=1,expected_priority_min=1))
    return cases
