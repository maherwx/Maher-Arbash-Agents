# Direct local agent tool execution

`agent-tools-run` exposes the existing real subprocess adapters and feedback loop
without requiring the full recon pipeline first. It plans initial checks, launches
installed tools, records their outcomes, and schedules eligible complementary
checks from returned scoped evidence for one to three rounds. This is actual
future tool execution, not a report generator. No tool was launched to verify
this addition; source/diff review only, unverified at runtime.

Supply `targets.json` as an array of exact authorized URLs and `scope.json` using
the project's existing `assets` / `out_of_scope` format. Initial URLs outside
scope are rejected before planning. Example commands (not executed here):

```sh
maher-bounty agent-tools-run --targets targets.json --scope scope.json --authorized --plan-only --out results/tool-plan
maher-bounty agent-tools-run --targets targets.json --scope scope.json --authorized --rounds 3 --out results/tools
```

The default is native fixed planning. For local model reasoning, install the
optional `local-inference` dependency and supply an already downloaded compatible
GGUF file. Nothing downloads a model or calls an external/local HTTP model API:

```sh
export MAHER_GGUF_MODEL=/absolute/path/to/your-model.gguf
maher-bounty agent-tools-run --targets targets.json --scope scope.json --authorized --local-model --out results/model-tools
```

An explicitly requested unavailable model stops before tool execution; it does
not silently fall back. Two local model roles review initial inventory and actual
execution evidence, including preceding peer reviews, and request complementary
checks. Roles share one model instance; they are not separate installed models.
Without the GGUF option, native planning does not perform language-model reasoning.
`--plan-only --local-model` still loads/runs local inference for planning, but does
not launch target tools. Model errors and candidate claims are recorded without
being promoted to verified findings.

Optional `--requests workers.json` accepts initial worker packets:

```json
[
  {"agent": "surface_executor", "tool_requests": [
    {"tool": "httpx", "targets": ["https://your-authorized-app.example/"],
     "reason": "Check supplied endpoint responsiveness"},
    {"tool": "whatweb", "targets": ["https://your-authorized-app.example/"]}
  ]}
]
```

These are initial requests, not an exclusive tool list. Later rounds use the
existing scoped feedback planner; model planning can also add requests when
enabled. Tool names must match existing adapters; no shell text, executable paths,
extra flags or payload fields are accepted. Requests use exact initial URLs;
crawler discoveries are rechecked against scope by the coordinator before reuse.
At most 120 initial URLs/packets, 20 requests per worker and 1 MiB per input JSON
file; duplicate fields/nonfinite constants are rejected. Existing per-round
request/target/origin and tool process timeout/output limits still apply.

Supported adapters include httpx, katana, nuclei, dalfox, ZAP baseline, nmap,
ffuf and the other router tools. Processes execute through argument arrays and
the process-tree runtime, not a shell interpreter. Missing installations,
nonzero exit codes, launch failures, timeouts and output limits remain explicit.
The router is not an unrestricted interactive terminal, does not install tools,
and does not implement arbitrary Burp extensions or full commercial Burp scanning.
Authenticated browser requests need a supplied workflow profile through the
existing workflow/full-pipeline path; this direct command rejects that adapter.

Artifacts: `agent-tool-plan.json`, `agent-tool-results.json` and per-round
execution files/checkpoints. Plan generation is distinct from execution;
`finished` means the bounded loop ended, not that scans succeeded or vulnerabilities
were exhaustively assessed. Inspect `run_status_counts`, execution decisions,
stop reason and deferred work. A successful process exit is not a security result.
Model reviews are separate from the adapters' actual findings. Outputs may contain
sensitive URLs, tool output and model excerpts; keep them private. Checkpoints
support existing programmatic recovery, but this command does not expose resume.
Use a fresh output directory; a new invocation must not be treated as a continuation
or automatically repeat uncertain prior mutation effects.
