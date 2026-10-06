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
sslscan, ffuf and the other router tools. sslscan is limited to HTTPS origins
already in scope and receives a fixed host/port argument; HTTP URLs are filtered.
It adds local TLS configuration/certificate output, not application exploit proof.
Processes execute through argument arrays and
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
support native completed-round recovery via `--resume`, as described below.
Use a fresh output directory for a new invocation; existing state requires an
explicit recovery request and must not automatically repeat uncertain effects.

## Complete recorded finding report

At the end of actual execution the command writes `findings-report.json` and
`findings-report.md` and prints their paths. Every finding in the tool execution
ledger is included, with its entire original record, source fields, exact-record
hash, verification label and missing-detail list. Exact duplicates remain visible
with occurrence counts; nothing is silently discarded or promoted by deduplication.
Each record keeps the evidence, target, severity, reproduction, impact and
remediation that its adapter actually supplied. Missing details are explicitly
listed rather than generated as unsupported claims. Tool-reported `validated`
is labeled `tool_reported_validated`, not independently confirmed impact.

All candidate findings returned in recorded local model reviews are included in
a separate unverified hypothesis section. They never become tool-validated
findings by appearing in the report. Findings without an adapter validation flag
remain candidates for review. The execution section retains all recorded runs,
decisions, rounds, initial targets, scope, status counts, stop reason and deferred
request count, including failed/missing tools. This is complete coverage of the
recorded ledgers, not all possible vulnerabilities or every unparsed message in
raw tool output. No exploit instructions, remediation or impact are invented.

The plan also records the supported-tool execution policy: fixed tool adapters,
no arbitrary shell text or agent-selected executable paths. The existing router
enforces those restrictions at execution time. These reports add no general
terminal, file-management or package-installation privileges.

Actual execution results are saved before report rendering. Report publication
failure does not remove that results artifact; the CLI reports an error directing
the user to it. Markdown is atomically replaced with a 16 MiB cap, authoritative
JSON uses the existing 8 MiB cap. Exceeding a cap fails explicitly instead of
truncating finding records. Both reports identify the same generation hash;
compare hashes before combining them after interruption/concurrent writers.
This is not a two-file transaction. Reports contain sensitive originals and
must remain private. No tests/tools/models/applications were run to verify this
addition; it remains unverified at runtime.

## Recorded evidence review

Direct execution now attaches an explicit review to every tool finding. Missing
targets/evidence and out-of-scope reported targets are flagged while their original
records remain in the report. Other scanner messages require independent
validation; `validated: true`, severity and repeated messages alone cannot
establish execution proof or confirmed impact. Local model reviewers receive the
same recorded-evidence review with execution feedback, and cannot change it by
claiming that a hypothesis is validated.

Browser marker findings may receive `recorded_browser_execution_proof` only when
two distinct valid marker tokens/attributes and the passed negative control match
the recorded confirmed check for the same query occurrence, tool and target hash.
Authenticated browser records also require matching identity and profile metadata.
The direct command does not enable authenticated browser execution on its own;
that adapter still requires the existing workflow profile path. These checks
compare records from the same invocation, not independent browser reruns, and
never confirm application impact. Existing host-based scope policy remains.

Dalfox text extraction no longer promotes a line to validated solely because it
contains `verified`. Whole-word negative/unverified statements are excluded from
the textual candidate classifier; positive scanner text remains an unvalidated
candidate needing browser proof. This classification also affects the existing
full pipeline because it shares the extractor. There is no new target request,
exploit execution or scanner launch in the review layer. Source/diff review only;
runtime behavior has not been tested.

## Execution outcomes

Results now include `execution_outcome`, also recomputed from the run ledger in
the JSON/Markdown report summary. The existing `status: finished` means the
coordinator returned, even if every recorded tool failed; it is not a success
certificate. The new state distinguishes no runs, all recorded runs failed,
all recorded runs OK, and mixed/partial recorded runs. Counts expose failed,
partial and unknown run statuses, and incomplete HTTP probe inventory extraction.
Unknown statuses are not counted as successful or automatically called failures.

Remaining native/deferred request counts, pending proposal count and stop reason
are shown alongside the outcome. These counts are not unique targets and must
not be added as an exhaustive coverage count. All recorded runs OK can coexist
with unfinished proposals; it means only that those recorded processes reported
OK and their recorded probe extraction was not incomplete. It does not establish
vulnerability absence, account authorization, exploit validity or application
impact. Existing CLI exit behavior and execution budgets remain unchanged.
This update received source/diff review only and is unverified at runtime;
no tests, tool execution, models, applications or assessments ran.

## Native execution recovery

`--resume` exposes the existing completed-round journal recovery for the native
fixed planner. Supply the same targets, scope, initial requests (if used), round
limit and output directory as the original invocation. The existing binding,
checksum, scope revalidation and exclusive journal lock still apply. An example
command, not executed here:

```sh
maher-bounty agent-tools-run --targets targets.json --scope scope.json --authorized --rounds 3 --resume --out results/tools
```

Recovery requires a checkpoint marked `completed_round`. A checkpoint marked
`running_round` has uncertain effects and is rejected; there is no automatic
replay, stale-lock removal, rollback or exactly-once guarantee. A completed
terminal checkpoint reuses saved execution results and regenerates evidence
review/reports without restarting tools. A nonterminal completed-round checkpoint
continues only within its original round budget. Changing tool availability can
change the native initial plan and cause the binding check to reject recovery.

`--resume` cannot be combined with `--plan-only` or `--local-model`; local model
review history is not restored by this command. It retains the original plan
artifact before validation and does not overwrite reports/results when journal
validation fails. Successful recovery records `execution_resumed: true`; the CLI
also prints the recorded execution outcome. The desktop form inherits the new
option from the shared parser. This is recovery for direct agent execution only,
not a resume switch for full reconnaissance or authenticated workflow runs.

No runtime recovery or parser execution was performed. This extension received
source/diff review only and remains unverified at runtime.
