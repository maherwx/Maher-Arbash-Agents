# Rejected operations with observable side effects

`state_cases` is an HTTP workflow-manifest extension for an explicit policy:
an operation by another supplied identity must be denied and preserve selected
owner-observable fields. It checks state instead of trusting the denial status.
It can help investigate authorization checks performed after state changes or
partial updates that survive rejection. It does not automatically generate
attacks, infer policy or select new resources.

```json
"state_cases": [{
  "id": "denied-update-preserves-test-resource",
  "owner": "owner",
  "actor": "other",
  "observe": {"url": "https://your-authorized-app.example/api/test-resource/42"},
  "resource_proof": {"json_equals": {"/id": 42, "/owner_id": "test-owner"}},
  "preserve": ["/label", "/version", "/settings/visibility"],
  "action": {"url": "https://your-authorized-app.example/api/test-resource/42",
             "method": "PATCH", "body": {"label": "authorized-test"}},
  "denial": {"statuses": [403], "json_equals": {"/error": "forbidden"}}
}]
```

The containing manifest supplies both identities at the same exact application
origin, with credentials through the existing environment-variable mechanism.
Use deliberately chosen disposable authorized resources and meaningful invariant
fields. IDs, URLs, methods and bodies are all supplied explicitly. Observe uses
GET without a body; action uses POST/PUT/PATCH/DELETE once. Browser engine, browser
settings and variable templates are unsupported for these cases. The same
preflight scope/origin/credential-header rules validate both requests before
traffic; the existing request, elapsed-time and pacing budgets remain shared.

Execution reads the owner resource twice and requires complete HTTP 200 responses
matching the resource-specific JSON proof, with identical selected values. An
unstable baseline stops before the action. Then it sends the actor action once,
evaluates the explicit denial (which must declare 4xx statuses), and reads the
owner state twice again. It does not retry a mutation. Stable post-action state
that differs from the baseline, alongside a complete matching denial response,
produces an unvalidated state-integrity candidate listing changed JSON Pointers.
Concurrent writers or background processes can still explain the change;
causality, business impact and exploitability require independent review.

If the action response fails the declared denial, it still attempts the owner
reads within the remaining budget, but records the case as inconclusive rather
than treating an unexpected response as proof. Missing fields, malformed JSON,
partial bodies, transport failures, unstable post-state or exhausted budgets are
inconclusive. An action transport failure stops the case without automatic
replay; effects may be unknown. `action_requested` means the case reached its
action send call, not that network delivery or server execution is guaranteed.

At most 20 cases and 100 unique preserved JSON Pointers per case are accepted.
Selected field serialization is bounded to 64 KiB each and 256 KiB per snapshot.
Booleans and numbers are compared with the existing strict JSON type semantics.
Values stay in memory; evidence stores per-field SHA-256, identities, phase,
status, body hashes and assertion outcomes. These hashes are integrity labels,
not encryption; low-entropy values may be guessable. Raw selected values and
credential headers are not copied into evidence.

Cases execute after access cases and before ordinary workflows. They share
sessions and do not reset supplied state between baseline and follow-up reads.
There is no implicit rollback; an explicitly configured ordinary workflow can
perform restoration afterward, but it is not guaranteed after interruption,
transport errors or budget exhaustion. This covers owner-visible selected state,
not database auditing, asynchronous eventual effects, concurrency races or all
application mutation surfaces.

The extension is available through the existing `workflow-run`, `run` and
`auto-run --workflow-manifest` paths. No external model API/cloud dependency is
added. Development used static source/diff review only; no tests, applications,
scanners or assessments were run, and the feature is unverified at runtime.
