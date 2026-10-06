# Native executable policy agents

`policy-agents-run` connects declared application tests to native planning,
execution, outcome analysis and evidence review workers:

```sh
maher-bounty policy-agents-run assessment.json --scope scope.json --authorized --out results/policy-agents
```

It accepts the same supplied identities, `access_cases`, `state_cases` and
`workflows` as `workflow-run`. To use it within the existing scanner pipeline,
add `"agent_policy_execution": true` to that workflow manifest and use
`run` / `auto-run --workflow-manifest assessment.json`. This routes the manifest
through policy agents instead of executing it again via the direct path.
Existing shell-backed scanner agents and authenticated browser checks remain
separate complementary execution paths. These commands were not run during
development of the change.

The planner creates case references grouped under access-policy, state-integrity
and workflow-invariant executor roles. Native request admission shares the
shell-tool router's role-round-robin helper, with at most 20 tool requests from
120 packets and 100 declared cases. The programmatic `run_policy_agents` API
also accepts worker packets in this exact shape:

```json
[{"agent": "access_policy_executor", "tool_requests": [
  {"tool": "policy-case", "case_refs": ["private-test-order"]}
]}]
```

Unknown references, unsupported fields or tools are rejected. Requests cannot
replace a declared URL, method, body, identity, policy or credential. Duplicate
case references execute once. If no case is admitted, execution is `not_run`;
selection is not a test outcome. Catalog and plan artifacts omit the original
request bodies and credential configuration.

Selected cases execute as one combined manifest. Original access/state/workflow
ordering, isolated credentials, state captures, cleanup semantics, request/time
limits and pacing are preserved. They are not executed concurrently, split into
independently reset budgets or automatically retried after mutation. This is
important for ordered application lifecycles and ambiguous side effects.
Unselected cases are not covered by the resulting assessment.

The outcome analyst maps actual decisions to case references and requesting
roles, including completed, invariant-failed and inconclusive outcomes. Findings
and incomplete cases still need review. The evidence reviewer checks that
findings cite a selected case and actual observations. A previously validated
access finding must retain two allowed controls per declared allowed identity
and two complete matching denied observations for its reported identity; lacking
those controls downgrades it to an unvalidated candidate. State/invariant
findings remain candidates requiring causality/impact review. Review does not
promote arbitrary findings to validated status.

Artifacts include `policy-agent-plan.json`, authoritative reviewed
`policy-agent-results.json` and matching `execution/workflow-evidence.json`, all
through bounded atomic JSON replacement. They record native worker outcomes,
admissions, request count, evidence and review levels. Raw credentials and
response bodies are omitted by the underlying evidence engine; identifiers,
paths, field hashes and assertions may still be sensitive.

These are fixed native policy workers that operate without model inference,
external model APIs or cloud services. They do not independently discover
business rules, invent identities, execute arbitrary shell commands or act as
general reasoning models. Optional GGUF/shell-agent capabilities elsewhere in
the project are not claimed to have run here. User-defined policies and supplied
identities remain necessary for meaningful tests.

Only static source/diff review was performed. No tests, models, tool processes,
applications, browsers or assessments ran; the feature is unverified at runtime.
