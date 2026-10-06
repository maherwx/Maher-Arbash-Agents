# Authenticated access policies and workflow invariants

HTTP access cases support supplied [GraphQL field authorization queries](graphql-field-authorization.md)
with aliases/fragments and repeated positive protected-field proof across identities.

[Native policy agents](executable-policy-agents.md) can select and execute these
declared tests, analyze outcomes and review proof completeness without a model API.

HTTP manifests can declare [rejected-operation state-integrity cases](rejected-action-state-integrity.md)
to check stable owner-observed state before and after an explicitly supplied actor action.

Expectations can verify [response headers and cookie attributes](response-security-policies.md)
alongside body, status and captured-state assertions in both HTTP and browser modes.

The same manifest can configure a supplied identity and session control for
[authenticated browser execution checks](authenticated-browser-checks.md),
integrated with the local agent tool coordinator.

Ordered workflows can check exact integer state changes across steps using
`json_delta`. Capture a counter, version or balance in minor currency units
from a successful earlier response, then compare a later value to that baseline:

```json
"steps": [
  {"request": {"url": "https://your-authorized-app.example/api/test-resource/42"},
   "expect": {"statuses": [200], "json_equals": {"/id": 42}},
   "capture": {"before_version": "/version"}},
  {"identity": "other",
   "request": {"url": "https://your-authorized-app.example/api/test-resource/42",
               "method": "PATCH", "body": {"label": "authorized-test"}},
   "expect": {"statuses": [403]}},
  {"request": {"url": "https://your-authorized-app.example/api/test-resource/42"},
   "expect": {"statuses": [200], "json_equals": {"/id": 42},
              "json_delta": {"/version": {"baseline": "{{before_version}}", "eq": 0}}}}
]
```

This example checks that a denied operation did not change the owner's resource
version, rather than trusting the denial status alone. Use only explicitly
authorized test resources and operations. All requests retain the existing
scope, identity origin, pacing and budget checks; no operations are generated.
The workflow's default identity must be configured, and `other` must be a
supplied identity. This is a user-defined invariant, not automatically a
confirmed vulnerability or guaranteed rollback.

Each pointer requires `baseline` and one or more `eq`, `gte`, `lte` delta bounds.
All operands are integers with at most 4,096 bits; booleans, floats, nonfinite
numbers and oversized integers are rejected. Literal integers or exact
`{{variable}}` substitutions are accepted. `gte`/`lte` can constrain bounded
increases or decreases. At most 100 pointers are allowed per assertion set.
Known invalid initial variables and undeclared dependencies fail preflight;
invalid captured operands stop the step before its request. A missing or
noninteger response field fails the assertion. JSON must be valid, complete,
unambiguous and finite. Deltas, baseline values and response values are kept
in memory; persisted checks contain only pointer, operator and pass/fail.
Captures still update only after all assertions pass. The baseline must come
from a meaningful successful control; this feature does not discover application
state semantics or solve concurrency / eventual consistency automatically.

The state-delta addition was reviewed statically only and is unverified at
runtime; no tests, applications or assessments were run for this change.

Each workflow can declare `cleanup_steps`, using the same request, expectation,
identity and capture structure as its main steps. They execute after normal
completion, invariant failure or handled transport/capture errors, using the
same sessions and successfully captured variables. For example, a step that
captures `id` from a created test object can be paired with:

```json
"cleanup_steps": [
  {"request": {"url": "https://your-authorized-host.example/objects/{{id}}", "method": "DELETE"},
   "expect": {"statuses": [204]}}
]
```

All cleanup steps are preflighted before main traffic, with the same exact
origin, scope, credentials, request count and elapsed budgets. They cannot
force requests after exhaustion or invent a missing captured ID. Separate
`cleanup_decisions` and `cleanup_observations` record the result. Failed or
incomplete cleanup makes the run partial without creating a vulnerability or
erasing earlier findings. This is explicit best-effort cleanup, not guaranteed
rollback after interruption or process crash. Keep enough run budget for it.

An access case may also supply an optional comparison resource:

```json
"negative_control": {
  "request": {"url": "https://your-authorized-app.example/api/orders/43"}
}
```

Choose an accessible test resource that must not match this case's positive
`contains` / `json_equals` proof. It runs twice under each allowed identity,
after allowed controls and before forbidden observations. Its URL must differ
from the target URL and pass the same scope, exact identity origin, credential
header and browser-setting validation. Only GET/HEAD without a body or browser
actions is accepted. No comparison URL, identity or resource ID is invented.
The extra requests share the existing run budget and sessions.

Both observations must be complete HTTP 200 responses and fail the positive
content proof. JSON proofs also require a valid unambiguous finite JSON document;
a non-200 response, malformed JSON, truncation, unfinished browser requests or a
matching comparison resource stops the case as inconclusive before forbidden
requests. Status, absence and numeric-bound assertions are excluded from this
specificity check so their failure cannot conceal a matching resource proof.
Evidence labels the comparison observations and records `proof_specificity` as
`passed_supplied_negative_control` or `not_configured`. Inconclusive case decisions
identify the failing phase without copying exception text. This checks one
supplied comparison resource, not uniqueness across every possible response.
Existing cases without a comparison retain their request count and behavior.

Access-policy evidence repeats each forbidden identity's resource proof twice.
Two matches can confirm a policy violation; two misses complete that check
without a finding. One match and one miss are inconclusive, stop that case and
make the run partial. Evidence records each forbidden attempt's proof outcome.
An earlier repeatable finding remains supported even if a different identity
later produces inconsistent results. None of these outcomes claim exhaustive
coverage or prove security outside the explicitly configured policy.

Workflow variable dependencies are checked before any request or session reset.
`{{name}}` in request URLs, bodies, headers, browser plans and expectations must
refer to a named initial `variables` value or a JSON/DOM capture from an earlier
step in the same workflow. A step's own captures become available only after its
expectations pass. Captures can replace prior values, but a step cannot assign
one variable from both JSON and DOM. Exact substitutions preserve JSON types;
URL substitutions remain encoded. This checks declared dependencies, not whether
a live response actually contains the requested JSON Pointer or DOM element;
missing runtime values still stop that workflow as inconclusive.

`workflow-run` issues real HTTP requests with isolated cookie jars. The same engine
is available in `run` and `auto-run` through `--workflow-manifest assessment.json`.
Credentials are supplied by environment variable names, never stored in the
manifest or evidence. Each identity is pinned to an exact scheme, host and port;
redirects are recorded without following them. TLS verification remains enabled.

```sh
maher-bounty workflow-run assessment.json --scope scope.json --authorized --out results/workflows
maher-bounty auto-run --target https://your-authorized-app.example/ --authorized --workflow-manifest assessment.json
```

Example `scope.json`: `{"assets":["https://your-authorized-app.example/"],"out_of_scope":[]}`.
Example manifest (replace the URL and proof with a resource owned by your test account):

```json
{
  "identities": {
    "owner": {"origin":"https://your-authorized-app.example", "headers_env":{"Cookie":"MAHER_OWNER_COOKIE"}},
    "other": {"origin":"https://your-authorized-app.example", "headers_env":{"Cookie":"MAHER_OTHER_COOKIE"}},
    "anonymous": {"origin":"https://your-authorized-app.example"}
  },
  "limits": {"max_requests":200,"timeout_seconds":10,"total_seconds":300,"interval_seconds":0.2},
  "access_cases": [{
    "id":"private-test-order",
    "request":{"url":"https://your-authorized-app.example/api/orders/42"},
    "allowed":["owner"], "denied":["other","anonymous"],
    "proof":{"json_equals":{"/id":42,"/owner":"test-owner"}}
  }],
  "workflows": [{
    "id":"checkout-prerequisite",
    "identity":"other",
    "steps":[{
      "request":{"url":"https://your-authorized-app.example/api/checkout","method":"POST","body":{"cart":"empty-test-cart"}},
      "expect":{"statuses":[400,409],"json_equals":{"/error":"empty_cart"}}
    }]
  }]
}
```

Only use fixtures and policies appropriate to the actual assessment. Mutating
workflow steps run once, in manifest order; the engine stops that workflow at
the first failed assertion. Access matrices use GET/HEAD and repeat allowed and
denied observations twice. A repeatable forbidden response matching the explicit
resource proof is evidence-backed. A generic HTTP 200, login page, invalid
baseline, truncated body, or network failure cannot confirm forbidden access.
Request headers cannot override any header configured in the selected
identity's `headers_env`, including custom credential or tenant headers.
Matching is case-insensitive and enforced both before a manifest starts and
for direct HTTP/browser transport calls. Unrelated request headers remain
available. Supplied target credentials are separate from model-service keys.
Truncation on either an allowed control or a denied observation stops that
access case as inconclusive and makes the overall result partial. The captured
observation remains in evidence; a size-limited response is not a completed
policy check even when the resource marker is present in its retained prefix.
Workflow invariant failures require impact review; they are not automatically
confirmed security findings. JSON assertions use JSON Pointer syntax.
JSON proofs compare booleans separately from numbers, including inside nested
objects and arrays (`true` cannot prove resource ID `1`). Numeric `1` and `1.0`
remain equivalent. Responses with duplicate object keys or nonfinite numbers
cannot provide JSON proof or captured state. Array pointers require canonical
nonnegative indices; negative indices and leading zeros are rejected.

Use `"json_absent":["/private_token"]` in a workflow expectation to require a
field to be missing from a valid JSON document. A present `null` value does not
count as absent. Missing object keys or canonical array indices beyond the array
length count as absent; malformed JSON, invalid pointers and traversal through
a non-container do not. Pair absence checks with expected status and known
resource/state fields, for example
`"expect":{"statuses":[200],"json_equals":{"/state":"revoked","/id":"{{id}}"},"json_absent":["/private_token"]}`.
This tests payload state, not whether a previously issued credential is unusable;
that requires a separate explicit application policy check. Absence alone cannot
serve as a resource-specific access-matrix proof.

JSON Pointer escapes must use `~0` for `~` and `~1` for `/`. Invalid escapes and
JSON capture mappings are rejected before traffic. Capture variable names follow
the `{{variable}}` identifier syntax: letters/underscore first, then letters,
digits or underscores. JSON is decoded once for each assertion set and once for
each capture set, rather than repeatedly for every selected field.

Each workflow step may specify `"identity":"other"` to override the workflow's
default identity. Only configured identities are accepted, and every request is
validated against that step's identity origin before and after substitution.
All participating sessions reset once at workflow start and remain isolated;
returning to an earlier identity preserves its cookies or browser context.
Captures belong to the workflow, allowing an owner-created resource ID to be
used in a second identity's explicitly expected denial step and a subsequent
owner state check. Evidence records the identity used for each step. A failed
denial or state assertion stops the workflow and requires impact review.

After a successful step, `"capture":{"order_id":"/id","csrf":"/csrf"}`
stores selected response JSON fields in that workflow's private memory. Later
requests and expectations can reference `{{order_id}}` or `{{csrf}}`. Entire
JSON values preserve their types; values embedded in URLs are percent encoded
and the resolved URL is checked against scope and identity origin again. Missing
captures stop the workflow as inconclusive before another request. This supports
CSRF values returned in JSON and dynamic object creation followed by
state checks. It does not extract HTML forms or execute JavaScript.

The evidence writer now uses bounded atomic JSON replacement (8 MiB): a
serialization, size or write failure before replacement preserves the previous
artifact. This does not guarantee recovery from process crashes or power loss.
This change was reviewed statically only; no tests, tool executions or target
assessments were run, and the new behavior remains unverified at runtime.

`workflow-evidence.json` contains response hashes, lengths, status, assertion
results, context labels and semantic comparisons. It omits credential headers
and raw response bodies. Finding target URLs redact all query values while
retaining parameter names, duplicates and the resource path. Execution still
uses the original URL. Paths and parameter names are not redacted; keep secrets
out of those components. Keep source manifests private if they contain sensitive
resource markers or request bodies. Cookie authentication and ordered requests
are supported by the default HTTP engine. For JavaScript execution, supplied
login selectors and HTML token extraction, use the optional
[browser engine](browser-workflows.md). Automatic login discovery and automatic
token refresh remain unsupported.
Supplied HTTP Cookie credentials initialize an isolated cookie jar; server
Set-Cookie rotation updates that jar across workflow steps. Resetting a workflow
restores its supplied starting credentials. Direct HTTP transport calls also
enforce the identity's full origin and reject credential-header overrides.
Content proofs must use lists of nonempty string markers or a JSON Pointer
mapping. Unknown assertion keys, scalar marker strings, empty assertions and
invalid HTTP status lists fail before requests rather than becoming generic
HTTP 200 evidence.
HTTP body reads use bounded chunks and an elapsed deadline shared with the
request/run budget, narrowing the socket timeout to the remaining body-read
time. A body-socket watchdog interrupts reads at the elapsed deadline, including
slow chunk framing that performs multiple underlying reads. Its timer is
cancelled and joined after each read. Slow-drip data cannot repeatedly reset
this read budget. Deadline checks
also run after rate delays, before starting another HTTP request. Premature EOF
with a remaining declared Content-Length and HTTP protocol read failures are
inconclusive; matching text from a partial body cannot confirm a finding.
DNS, connection/TLS setup and response-header processing retain urllib's
underlying timeout behavior. This is not a strict wall-clock guarantee for the
entire HTTP exchange; those phases may extend a run beyond its deadline.
