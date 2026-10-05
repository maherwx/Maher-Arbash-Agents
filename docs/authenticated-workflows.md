# Authenticated access policies and workflow invariants

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
Workflow invariant failures require impact review; they are not automatically
confirmed security findings. JSON assertions use JSON Pointer syntax.
JSON proofs compare booleans separately from numbers, including inside nested
objects and arrays (`true` cannot prove resource ID `1`). Numeric `1` and `1.0`
remain equivalent. Responses with duplicate object keys or nonfinite numbers
cannot provide JSON proof or captured state. Array pointers require canonical
nonnegative indices; negative indices and leading zeros are rejected.

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

`workflow-evidence.json` contains response hashes, lengths, status, assertion
results, context labels and semantic comparisons. It omits credential headers
and raw response bodies. Keep source manifests private if they contain sensitive
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
Request and run budgets bound new work; an already running request can extend
beyond the run deadline by its per-request timeout.
