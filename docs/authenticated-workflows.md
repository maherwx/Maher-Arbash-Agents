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
are supported; JavaScript execution, automatic login discovery, HTML token
extraction, automatic token refresh and browser-only workflows are not yet supported.
Request and run budgets bound new work; an already running request can extend
beyond the run deadline by its per-request timeout.
