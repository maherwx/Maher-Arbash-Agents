# Local API contract review

The local OpenAPI analyzer adds declared operation and authorization structure
to API review. It reads a supplied JSON file without fetching schema URLs,
servers or endpoints and without scheduling traffic:

```sh
maher-bounty api-contract-review ./openapi.json --out results/api-contract
```

Existing `run` and `auto-run` also accept `--api-contract ./openapi.json`.
They preflight the file before target collection and include the bounded report
in local agent context, execution-review context, checkpoints and report payload.
The standalone command does not run scanners, browser engines or models. No
external model API/cloud dependency is introduced. None of these commands were
executed during development of this feature.

The parser supports OpenAPI 3.0 / 3.1 JSON, retaining the file SHA-256 as
provenance. It rejects duplicate keys, nonfinite numbers, unsupported versions
and files over 4 MiB. Swagger 2 and YAML are unsupported. Operation summaries
contain path/method, filtered operation ID, parameter names/locations/required
flags, direct JSON request-object property names/types/readOnly/writeOnly flags,
and the effective declared security requirement.

Operation-level security overrides the global requirement. A list of security
objects represents alternatives; schemes inside each object remain a joint
requirement, with scopes preserved. Empty requirements expose an explicitly
anonymous alternative; absence at both levels is labeled `no_security_declared`.
Unresolved schemes have unknown type and a coverage gap. This is declaration
analysis, not proof of anonymous access or effective deployed authorization.
Version route families such as `/v1/orders` and `/v2/orders` are compared per
method for differing effective security declarations. Alternative ordering is
normalized; inheritance source alone does not cause a difference.

Direct object fields marked readOnly on mutation operations propose property
authorization review. Path parameters propose object-authorization review with
an explicitly owned resource and distinct supplied identity. Mutation methods
propose rejected-action state-integrity and prerequisite review. These are
questions for explicit application policies, not payload generation or validated
findings. Use supplied access/workflow/state-case manifests for execution;
contract paths alone do not authorize or become new network targets.

Only in-document dictionary JSON Pointer references are resolved, with at most
16 hops and 10,000 reference visits. External references, cycles, siblings next
to `$ref`, percent-encoded pointers, schema composition/conditional constructs
and unresolved objects are left unexpanded with explicit coverage gaps. Property
inspection is shallow: nested/array/polymorphic bodies, response contracts,
full schema validation, serializer behavior and deployed request handling are
not analyzed. Names/paths with unsupported characters are omitted.

Bounds include 500 path entries / operations, 100 parameters per declaration
list, 100 direct body properties, 20 security alternatives / schemes per group
and 100 scopes per scheme. Serialized operation summaries share a 2 MiB budget
to bound expansion of repeatedly referenced schemas. Truncation or unsupported constructs make the report
partial. Descriptions, examples, defaults, server URLs, OAuth URLs and credential
values are not copied into model context or artifacts. Paths/property names are
still visible; avoid secrets in schema identifiers. Report JSON uses bounded
atomic replacement.

The feature was reviewed statically only and remains unverified at runtime.
No tests, API assessments, applications, browsers or scanners were run.
