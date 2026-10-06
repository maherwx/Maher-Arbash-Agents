# GraphQL field authorization execution

HTTP access cases can now declare `"graphql": true` and a supplied JSON POST
query. Both `workflow-run` and the native `policy-agents-run` pipeline use the
same access evidence engine. This enables repeated owner/other/anonymous
comparisons at nested response fields, including aliases and fragment fields.
It requires the optional installed local parser (`pip install -e '.[graphql]'`);
there is no model API, cloud service or schema download. Installation and
execution were not performed during development.

Example access case inside a manifest with `engine: http`, supplied identities,
explicit authorized scope and request limits:

```json
{
  "id": "graphql-private-order",
  "graphql": true,
  "request": {
    "url": "https://your-authorized-app.example/graphql",
    "method": "POST",
    "headers": {"Content-Type": "application/json"},
    "body": {
      "query": "query OrderProof($id: ID!) { privateOrder: order(id: $id) { ...OrderIdentity } } fragment OrderIdentity on Order { id ownerId }",
      "operationName": "OrderProof",
      "variables": {"id": "supplied-owned-test-id"}
    }
  },
  "allowed": ["owner"],
  "denied": ["other", "anonymous"],
  "proof": {
    "json_equals": {
      "/data/privateOrder/id": "supplied-owned-test-id",
      "/data/privateOrder/ownerId": "supplied-owner-id"
    }
  }
}
```

Adapt the query, schema type names, test resource, identities and positive proof
to the application. JSON Pointers follow response aliases, not schema names.
The example is configuration documentation, not a test that ran. Requests are
never generated from an endpoint, introspection response or API contract.

Every allowed identity must return HTTP 200 and all protected-field proofs
twice before denied identities are examined. A denied identity must return
matching protected data twice for an access violation finding. HTTP 200,
error messages or null fields alone cannot establish disclosure. Partial data
with GraphQL errors may establish exposure when every protected-field proof
still matches. Non-JSON, invalid GraphQL envelopes, truncated/network-incomplete
responses and inconsistent matches leave the case inconclusive. A completed
case without a finding only records that the supplied proof did not match;
it does not certify the endpoint or all resolvers as secure.

Proofs require non-null scalar `json_equals` values below `/data/`, preferably
resource and owner identifiers. This enforces a positive field proof but cannot
determine whether the user-supplied marker is specific enough or the declared
access policy is correct. GraphQL negative controls are unsupported in this
version. Generic access cases retain their GET/HEAD method restriction.

The body accepts `query`, `variables` and `operationName` only. Arrays/batching,
persisted-query extensions, schema definitions, mutations and subscriptions
are rejected. Multiple queries require a selected operation name; duplicate
operations, unknown/cyclic fragments, excessive depth and expansion are rejected.
Limits: query 64 KiB, JSON body 128 KiB, 5,000 parser tokens, 10 operations,
100 fragments, depth 12 and 1,000 expanded selections across all definitions.
Unused definitions are also checked. These are client execution limits, not
tests for server complexity or resource exhaustion. Parser API is described in
the [official GraphQL-core documentation](https://graphql-core-3.readthedocs.io/en/v3.2.6/modules/language.html).

Only query operations are admitted, but query syntax cannot guarantee that a
resolver has no side effects. Supply only application-approved queries and
test objects whose policy is known. There is no schema type validation, resolver
implementation analysis, automatic payload discovery or mutation execution in
this access mode. Existing identity-origin, scope, credential isolation, pacing
and shared request/time budgets still apply. Add an explicit application/json
header; do not configure an identity with conflicting content-type headers.

Evidence records protocol, query/normalized JSON body SHA256 and bounded AST counts, not
raw queries, variables, operation names, response data or parser diagnostics.
Hashes and field pointers may still be sensitive and do not anonymize low-entropy
values. Static source/diff review only: unverified at runtime; no tests,
applications, scanners, models or assessments were run for this addition.
