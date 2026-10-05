# Numeric application state invariants

Workflow expectations support `json_number`: JSON Pointer keys mapped to one or
more `gt`, `gte`, `lt`, or `lte` bounds. All comparisons must pass. For example:

```json
{
  "json_number": {
    "/balance": {"gte": 0, "lte": "{{initial_balance}}"},
    "/quantity": {"gt": 0, "lte": 100}
  }
}
```

Capture `initial_balance` from an earlier successful step, or declare it as a
numeric workflow variable. Exact template substitution preserves its JSON type.
Bounds must be finite numbers; booleans and numeric strings are rejected.
Malformed bounds, unknown operators and undeclared variables fail manifest
preflight before any workflow traffic. A nonnumeric captured bound stops the
dependent step before its request; earlier traffic has already occurred.

Missing fields, invalid JSON, duplicate keys, booleans, strings and nonfinite
response values fail the assertion. Evidence records pointer, operator and pass
status without persisting the actual value or bound. Failed invariants produce
unvalidated candidates for impact review. Numerical checks alone cannot serve
as resource-specific access-policy proof. The operator does not infer an
application's business rules: configure bounds that match its intended policy.

The HTTP engine compares response JSON. The browser engine compares its returned
representation, which must contain valid JSON for these assertions to work;
an arbitrary rendered HTML page requires DOM assertions or capture instead.
