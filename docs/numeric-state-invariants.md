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
Bounds referring to initial variables are checked before any traffic when their
values are already known. An earlier successful JSON or DOM capture replaces
that initial value, so the captured bound is checked at runtime instead.
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

To use a DOM value as a numeric bound, explicitly opt into numeric capture:

```json
{"capture_dom": {"initial_balance": {"selector": "#balance", "type": "number"}}}
```

An optional `attribute` reads an attribute instead of visible text. Numeric
capture accepts at most128 characters in JSON number syntax, strips surrounding
whitespace, and requires a finite number. Currency labels, grouping separators,
booleans and quoted numbers are rejected. Default capture remains exact text.
Capture failure makes the workflow inconclusive and stops dependent steps;
cleanup still follows its configured best-effort policy. Values are retained in
memory for substitution, not copied into the workflow evidence.
