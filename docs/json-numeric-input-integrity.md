# JSON numeric input integrity

HAR imports, direct agent JSON inputs and execution journal loading now reject
numeric float tokens that overflow Python's finite float range. Rejecting the
special `NaN`/`Infinity` spellings alone did not cover valid JSON syntax such as
`1e9999`, which Python otherwise decodes to infinity. The new decoder rejects
that value at the input boundary, including inside nested objects and lists.

The existing sanitized HAR and direct-input error paths handle the failure.
Journal loading fails before integrity checking or restoring execution state;
it does not replay uncertain work. Duplicate-field and special-constant checks,
file size limits and atomic writes remain in place. Ordinary finite float tokens
and integer decoding retain their existing behavior. This is not exact decimal
arithmetic and does not prevent finite rounding or underflow to zero.

Only these three input boundaries use this helper; no claim is made that every
JSON reader in the project uses it. No target requests, model inference, API or
cloud dependency is added. Source/diff review only: runtime behavior remains
unverified, with no tests, imports, tools, applications or assessments executed.
