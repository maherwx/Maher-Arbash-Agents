# Finding review record binding

The direct agent command now hashes each original finding when reviewing its
recorded evidence. The finding report attaches that review only when the record
ID is unique and its SHA-256 matches the original finding's canonical JSON.
Reordering or modifying findings after review cannot silently attach the review
of a different record at the same list index. Duplicate review IDs, missing
hashes and mismatched hashes are labeled `unbound_review`; absent reviews are
`not_reviewed`. Older hashless reviews need regeneration before attachment.

All original findings and the source review ledger remain in the report.
`summary.evidence_review_counts` counts the reviews actually attached to those
findings, including binding failures, rather than copying potentially stale
counts from the supplied ledger. Model hypotheses remain separate and unverified.

Hashes check record consistency, not authenticity, application impact or fresh
runtime validation. Someone who edits both a record and its hash can bypass
this check. The hash does not bind the complete execution environment or prove
that recorded browser requests happened; the existing reviewer checks recorded
proof/run consistency separately. No target requests are introduced.

This change received source and diff review only. Runtime behavior is unverified;
no tests, tools, models, applications or assessments were executed.
