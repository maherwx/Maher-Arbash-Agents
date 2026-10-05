# Source-guided tool checks

Authorized active runs with source and captured traffic can now turn lexical
source/handler candidates into requests to existing local verification tools.
The planner requires matching file hashes, candidate lines, scoped known exact
traffic references and an observed GET. It does not replay captured POST bodies,
reconstruct identities or convert source-only declarations into new URLs.

For CWE-79 candidates on query URLs it requests the existing browser-XSS verifier
and Dalfox, plus Nuclei. Other correlated candidates request a complementary
Nuclei template pass; this is not a dedicated test of that source defect. Existing
router allowlists, templates, scope checks, prior coverage, request/process budgets,
deferred queue and three-round limit continue to apply. Up to 100 source tasks
are recorded. Requests aggregate by tool into one deterministic role packet.
No model or cloud service is needed for this planning path.

`source/source-check-plan.json` records file/line/hash/task/reference provenance.
`source/source-check-audit.json` distinguishes prior attempts, admitted follow-up
attempts and tasks not admitted. The run report carries both. Admission evidence
uses hashes of tool coverage keys; query values are not copied to this audit.
Missing, blocked and failed tools can count as attempted; see the actual execution
run statuses for success/failure. Neither task admission nor a complementary
template finding automatically validates the original source candidate.

Active discovery disabled means no source-guided requests run. Browser-XSS remains
limited to its supported query/HTML context. Authentication, POST workflows and
application-specific invariants still require the explicit supplied workflow
manifest and identities. This addition does not invent those inputs.

Code review only for this implementation: no tests, experiments, analyzer/tool
executions, model inference or target assessments were run. Runtime verification
remains outstanding.
