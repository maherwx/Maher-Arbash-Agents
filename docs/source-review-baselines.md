# Source candidate baselines

Running source review again with the same source directory and output directory
compares the new report with the previous `source-review.json` before replacing it.
The result is embedded as `baseline_comparison` and enters the normal source
evidence packet. Reading a baseline does not run an analyzer or issue requests.
The prior snapshot read is capped at 8 MiB, with duplicate JSON keys/non-finite
values rejected. Invalid prior data does not prevent the current review report.

Comparison requires the same hashed absolute source root, analysis revision and
bundled rule hash. Older unbound snapshots or another project in the same output
directory are not compared. This is candidate tracking, not a vulnerability
database with automatic acceptance, suppression or confirmed fixes.

Identity uses file, line, source, CWE, rule and sink metadata. A moved line can
therefore appear as a new candidate. States are new, continuing, not observed in
the current review, and unknown due to coverage. A candidate disappears only as
an observation; it is never marked fixed or validated by this comparison.
Missing files, missing analysis modes, source truncation or skipped input keep
absence unknown. Missing Semgrep candidates always remain unknown because the
installed engine version is not pinned. Baseline provenance includes previous
and current file hashes; no source text or secret match values are copied.

Developers must increment `SOURCE_ANALYSIS_REVISION` when changing native Python
analysis semantics. Generic and Semgrep bundled rule changes also alter the rule
hash. This does not guarantee identical external engine behavior between reviews.
Only the latest report is retained in the output directory; save older reports
separately when a longer history is needed. Concurrent reviewers may read the
same previous report; atomic writes prevent partial JSON, not serial history.

This implementation was reviewed statically only. No tests, experiments, source
review executions, model inference or target assessments were performed.
