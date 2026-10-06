# Local execution feedback

The normal assessment pipeline now continues specialist tool execution after a
follow-up discovers new in-scope routes. The router runs a first batch from model
suggestions (when a local model is enabled) and deterministic specialist tool
requests. A shared attempt ledger and run history feed the next deterministic
plan. For example, a crawler discovers a parameterized route, then a subsequent
batch can select Dalfox for that newly observed route.

The loop uses up to three rounds and admits at most30 newly discovered URLs
across them. Each router round retains its existing request/target/process
limits. Attempts are shared by tool and its host/origin/URL coverage key,
including failed or missing-tool attempts; the loop does not repeatedly retry
them. It stops when there are no unattempted requests, no new in-scope evidence,
or the round limit is reached. Different tools may examine the same route.

Reports preserve all runs, decisions and findings plus per-round counts and an
explicit stop reason. Fresh routes are scope-filtered before entering another
round; identities and credentials are never invented. Tool commands still use
the existing structured allowlist and validated known targets. The pipeline
does not interpret model output as arbitrary shell commands.

Requests can use `target_refs` from scoped traffic evidence, including a single
reference string. References resolve before attempt deduplication and still
require known, in-scope URLs. Unknown references produce a filtered decision.
Single-string `targets` and ZAP aliases retain the router's supported behavior;
aliases and references to the same target share one attempt key.

No model service or cloud is required for this coordination. Without a local
model, it is deterministic feedback based on observed routes and coverage,
not autonomous language-model reasoning. This change does not implement
automatic credential discovery, policy inference, proof of impact, or arbitrary
application-specific workflow generation. It reuses installed scanners;
missing tools remain visible in the report instead of being claimed as run.
