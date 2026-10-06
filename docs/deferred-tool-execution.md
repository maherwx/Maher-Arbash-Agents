# Budget-aware follow-up execution

The router distinguishes admitted tool attempts from requests deferred by the
per-round request, target or per-tool process budget. Origin/host tools and the
browser verifier admit at most two distinct coverage targets per round; HTTPX,
Nuclei and Dalfox retain their batch target limit. Excess requests within the
bounded role queues are preserved for later rounds instead of silently counted
as attempted. Input remains bounded to 120 result packets and twenty requests
per role; input beyond those limits is not an unlimited persistent work queue.

Router results include `attempted_targets` and `deferred_requests`. A missing,
blocked or failed admitted tool is still an attempt, but an eligible target which
never fit the budget is not. Only admitted attempts enter the feedback ledger.
The feedback loop prioritizes deferred work before generating another plan and
can continue without new discovered routes when deferred requests remain.
Every later admission still requires an allowlisted tool and an exact known,
in-scope target. Scope references resolve before feedback deduplication.

The original three-round limit remains. Reports record deferred request counts
per round and `remaining_deferred_request_count` at the stop point. A deferred
request can contain several targets; this count is requests, not targets. Hitting
the round limit does not mean all proposed checks ran. Pending deferred work is
included in the existing completed-round checkpoint state for programmatic recovery
within the original round budget; a terminal journal does not start a new budget.

Host-based prior coverage now normalizes recorded URL targets to the same hostname
key as proposed requests, preventing the same host from looking uncovered simply
because a prior run recorded its URL.

Compatibility with older routers without `attempted_targets` retains their previous
attempt accounting. New router metadata is used in the normal bundled pipeline.
No tests, experiments, scans or model/tool executions were performed for this
change. Source and diff review only; runtime verification remains outstanding.

The coordinator now checks the unattempted native plan before stopping for lack
of newly discovered URLs. It can continue a complementary check on an existing
known URL when an earlier plan/request budget left an eligible adapter uncovered.
The native next plan is filtered against admitted attempts, including failed or
output-limited attempts; it does not automatically retry those tools. The same
scope, coverage keys, process templates and three-round budget still apply.

Model reviewers receive `unattempted_native_plan` with actual execution feedback
so they can see which complementary requests the fixed planner already proposes.
Each round records `next_native_request_count`; the aggregate exposes
`remaining_native_request_count` and `pending_request_proposals`. At the round
limit, the direct command's JSON/Markdown finding report retains these unfinished
proposals. They may contain duplicate/ineligible model requests and are not
admitted execution or confirmed missing security coverage. Deferred and native
counts are request batches, not distinct targets; do not add them as a unique
coverage count. No extra round, target expansion or unrestricted shell is added.
An interrupted running checkpoint still cannot be automatically replayed.
This extension was reviewed statically only; no runtime tests or tools ran.

HTTPX follow-up output is now preserved in `httpx-followup-responses-<run-id>.jsonl` and
parsed into the scoped feedback inventory. Previously that branch captured only
an output tail and never admitted its returned URLs. Only explicit `url` values
with recorded HTTP status integers and no failed flag are admitted, after scope
validation and deduplication; hosts/paths are not inferred. This can retain a
recorded alternate HTTP/HTTPS URL for complementary checks within scope. No
redirect-following flags or target policy changes are added. Inventory admission
is not proof of vulnerability or authentication.

The parser reads at most 8 MiB and 1,000 lines. Invalid/non-response rows and
out-of-scope URLs are counted. Missing artifacts, incomplete extraction and
truncation remain explicit in run telemetry (`probe_inventory_status`, response,
rejected/invalid row counts). Tool process status is retained separately; parsing
partial output does not turn a timeout/nonzero exit into success. Existing global
discovery budgets and router scope checks still apply. Output may contain sensitive
probe metadata. Unique invocation paths prevent a failed launch or empty timeout
from parsing an older probe artifact as fresh output. Output may contain sensitive
metadata and must remain private. Source/diff review only; no HTTPX process,
test, application or assessment was executed for this change.
