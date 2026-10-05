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
