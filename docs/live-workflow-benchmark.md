# Live access and application-state evaluation

```bash
maher-bounty workflow-benchmark --engine http --out results/quality-http
maher-bounty workflow-benchmark --engine browser --out results/quality-browser
```

Browser mode requires the browser extra and installed Chromium. The command
starts a generated application on an ephemeral literal loopback listener, uses
fixture identities and closes it after evaluation. It has no external target,
model service, Burp or ZAP dependency. No authorization flag is needed for this
self-contained local fixture. It cannot be used to claim those tools ran.

Both engines exercise eight known cases through actual network requests:
secure object access, cross-user leakage, anonymous leakage, a login page with
HTTP 200, fluctuating forbidden access, an invalid allowed control, protected
state and unauthorized state modification. Browser state cases fill/click a
page that sends a real PATCH; HTTP cases send PATCH directly. Values captured
from JSON or DOM link the owner/other/owner resource lifecycle.

`workflow-benchmark.json` records expected versus observed classifications,
confirmed access findings, state invariant candidates, false positive cases
and preserved clean/inconclusive controls. Each case saves normal hashed
workflow evidence. State failures remain unvalidated candidates for impact
review. Exit code is zero only when all expected outcomes match; otherwise one.

This measures these eight controlled policies. It does not estimate detection
coverage across arbitrary applications or discover the policy of an unknown
target. Running with no local model does not imply model agents participated.
