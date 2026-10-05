# Browser-driven application research

Manifest `limits` accepts only `timeout_seconds`, `total_seconds`,
`interval_seconds` and `max_requests`. Timeouts must be finite positive numbers,
the interval a finite nonnegative number and the request budget a positive
integer. Booleans, strings and unknown keys fail preflight before browser launch.
Existing runtime clamps remain: timeout 1 to 60 seconds, total 1 to 3600 seconds,
request budget 1 to 2000, interval at least 0.1 seconds. If the next request's pacing
delay cannot fit inside the remaining run budget, execution becomes inconclusive
without sleeping beyond the deadline or sending that request.

Install the optional browser runtime in your project environment:

```sh
python -m pip install -e '.[browser]'
python -m playwright install chromium
```

Set `"engine":"browser"` in the assessment manifest. Existing `workflow-run`,
`run` and `auto-run --workflow-manifest` commands select Chromium automatically.
Every test identity gets a separate non-persistent browser context. Credentials
can come from `headers_env` or an explicit Playwright `storage_state` file in
the identity configuration; keep those files private. Workflows reset their
context at the start and keep cookies/DOM state across ordered steps.
Cookie credentials supplied through environment variables are imported into
the identity's browser cookie jar. Server `Set-Cookie` rotation then updates
that jar instead of a fixed Cookie header overriding the refreshed session.

Example browser step inside an explicitly scoped workflow:

```json
{
  "request": {
    "url":"https://your-authorized-app.example/login",
    "browser": {
      "actions":[
        {"kind":"fill","selector":"input[name=username]","value_env":"MAHER_TEST_USERNAME"},
        {"kind":"fill","selector":"input[name=password]","value_env":"MAHER_TEST_PASSWORD"},
        {"kind":"click","selector":"button[type=submit]"}
      ],
      "wait_for":"#account-home",
      "capture_dom":{"csrf":{"selector":"input[name=csrf]","attribute":"value"}}
    }
  },
  "expect":{"contains":["Test account"]}
}
```

Later steps can substitute `{{csrf}}` in a form action value or request header.
Supported actions: fill, click, check and select. `wait_for` uses a Playwright
locator; prefer a locator specific to the completed application state. Response
proofs refer to rendered DOM text (default body or `body_selector`), not merely
the original HTML. Browser navigation uses GET; mutations use explicit form
actions in workflows. Access matrices cannot contain repeated form actions.
The complete manifest is checked before execution: engine names, supported
browser settings, action kinds/fields, nonempty locators, fill value sources
and DOM capture mappings must be valid. Browser settings require
`engine=browser`; the HTTP engine cannot silently ignore a browser plan.
Direct browser calls apply the same structural checks before navigation.
This validates plan structure, not whether selectors exist in the live page
or whether dynamically resolved values/environment credentials are available.

All browser HTTP requests, including scripts and fetch/XHR, pass through origin
and scope checks, network budgets and rate limits. Redirect responses are fetched
one hop at a time, checked before Chromium follows them. Service workers and
WebSockets are blocked to avoid bypassing HTTP interception. External origin
dependencies are currently blocked, even if the program includes them: use a
single-origin fixture for this runtime. TLS verification is enabled. Dialogs are
dismissed; downloads are disabled. There is no unattended account registration
or automatic login discovery; supplied application-specific selectors determine
the tested flows. Browser evidence stores hashes and assertions, not credentials,
DOM token values or raw HTML. Browser summaries separately report actual network
requests, including subresources, and blocked requests.
Failed intercepted requests are counted separately and retain a generic
`network_error` marker, with query values redacted and exception text omitted.
If a step observes blocked or failed network traffic, its DOM evidence records
`network_incomplete`: the access case or workflow becomes inconclusive and
cannot confirm a finding or continue capturing state. This conservative rule
also covers blocked external dependencies, even when the visible text matches
the expected resource marker. A successful DOM assertion alone does not prove
the page finished its required network operations; use explicit wait selectors
appropriate to the application. Late activity after observation is not covered.
Direct browser calls reject credential-header overrides and exhausted budgets.
After rate-limit delays the deadline is checked again before fetching traffic.

For pages that update state through asynchronous requests, set
`"browser":{"wait_for_network_idle":true}` on a step. After actions and the
optional application wait selector, this waits for Playwright's network-idle
state (no active network connections for at least 500 ms), bounded by the
per-operation timeout and remaining run deadline. A busy polling page may never
reach this state; timeout produces an inconclusive workflow, not a policy
finding. Application readiness selectors remain necessary when activity starts
later or state updates are scheduled independently of network traffic.

Each identity tracks its own in-flight requests. Observations record their count
as `pending_requests`; any outstanding request at the snapshot makes the
network evidence incomplete. Resetting an identity installs a new tracker with
its new context, so old-context completion callbacks cannot alter the new
session's tracker. The network-idle option must be a JSON boolean and is
validated before starting traffic.

Context reset and transport shutdown use the same disposal path. It marks the
context as closing and sets it offline before removing route handlers, so new
polling traffic cannot bypass origin routing during disposal. In-flight handler
errors are detached with Playwright's `ignoreErrors` behavior before context
closure; cleanup does not wait indefinitely for cancelled callbacks. Normal
route cancellation is converted to incomplete network diagnostics without raw
exception text. Closing the transport repeatedly is safe, clears retained
context/page/pending-request state, and prevents further use or reset.
The summary also retains a sanitized network timeline: identity, HTTP method,
resource type, status and URL with query values redacted. This exposes endpoints
reached through JavaScript and forms to the research context without replaying
redacted URLs or asserting that a status difference is itself a vulnerability.

Each form action, explicit selector wait, DOM capture and body read
recomputes its timeout from the remaining run budget. A slow preceding action
cannot give the next operation a fresh copy of the original run allowance.
The transport also checks the deadline after extracting the body before
returning evidence. This bounds Playwright waits; it is not a hard operating
system deadline for browser startup, synchronous callbacks or cleanup.
Real-browser CI runs the local Chromium fixture suite separately from the core
suite. To run it locally, set `MAHER_BROWSER_TESTS=1` and execute
`python -m unittest discover -s tests -p test_browser_runtime.py -v`.

Tool execution now starts a new process group on POSIX and kills the group at
timeout or cancellation, including descendants that retain stdout handles.
Windows binds the tool to a Job Object and terminates the job on timeout. The
job is closed on successful completion too, removing surviving descendants.
Tool input is validated before launch: text mode requires a string, binary
mode requires bytes-like input, and captured text input is encoded as UTF-8
on the calling thread. Invalid or unencodable input cannot be silently lost
in a writer thread. Timeouts must be finite numeric values or `None`; zero
and negative values retain immediate-timeout behavior.
Failure to create/assign the job fails the launch and kills the root instead of
silently running without tree control. Cleanup never waits indefinitely for
inherited pipe handles. A child deliberately escaping OS process-group controls
is outside this runner's guarantees.
