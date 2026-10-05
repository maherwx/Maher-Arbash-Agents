# Browser-driven application research

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
The summary also retains a sanitized network timeline: identity, HTTP method,
resource type, status and URL with query values redacted. This exposes endpoints
reached through JavaScript and forms to the research context without replaying
redacted URLs or asserting that a status difference is itself a vulnerability.

Real-browser CI runs the local Chromium fixture suite separately from the core
suite. To run it locally, set `MAHER_BROWSER_TESTS=1` and execute
`python -m unittest discover -s tests -p test_browser_runtime.py -v`.

Tool execution now starts a new process group on POSIX and kills the group at
timeout or cancellation, including descendants that retain stdout handles.
Windows binds the tool to a Job Object and terminates the job on timeout. The
job is closed on successful completion too, removing surviving descendants.
Failure to create/assign the job fails the launch and kills the root instead of
silently running without tree control. Cleanup never waits indefinitely for
inherited pipe handles. A child deliberately escaping OS process-group controls
is outside this runner's guarantees.
