# Local ZAP execution

Agent follow-ups and active-testing orchestration now share a ZAP CLI adapter.
It prefers an installed `zap-baseline.py`. Otherwise it detects `zaproxy` or
`zap.sh` on PATH and runs `-cmd -autorun` with a generated local YAML plan.
Agent requests can use `zap`, `zaproxy`, `zap.sh` or `zap-baseline.py`.
Commands are argument lists executed by the process-tree runtime, not interpolated
shell strings. No model service or ZAP HTTP control API is called by this adapter.

The native fallback sends one GET to the supplied scoped URL, waits for passive
analysis and generates a traditional JSON report. It does not crawl, launch active
attacks or seed authenticated sessions. Its coverage is explicitly
`exact_url_passive`, not equivalent to the packaged baseline's spider coverage.
Installed Automation Framework, passive scanner and reporting add-ons are required;
the adapter does not automatically download/install add-ons. ZAP's own networking
and installed add-ons are not an OS-level scope sandbox.

Each execution receives a fresh artifact directory and isolated ZAP profile.
Successful or warning exit codes require a valid JSON report with a site list;
missing, malformed or oversized reports do not count as success. Raw artifacts
may contain sensitive URLs and response data; keep result directories private.
Existing timeout/output limits and process-tree cleanup apply.

The adapter is covered by plan-generation, report-integrity, scope and coordinator
tests. Native ZAP is not installed in the development environment: real ZAP/Kali
end-to-end execution remains unverified. Burp traffic import remains available;
this change does not automate a Burp desktop session or licensed scanner.

Reference: [ZAP Automation Framework](https://www.zaproxy.org/docs/automate/automation-framework/),
[requestor job](https://www.zaproxy.org/docs/desktop/addons/automation-framework/job-requestor/),
[report job](https://www.zaproxy.org/docs/desktop/addons/report-generation/automation/).
