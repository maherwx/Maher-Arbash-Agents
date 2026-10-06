# Browser execution proof

The agent tool router supports `browser-xss`, a local Chromium verifier for
query-input JavaScript execution. The deterministic coordinator selects observed
parameterized URLs, and local model specialists can request the same tool.
It participates in the normal authorized `auto-run` or scope-based `run` flow.
Install the existing browser extra and its Chromium runtime first:

```sh
pip install -e '.[browser]'
python -m playwright install chromium
```

For each of the first three query occurrences, the verifier replaces only that
value. It loads an inert control and then two HTML event probes in independent
fresh contexts. Each probe sets a distinct unpredictable attribute/token on the
document root. A finding requires observing both attributes through Chromium;
text reflection alone cannot confirm execution. The probes only set DOM markers.

The structured finding contains parameter/occurrence, two reproducible marker
payloads and the control result. Original query values are redacted. Run coverage
uses an exact-URL hash so the coordinator can avoid repeating an attempted URL.
Per router batch it examines at most two selected URLs, with 60 seconds and
60 browser network requests per URL. Existing scope/origin interception applies
to navigation and subresources. Missing Chromium/dependencies are reported as
blocked, and incomplete execution evidence is inconclusive.

This is anonymous GET query testing with one HTML event context. It does not
cover every JavaScript context, forms, stored XSS or authenticated sessions.
Escaped input and CSP controls are tested without confirming findings.
`not_confirmed` means no execution proof from these probes, not that the
application is secure. Confirmed execution still needs application-specific
impact review. Tests run only against generated local fixtures.
