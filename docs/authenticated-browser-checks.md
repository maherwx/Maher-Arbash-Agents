# Authenticated browser execution checks

`run` and `auto-run` can run the fixed browser XSS verifier with one explicitly
supplied identity, in addition to anonymous checks. Add `browser_xss_profile`
to the existing workflow manifest passed with `--workflow-manifest`:

```json
"browser_xss_profile": {
  "identity": "owner",
  "session_request": {
    "url": "https://your-authorized-app.example/api/session"
  },
  "session_proof": {
    "json_equals": {"/account_id": "authorized-test-owner"}
  }
}
```

The manifest must already contain that identity and at least one valid access
case, state case or workflow. `owner` needs supplied `headers_env` credentials or a private
Playwright `storage_state` file. Environment names and storage paths refer to
the local machine; no cloud/model API or invented login is used. Chromium and
the optional browser dependencies must be installed separately. This feature
does not install them or perform automatic login/token refresh.

The session request is a fixed GET at the same exact identity origin, within
scope, with no credentials or fragment in its URL. Optional browser settings
can wait for or select rendered content, but cannot execute form actions or
capture variables. Its proof must include positive `contains` or `json_equals`
evidence identifying the configured account; status alone is insufficient.
Use an actual account-specific control, not a generic login page marker.

The deterministic coordinator proposes `browser-xss-auth` only for already
known scoped query URLs at this identity's origin. Optional local GGUF roles
can request the same fixed tool; they cannot select credentials, a different
identity, shell commands, flags, JavaScript or new targets. Without a configured
profile, authenticated requests are rejected instead of silently using an
anonymous session. Anonymous `browser-xss` remains a separate check.

Each inert control and marker attempt resets the browser context to the supplied
starting credentials, then verifies the session control in that context before
navigating the probe. Controls must return complete HTTP 200 with all proof
assertions passing; authenticated probe navigations must also return HTTP 200.
Failed credentials, expired state, failed control, incomplete network evidence
or missing browser runtime yield blocked/inconclusive results, not an anonymous
fallback or vulnerability confirmation. A session proof proves only the declared
control matched before navigation; it cannot establish application identity
semantics by itself or prevent logout during the following navigation.

The verifier retains the existing harmless DOM-marker proof: an inert input,
then two distinct fixed HTML event probes in fresh contexts. It covers the first
three query occurrences in one HTML event context, not forms, stored XSS, every
JavaScript context or all application attack surfaces. Nothing exfiltrates data.
Authenticated mode remains bounded to two target URLs per tool round and each
URL's 60-second / 60-network-request budget, including session controls and page
resources. Missing coverage is not evidence that the application is secure.

Evidence includes the identity label and a profile SHA-256, but omits credential
values, storage-state content and session response bodies. The digest binds the
configuration and initial credential/state digests so one profile's attempts
do not suppress another profile's checks. Anonymous and authenticated coverage
are distinct. Journal input binding includes the resolved profile. Keep the
credential environment and state file stable throughout one run; this is not a
transactional credential snapshot. Storage-state fingerprint reads are bounded
to 8 MiB. The optional configured local proxy is reused; Chromium must trust its
CA itself, as the HTTP-only `ca_file` setting is rejected here.

Browser evidence uses bounded atomic JSON replacement. These changes were
reviewed statically only. No tests, browser/model execution, applications or
assessments were run for this feature; it is unverified at runtime.
