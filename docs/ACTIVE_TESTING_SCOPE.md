# Active testing scope controls

Active checks are bounded by the assessment scope supplied to the orchestrator.

## Scope format

Use explicit host assets and explicit exclusions in the scope YAML:

```yaml
assets:
  - https://app.example.test
  - "*.api.example.test"
out_of_scope:
  - admin.api.example.test
```

An exact host rule covers that host only. A wildcard such as `*.api.example.test` covers its subdomains and does not include the wildcard's base host. Exclusions always take precedence. The supplied target is treated as an exact host rule, so it does not implicitly authorize sibling subdomains.

Only HTTP and HTTPS URLs without embedded credentials are passed through the URL scope filter. Discovered endpoints outside the allowlist, malformed URLs, unsupported schemes, and URLs with userinfo are rejected. The run writes `scope-review.json` under the active-testing output folder with the allowed and rejected URL candidates for audit.

The crawler is explicitly limited to the target's fully qualified domain name (FQDN); it does not inherit Katana's broader default that can include sibling subdomains. The parameter-analysis input contains only filtered, in-scope inventory URLs. A scope decision is not proof of ownership or permission; run active checks only for assets covered by the user's authorization.
