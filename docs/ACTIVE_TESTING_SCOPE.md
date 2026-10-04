# Active testing scope controls

Active checks follow the asset list and exclusions supplied for the bug bounty program.

## Scope format

```yaml
assets:
  - https://app.example.test
  - "*.example.test"
  - https://api.other.test
out_of_scope:
  - admin.example.test
```

Exact host entries authorize that host. A wildcard authorizes matching subdomains; each discovered host is crawled separately with an exact FQDN scope. The wildcard's base domain is used only as a passive enumeration seed unless it is independently listed as an in-scope asset. Exclusions override matching asset entries.

The scope-based `run` command can collect inventory for every listed asset seed, filter discovered hosts before HTTP probing, then run the active checks over every exact in-scope asset and every discovered host admitted by the program scope. It also passes all in-scope endpoints to parameter analysis. Use `--authorized` once to confirm authorization for the supplied program scope.

Only HTTP and HTTPS URLs without embedded credentials enter web checks. Rejected URLs and hosts are recorded in `scope-review.json`. Network/service checks run against each admitted host. A scope decision is not proof of ownership or permission; use only assets covered by the current program authorization.
