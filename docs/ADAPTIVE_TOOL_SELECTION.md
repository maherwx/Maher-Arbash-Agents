# Adaptive tool selection

The tool advisor ranks relevant installed integrations using discovered HTTP technology, endpoint inventory, and source-analysis metadata. It reports missing tools without installing them and never launches a scanner itself.

Active integrations appear as `authorization_required` unless the caller explicitly requests an active plan. Burp Suite is listed as a manual proxy/report-import integration because scanner automation depends on the installed edition and local configuration. ZAP is listed as passive baseline only; it is not treated as an unrestricted active scanner.

The advisor does not receive or rewrite target URLs. Scan inputs must retain the exact URL value, including path, query, fragment, port, and percent-encoding. Scope validation may parse a URL for its host, but execution and evidence preserve the original string.
