# HTTP workflows through a local Burp/ZAP proxy

Start your installed Burp or ZAP and configure an HTTP proxy listener on a
literal loopback address, such as `127.0.0.1:8080`. Disable manual interception
when running unattended workflows. Add this to an HTTP workflow manifest:

```json
{
  "engine": "http",
  "proxy": {
    "url": "http://127.0.0.1:8080",
    "ca_file": "/path/to/exported-proxy-ca.pem"
  }
}
```

Keep the manifest's existing identities, access cases and workflow steps.
`ca_file` is optional when no interception certificate is needed. For HTTPS
interception, export the proxy's CA as PEM and supply that file; certificate
verification and target hostname checks remain enabled. Do not disable TLS
verification. HTTP targets use absolute-form requests; HTTPS uses CONNECT.
Target credentials are sent inside the HTTPS connection, not in CONNECT headers.

Execution retains original identity-origin checks, cookie isolation/reset,
redirect blocking, body-size limits and deadlines. Explicit proxy routing
overrides ambient NO_PROXY; with no proxy configured, environmental proxies
remain disabled. Invalid/non-loopback/credential-bearing proxy endpoints fail
before traffic. Proxy settings currently require `engine=http`; browser proxy
support is not yet implemented and is rejected rather than silently ignored.

This is ordinary local proxy traffic, not a Burp/ZAP HTTP control API. It lets
the proxy capture workflow traffic but does not launch Burp, start a scanner,
configure authenticated Burp users or bypass edition/licensing requirements.
The local proxy is a trusted intermediary that receives the assessment traffic.
Real HTTP proxy fixtures cover routing, cookie isolation, CONNECT, scope/redirect
guards and manifest execution. Actual Burp/ZAP end-to-end interception remains
unverified in the current development environment.
