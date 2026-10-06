# Traffic input preflight

`--traffic` imports an existing Burp XML or HAR export. It does not start Burp
or create that export. Relative paths resolve from your current shell directory.

```bash
maher-bounty auto-run --target 'https://your-authorized-host.example/' \
  --authorized --traffic '/home/maher/captures/burp-export.xml' \
  --out results/burp-run
```

Omit `--traffic` when you have no export. Missing files, directories, unreadable
inputs and malformed formats produce an error and exit status 2. Assessment
preflight parses the input before reconnaissance, run creation or output creation.
Valid empty Burp `items` or HAR `log.entries` exports are accepted; they provide
no captured traffic evidence. Parser diagnostics omit captured contents.

Check the target spelling independently: accepting a scope seed does not prove
DNS resolution, successful HTTP responses or discovered vulnerabilities.

Imports now reject exports above 64 MiB or 10,000 records. The read itself is
bounded, including a file that grows while being read. Split larger captures
into separate exports; the importer does not silently truncate evidence or
return a partial record list. These are input/record limits, not a guarantee
that total parser memory stays below 64 MiB.

HAR imports reject duplicate JSON fields, non-finite JSON numbers and malformed
entry/request/response/header/cookie containers. URL and method fields must be
strings. UTF-8 files with a BOM are accepted. Deep JSON parser failures receive
the same sanitized import error rather than exposing captured contents.

Burp XML element/attribute DTD declarations remain supported. Entity declaration
markers are rejected before XML parsing, including markers in UTF-16/32 files;
this conservative check also rejects a literal declaration marker in a comment.
Normal escaped XML text and base64 messages remain supported. Importing never
fetches an external DTD or contacts a target.

This change was reviewed from source and diff only. Runtime compatibility and
limits are unverified; no tests, imports, scans or applications were executed.

Captured HTTP header handling now redacts continuation lines of sensitive
headers, including obsolete folded Authorization/Cookie/Set-Cookie values.
Header names are matched after surrounding whitespace is removed; the message
body and original line endings remain unchanged. This is header redaction,
not automatic removal of every secret from URLs, bodies or arbitrary headers.

Burp actor extraction unfolds continuation lines before hashing credentials.
HAR and Burp imports leave actor identity unknown when a credential or explicit
identity header occurs more than once, instead of choosing an arbitrary last
value. Multiple recognized session cookies also leave cookie-derived identity
unknown. An explicit supplied identity header still has the existing precedence
over cookie/Authorization inference. Hashed capture identity is a correlation
hint, not proof that the application authenticated that account or granted it
access. This header handling update remains unverified at runtime and received
source/diff review only, with no capture import or tests executed.
