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
