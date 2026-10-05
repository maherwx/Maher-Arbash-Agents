# Local source review

Use supplied local source code alongside assessment evidence:

```sh
maher-bounty source-review --source-dir /path/to/application --out results/source
maher-bounty auto-run --target https://your-authorized-host.example --authorized --source-dir /path/to/application --out results/combined
```

The standalone command performs local static review only: no source imports,
application execution, dependency installation or network requests. The combined
command retains the normal authorized assessment pipeline and adds source evidence
to the report and local model agent packets. These commands are usage examples;
they were not run during development.

The native implementation currently analyzes Python using the standard-library AST.
It propagates recognized request input through simple name assignments within a
module/function region, and flags sensitive first arguments in SQL execute methods,
shell-enabled subprocesses/os.system, eval/exec, pickle deserialization, Flask
template bodies and file responses. Constant SQL statements with separate bound
parameters do not match this first-argument taint check. No submitted code runs.

Reports contain relative file paths, SHA256 hashes, source/sink line references,
sink symbols and candidate explanations; source text and literal values are not
copied into reports/model packets. Optional in-process GGUF reviewers receive
these static evidence summaries along with the normal assessment packet. Without
a configured local model the native AST analyzer remains usable, but model roles
are not claimed to have run. Two source-review roles assess sink/control concerns
and dataflow uncertainty. No external model API or cloud service is required.

Limits: 200 analyzed Python files, 256 KiB per file, 8 MiB total source input,
20,000 AST nodes and 200,000 propagation node visits per file, 200 candidates,
500 directories and 4,000 visited file
entries. Symlinks, dependency/build/cache directories and the selected output tree
are skipped. Unreadable, invalid or oversized files are counted; truncated review
is partial. Deterministic traversal makes the bounds visible and repeatable.

This is conservative heuristic propagation, not complete control-flow or
interprocedural analysis. It does not prove exploitability, understand all
sanitizers/import shadowing, or guarantee that every `.execute` is a database
operation. Framework request aliases, annotated route parameters and other input
sources may be missed. JavaScript and other languages are not analyzed in this
implementation. Candidates always remain unvalidated and require source review
and subsequent runtime verification when authorized.

A website URL does not provide its server source code. Supply the application's
source directory; no remote repository is cloned or server source recovered.
Source evidence does not expand the network authorization scope. No source review,
tests, experiments, model execution or target scan was run for this code change;
it was reviewed statically only and remains unverified at runtime.
