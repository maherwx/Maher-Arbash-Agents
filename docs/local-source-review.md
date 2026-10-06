# Multilingual local source review

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

The native implementation reviews all readable UTF-8/UTF-16 text files, including
unknown language extensions. Extension/shebang inventory recognizes many application,
script, markup and configuration languages. Generic checks flag private-key markers,
disabled certificate verification, dynamic evaluation, legacy memory APIs and raw
HTML writes. These textual markers do not prove that untrusted input reaches a sink;
comments and intentionally safe usage can also match.

Python additionally uses the standard-library AST. It propagates recognized
request input through simple name assignments within a
module/function region, and flags sensitive first arguments in SQL execute methods,
shell-enabled subprocesses/os.system, eval/exec, pickle deserialization, Flask
template bodies and file responses. Constant SQL statements with separate bound
parameters do not match this first-argument taint check. No submitted code runs.

Python review also makes four bounded passes through directly named, uniquely
defined top-level functions in the same file. Positional/keyword arguments and
return-source summaries can propagate request origins into a local helper's sink.
FastAPI Query/Path/Body/Form/Header/Cookie markers and declared route placeholders
seed recognized parameters. Methods, imports across files, dynamically selected
callees, star-argument expansion and runtime alias rebinding are not resolved.
Summaries merge call contexts conservatively; branches and sanitizer correctness
remain unproven. The existing propagation work limit covers all four passes.

When `semgrep` is installed, an optional local Community Edition adapter adds
parser-based sensitive-sink patterns for JavaScript, TypeScript, Java, Kotlin,
Scala, Go, C#, PHP, Ruby, C, C++, Rust, Swift and Dart. These are fixed
candidate rules for selected process, query, evaluation, deserialization and
HTML sinks. They are not complete language coverage. Additional local CE taint
rules track selected request sources into query, HTML, evaluation, and process
sinks for JavaScript, TypeScript, Java, and PHP. These generated rules do not use
registry content or cloud services. Their source/sink models are deliberately
narrow and have no project-specific sanitizer assumptions, so candidates can be
false positives and flows through unsupported frameworks, aliases, reflection,
dynamic dispatch, or multiple files can be missed. CE analysis remains per-file;
a reported flow is a review lead, not exploit proof.
Only the bounded source snapshot is staged in a temporary
directory. Fixed locally generated rules are used with `--oss-only`, metrics off,
version checks disabled, secret validation disabled and inherited Semgrep settings
removed from the subprocess environment. There is no registry config, login,
cloud upload, build, autofix or source execution. The temporary snapshot is deleted
when the adapter exits normally; an abrupt process crash can leave temporary files.
The adapter has a 120-second process budget, 4 MiB output budget, two jobs and
per-file rule timeouts. Tool failure/timeout/missing status is explicit; it never
claims a missing engine ran. Semgrep's scanned-path list supplies file coverage,
and scanner parser/rule errors make the result partial.

Reports contain relative file paths, SHA256 hashes, source/sink line references,
sink symbols and candidate explanations; source bodies and matched secret values are not
copied into reports/model packets. Optional in-process GGUF reviewers receive
these static evidence summaries along with the normal assessment packet. Without
a configured local model the native AST analyzer remains usable, but model roles
are not claimed to have run. Two source-review roles assess sink/control concerns
and dataflow uncertainty. No external model API or cloud service is required.

Limits: 200 analyzed text files, 256 KiB per file, 8 MiB total source input,
20,000 AST nodes and 200,000 propagation node visits per file, 200 candidates,
500 directories and 4,000 visited file
entries. Symlinks, dependency/build/cache directories and the selected output tree
are skipped. Unreadable, invalid or oversized files are counted; truncated review
is partial. Deterministic traversal makes the bounds visible and repeatable.
Language coverage records actual analysis modes and parser-reviewed file counts;
`parser_coverage_gaps` keeps text-only languages visible. Recognizing a language
is not the same as having a complete semantic analyzer for it.

This is conservative heuristic propagation, not complete control-flow or
interprocedural analysis. It does not prove exploitability, understand all
sanitizers/import shadowing, or guarantee that every `.execute` is a database
operation. Framework request aliases, annotated route parameters and other input
sources may be missed. The bundled Semgrep patterns are structural sink checks,
not a full taint or interprocedural ruleset. Languages without a bundled parser
rule still receive generic textual review; they do not receive deep semantic
analysis. Binary source formats and other encodings are explicitly skipped.
Candidates always remain unvalidated and require source review
and subsequent runtime verification when authorized.

A website URL does not provide its server source code. Supply the application's
source directory; no remote repository is cloned or server source recovered.

`source-structure.json` and the report's `source_structure` add resolved local
import edges, declared route locations and a deterministic file-review priority
list. Python import/decorator syntax uses AST; JavaScript/TypeScript relative
module imports and app/router/server route declarations use text patterns.
Only edges to files already in the bounded snapshot are included. Route paths
must be short, begin with `/` and contain allowed path/template characters;
query values, host URLs and arbitrary strings are not copied. Python candidate
lines inside a decorated handler, or candidates whose same-file source lines fall
inside that handler, are linked heuristically; JS/TS
declarations have no handler dataflow link. The map is limited to 1,000 edges,
200 routes and 30 priority files, with truncation/errors explicit.

Priority combines candidate count, route declarations and incoming local import
edges. This is a review-order heuristic, not a severity or exploitability score.
Route prefixes, wrappers, dynamic imports and runtime registrations may be missed.
The map is not a complete call graph or dependency-vulnerability analysis and
does not expand network scope or automatically schedule checks against a route.
Model roles receive this structure only when their configured local model runs.

Source artifacts are written through bounded atomic JSON replacement, using a
private temporary file where supported, flushing before replacement. The previous
artifact survives a serialization/size/write failure before replacement; a reader
does not receive a half-written JSON file. Each artifact is limited to 8 MiB and
non-finite numeric values are rejected.
The writer incrementally encodes JSON and stops before the accumulated UTF-8
buffer exceeds the limit, before creating any temporary file. UTF-8 conversion
uses bounded slices; the input object and individual JSON encoder tokens are
not covered by this byte budget. This is not a total process memory limit.
Both artifacts share `artifact_generation`, derived from the complete report
content before generation fields are added.
The main report embeds the full structure and is written last; use it as the
authoritative snapshot. Consumers combining the separate files must compare
generation IDs and reject mismatches. Two file replacements are not one transaction;
interruption or concurrent writers can leave mismatched generations. File flushing
does not promise recovery from every power loss or filesystem failure.
Source evidence does not expand the network authorization scope. No source review,
tests, experiments, model execution or target scan was run for this code change;
it was reviewed statically only and remains unverified at runtime.

Semgrep integration options were checked against the official CLI reference:
https://docs.semgrep.dev/cli-reference and local metrics documentation:
https://github.com/semgrep/semgrep/blob/develop/metrics.md.
