# Tool process budgets

Captured stdout and stderr share an 8 MiB byte budget per process by default.
The runner drains both streams concurrently, retains at most that combined
amount, and stops the process tree when output exceeds the limit. Callers may
set a positive integer `max_output_bytes` on `process_runtime.run`.

`OutputLimitExceeded` carries bounded partial stdout/stderr and the limit.
Active and inventory tool adapters report `output_limit`, distinct from
`timeout`; coverage records `output_limited` with incomplete results. Partial
diagnostics do not imply a complete assessment. Text output uses UTF-8 with
replacement for invalid bytes, so malformed tool output preserves exit status.

This budget covers captured pipes, including stderr when stdout streams to a
file. Files written directly by tools or caller-supplied stdout files are not
disk-budgeted by this mechanism. Per-process timeouts and bounded cleanup still
apply; Windows jobs and POSIX process groups terminate descendants on failure.

Captured-process startup and cancellation handling now share the same cleanup
boundary. If an I/O worker cannot start after another worker has started, the
runner terminates the process group/job, joins started workers within the
existing two-second cleanup window and closes pipe handles that no worker owns.
The original startup error propagates. Live worker streams are not closed from
the calling thread because an escaped descendant may hold their stream locks.
Read/write/close errors are recorded and surfaced instead of treating missing
I/O as a successful invocation; a child closing stdin early still follows the
existing broken-pipe behavior.

A cancellation event already set before `Popen` now raises `ProcessCancelled`
without creating a child, with empty captured stdout/stderr in the requested
text/binary format. Cancellation arriving after that check uses the existing
running-process cleanup; the check is not an atomic guarantee against races.
No arbitrary shell commands or changes to tool budgets are introduced.
This update received source and diff review only. Runtime behavior remains
unverified: no tests, tool processes, desktop application or assessments ran.
