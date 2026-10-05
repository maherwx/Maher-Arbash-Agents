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
