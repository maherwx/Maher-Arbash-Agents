# Local execution-round checkpoints

The pipeline saves follow-up execution state to
`active/agent-followups/execution-state.json` in its output directory. Each
completed round preserves actual run history, findings, decisions, known URLs,
pending requests and the shared attempt ledger. Atomic replacement and a flushed
temporary file avoid partially written JSON. Journal writes are limited to 8 MiB.
Temporary files use private permissions where supported by the operating system.

Only one process can own a journal at a time. Its exclusive lock records the
process ID. A process crash can leave that lock behind; inspect the process and
interrupted work before manually recovering it. The tool never automatically
removes an existing lock or claims an unfinished tool completed.

Programmatic callers of `run_agent_tool_feedback` can supply `checkpoint_path`
and `resume=True` to continue after a completed round. The inputs must match:
scope, initial known URLs, base execution history, tool plan, target references,
round budget, review mode, output directory and optional `checkpoint_context`.
The pipeline binds its rules through that context. Completed attempts are restored
before another batch is selected; a finished journal returns its saved result.
Restored target inventory is checked against scope again.

An interrupted running round has uncertain effects and cannot be automatically
replayed. Missing, mismatched, invalid, oversized or locked state raises an error
instead of silently starting another assessment. This is not a transaction rollback
and does not guarantee exactly-once execution after an arbitrary process failure.

This is recovery for the follow-up coordinator, not a full pipeline resume command.
The ordinary CLI writes checkpoints but starts a new assessment on another invocation;
it does not automatically skip reconnaissance or other earlier stages. Local model
reviews from earlier stages are not restored into a new pipeline run. Keep checkpoint
files private because, like assessment reports, they can contain target and evidence
data. A fresh invocation with resume disabled replaces the prior journal.

This implementation was reviewed statically only. No runtime tests, experiments,
model executions or target assessments were performed for this change.
