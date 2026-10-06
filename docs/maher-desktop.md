# Maher desktop interface

Maher is a local desktop workspace for the existing CLI, using Python Tk without
a web server, cloud account, model API or extra pip UI framework. A graphical
session and Python Tk support are required. After installing/updating this
checkout in your environment, launch either entry point:

```sh
maher
# or
maher-bounty gui
```

The interface has an operation sidebar, generated options form, command preview,
execution state, stop control, optional GGUF file selection and text report viewer.
It reads all CLI subcommands and arguments from the same `build_parser()` used
by the terminal. Run/auto-run, native policy agents, direct tool agents, workflows,
source/API contract review, traffic import/analysis, inventory, continuous service,
service status, doctor and benchmark options are available. The benchmark is
only exposed as an existing command; it was not run during UI development.
The GUI does not recursively offer itself as a worker command.

Required inputs, original defaults, boolean authorization flags, choices and
numeric parser validation are preserved. You still supply scope, identities,
traffic exports, source paths, request packets and assessment manifests. The
workspace directory is the directory from which Maher was started; relative
paths have the same meaning as in the CLI. The local GGUF selector sets only
`MAHER_GGUF_MODEL` in the child environment; enabling model reasoning still uses
the relevant command's existing options. Credential environment variables are
inherited from the shell, not entered or stored in this interface.

Execution uses the current Python interpreter and the same CLI dispatcher in
a worker subprocess, through argv arrays without a shell interpreter. Tool
arguments, capabilities, execution budgets, scope policy and artifact formats
are not rewritten by the form. One desktop job runs at a time. The event queue
and background thread keep the window responsive; progress is an activity
indicator, not a completion percentage. Captured logs are shown when the job
ends, not streamed live. Previewing a command launches nothing.

Stop requests cancel the worker through the existing bounded process runtime.
On POSIX the worker receives cooperative SIGTERM, allowing nested adapters to
clean up their own process sessions, with a five-second grace period followed
by forced cleanup. Windows uses the existing job mechanism. Closing the window
while running requests cancellation and waits for the worker's result. Cancellation
does not reverse application mutations or safely resume an interrupted scan;
review outputs before repeating operations. Processes deliberately escaping
their groups/jobs or cleanup that exceeds the grace period are not guaranteed
to be contained. No automatic restart, rollback or forced target retry is added.

The desktop retains at most the first 8 MiB of process logs, continuously drains
later output and does not stop the CLI job because that preview budget was reached.
It labels capture truncation. Its text pane displays at most the last 200,000
characters of that captured buffer, labeled when truncated. This does not truncate
tool-generated files. Underlying tool adapters keep their existing output limits;
only the desktop wrapper opts into log truncation instead of process termination.
Long-running services remain running until stopped; their captured logs appear
at the end. Open report reads at most 4 MiB of a selected JSON/Markdown/text
file, indicates preview truncation and does not edit or execute the file.
Raw reports and tool artifacts remain available at the CLI's output paths.

This interface improves access to existing capabilities, not underlying scan
accuracy or discovery coverage by itself. Local model reasoning still requires
an installed compatible GGUF runtime/model; native workers remain fixed routines.
Tk initialization failures return a short message and leave CLI usage available.
Source/diff review only: no GUI launch, screenshot, tests, model, tool process,
application, assessment or new CI run was performed. Runtime and visual appearance
are unverified under the user's existing no-experiments restriction.

Forms retain their entered values in memory while switching operations, so
returning to a configured scope/manifest form does not reset its inputs. Values
are not written as presets or retained after closing Maher. Authorization
checkboxes retain their own value within that operation; no other operation is
implicitly authorized. Changes during a running job do not change its already
captured argv/environment.

Browse controls distinguish input files, source/watch/result directories, output
directories and output files. In particular, traffic-import output uses Save As
instead of the directory chooser, and database output fields also use Save As.
URL/numeric fields no longer show an unrelated file chooser. Output directory
selection permits a new path; the original CLI remains responsible for creating
it during execution. This form handling update was reviewed from source/diff
only; no desktop application, test or scan was launched.
