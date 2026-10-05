# Source and observed traffic correspondence

Combined runs using both `--source-dir` and `--traffic` produce
`source/source-traffic-correspondence.json`. Source evidence in the pipeline's
report and local model packets includes the same `traffic_correspondence`.
Without captured traffic the artifact records zero correspondence; it does not
invent an observed route. The standalone source review report remains the
original static snapshot. The augmented pipeline packet and correspondence artifact
use `static_artifact_generation` to identify that snapshot, rather than claiming
the original generation hash covers the additional correspondence fields.

Declared paths are compared with exact traffic references held by the local
coordinator, revalidated against the current network scope. Matching uses exact
paths or whole-segment `:name`, `{name}`, `<name>` and `<int:name>` placeholders.
Explicit HTTP methods must match. Unspecified declaration methods remain marked
unverified. Regex routes, catch-all/multiple-segment placeholders and dynamic
prefixes are not inferred. At most 200 declarations and 500 captured records are
considered. Truncation and unsupported patterns remain explicit.

The result cites file hashes, source declaration/candidate lines and traffic
reference IDs; it does not copy query/header/body values or generate new URLs.
Several hosts may share a path, and the supplied source may differ from deployed
code. Correspondence therefore does not prove deployment identity, handler
reachability, input-to-sink flow or exploitability. Candidates remain unvalidated.
This addition does not schedule tools, expand scope, reconstruct identities or
issue network requests. Existing checks can still use the previously authorized
traffic references through the normal router.

Implementation was reviewed statically only: no tests, experiments, source
analysis, model inference or live target assessments were run for this change.
