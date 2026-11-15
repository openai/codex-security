# Dependency evidence graph

## Source collection

Directory discovery collects every matching filename and schedules structural
analysis in batches of 16 files. Collection has no total file, call, scope,
evidence, or expansion count cutoff. Matching tracked ignored files are included.
Exact file lists use the same batches; dependency manifests are inspected
separately. File and directory lists have no count cutoff. Repeated complete
source batches are cached; changing a file invalidates its batch.
Source files still have a 1 MiB size limit. Native scan output, cancellation,
requested time and hop budgets, and graph retention limits can leave explicit
incomplete coverage; a large file count alone does not.

Full collected results feed the host graph and candidate registry before the
model view is bounded. Model-facing replies remain paged to 128 items and 32 KiB;
that projection does not discard collected candidates or mark completed source
collection incomplete.

Every OpenGrep call or flow scan requires model-authored `rules: [...]` containing
standard native OpenGrep rule objects. There is no built-in rule fallback;
missing rules return an incomplete lookup without invoking OpenGrep. Package,
manifest, catalog and service-only lookups can omit rules when they do not scan
calls or flows. The
native parser validates patterns, language names and rule fields; supplied IDs
are retained rather than rewritten or filtered to built-in names. Use native
`focus-metavariable` when a surrounding pattern needs a precise call range.
Captures such as `$CALLER`, `$ALIAS` and `$RECEIVER` can provide caller and alias
context. Optional `metadata.evidence_kind: "unresolved_lead"` records a native
match as text to investigate, not an execution edge. Other metadata remains
opaque; `metadata.focus_metavariable` is not interpreted by this tool.

Exact custom-rule files are passed to the native engine, including extensions
outside the default Go/Python/JavaScript/TypeScript discovery map. Native skipped
targets and parse errors remain incomplete. Configurations, native IDs and
engine identity are retained once in graph/host provenance; model projections
show references and summaries. Both direct and batch cache identities include
the actual serialized rule configuration and material native scan options.
A matched call remains a syntactic candidate, not proof of execution or access.

Trace citations retain their existing `source` and `lines` fields and include
`matches` with the native `start`/`end` line, column (`col`) and byte offset,
plus native rule and rule-execution references. Grouped citations retain each
distinct match. Static graph facts expose the same range as `match`. These are
the actual native ranges: a receiver-only focus is not widened to a whole call.

Caller followups identify the next operation but do not generate its rules.
Supply newly authored rules for those followups. An automatic hop without rules
is explicitly incomplete rather than a silent leaf-pattern scan.

## Sampled observations

The host can ingest a saved observation receipt through
`session.recordObservations(observations, receiptId, recordPrefix)`.
`recordPrefix` defaults to `["observations"]`. This host method is not an MCP
tool; the model uses the existing `query_codex_security_graph` tool.

Each `TraceObservation` contains a native `id`, `kind: "sampled_stack"`, a
JSON-compatible `scope` object, and root-first `TraceEntity` frames (caller before
callee). The normalized receipt container declares `frame_order: "root_first"`.
Producers
supply frame scopes that identify the image, build, or other runtime context.
The graph keeps sampled identities separate from static source identities.
Unscoped sampled names are local to one witness.

Each receipt record becomes a separate witness. Its `id` is a graph query ID,
derived from the receipt and record position. Its `native_id` preserves the
source observation's `id`; these identifiers have different purposes and are
not expected to match. Use the graph `id` in the query's `witness` argument.
Its internal receipt selector is exactly
`{receiptId, textBlock: 0, record: [...recordPrefix, index]}`. Model-visible
citations select only the observation's `id`, `kind`, and `scope` fields, specific
`frames` entries, and the normalized container's `frame_order`. The order selector
is `["frame_order"]` by default, or
`[...recordPrefix.slice(0, -1), "frame_order"]` for a nested observation array.
These citations never select the whole observation. Native ordering metadata
inside `scope` describes the original profile and does not override the normalized
container's order. Every witness summary explicitly reports
`frame_order: "root_first"`. Ordered frame IDs
include repeated frames, preserving recursion. Shared call edges retain separate
witness membership and occurrence positions; calls from different stacks never
become one observed path. Static candidate calls retain their existing meaning.

Query examples:

```json
{}
{"search": "decode"}
{"witness": "witness_<id>"}
{"node": "node_7", "witness": "witness_<id>"}
```

The summary lists bounded witness metadata and counts after ingestion. A witness
query returns root-first frame IDs, scoped nodes, and position-indexed frame
citations. A node query lists its
witnesses; selecting one also returns only that witness's adjacent observed
calls with exact citations for both adjacent frames. Sampling shows observed execution, and an absent frame does not establish
that code cannot run.

The ingestion summary reports `received`, `retained`, `already_recorded`,
`omitted`, `witnesses_found`, and `observed_calls_found`. Whole witnesses are
retained within a 64 MiB host-side graph retention budget, independently of
the model-visible response limit. This leaves room for successive collections
without increasing model context. Re-ingesting the same
receipt record is idempotent. Query replies retain at most 128 items per list
and fit within 32 KiB. `truncated`, omission counts, and `omitted_fields` identify
omitted details; returned receipt selectors remain exact. The original receipt
remains the source for full evidence.
