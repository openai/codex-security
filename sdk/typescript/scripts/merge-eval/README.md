# Completed-report merge evaluation

These synthetic fixtures measure grouping completed findings. They contain no
source targets or reproduction steps. Cases cover independent findings with
similar titles, duplicate procedures, accepted aliases, conflicting severity,
and large fields with useful facts at the end and in nested history.

The model returns source groups and selects an existing canonical finding. The
host retains exact originals and accepted history. This deliberately gives up
synthesizing one narrative from complementary sources; their details remain in
provenance. Previously accepted groups select their current canonical narrative;
they cannot revert to an archived original. The host retains the first/prior
scope and threat model, and records each child context under `scope.sourceScans`.
The independent oracle checks grouping and evidence-supported
canonical selection, while the production validator checks all-source
accounting, indivisible accepted groups, and preservation.

Run deterministic quality checks and negative controls:

```sh
bun test tests-ts/merge-eval.test.ts
```

An explicit model run uses the existing Codex login and incurs model usage:

```sh
bun scripts/merge-eval/run.ts /absolute/path/to/results MODEL 3
```

The runner disables inherited MCP servers, plugins, apps, subagents, web search
and network access. Its temporary directory contains only synthetic inputs,
without the oracle. Raw responses, usage, latency and thread IDs are retained for
review. Compare baseline and candidate with the same held-out cases and runtime
settings; alternate order and report raw samples and error rates. A failed
quality gate disqualifies a speed improvement. These cases do not establish
general scan precision or recall, and grouping quality still needs model evals.
