# Completed-report merge evaluation

These synthetic fixtures measure merging alone. They contain no source targets,
discovery tasks, or reproduction steps. The oracle tests independent findings
with similar titles, duplicates with distinct repairs, accepted aliases,
conflicting severities, and a field larger than ordinary tool output with useful
facts at its end and in retained sources.

Run the deterministic oracle and its negative controls:

```sh
bun test tests-ts/merge-eval.test.ts
```

An explicit model run uses the existing Codex login and incurs model usage:

```sh
bun scripts/merge-eval/run.ts /absolute/path/to/results MODEL 3
```

The runner uses the same scan matcher as Deep Scan, including full evidence for
confirmed matches. It explicitly disables inherited MCP servers, plugins, apps,
subagents, web search, and network access. Synthetic inputs reach the thread
through the matcher's catalogue and evidence messages. The temporary working
directory is empty. Results retain each turn's response and usage, the accepted
combined decision, elapsed time, and thread ID. Failed merges retain their raw
turns and error without an accepted decision. The fixture oracle is not included
in the prompt or that directory.

Two independent gates apply: the production validator checks structural source
accounting and preservation, while `grade.ts` checks expected partitions,
severity, and named repair facts in canonical fields. Full archived originals
cannot hide an omitted canonical repair. Named facts are a closed-world rubric;
inspect semantic paraphrases and unexpected outcomes independently rather than
tuning the oracle to a candidate's output. These cases do not establish general
scan precision or recall.

For comparison, run the same held-out cases against baseline and candidate at
identical model/runtime settings, alternate order, and report p50/p95, usage and
error rate with raw samples. Any failed quality gate disqualifies a speed win.
This runner times model merging and validation; it does **not** time parent
publication. Measure completion-to-sealed-parent separately with real artifact
and database operations before claiming end-to-end improvement.
