# SCA evaluation

This harness tests dependency advisory assessment using twelve fictional
application snapshots. It does not discover vulnerabilities or
execute affected code. Four advisory families each contain an affected, a
not-affected, and an unresolved configuration. The labels come from the fixture
specification; none has independent human review.

The suite distinguishes a correctly matched dependency advisory from application
applicability. The original match remains in each frozen `osv.json`, including
when the application assessment is negative, unresolved, malformed, or fails.
SDK tests separately exercise actual scanner invocation and artifact retention.

## Deterministic checks

Install the TypeScript SDK dependencies using the repository's normal setup; the
scorer uses that installation's Ajv to validate the canonical plugin triage
schema. No model, network, OSV binary, or package installation inside the
synthetic target repositories is required:

```sh
node --experimental-strip-types --test evals/triage-finding/sca/scripts/test-sca.js
```

Checks cover frozen input/source/advisory digests, all three gold labels, schema
and match IDs, package/version/source/advisory correspondence, source citations,
execution errors, confusion matrices, cost/latency availability, alias/source
occurrence retention, and isolation of label-bearing evaluation files.

Mechanical evidence checks require a repository-relative `path:line` citation
plus a backtick-quoted source fragment in `evidence` or `counterevidence`. They
verify that the fragment actually appears in the cited source span and concerns
the configuration needed for that case. They do **not** establish that a human
reviewer supports the reasoning; that metric stays null until reviewed.

## Optional model smoke

From `evals/triage-finding`, install the existing pinned Promptfoo dependencies
with `pnpm run setup`. Before model calls, also follow the checkout policy-helper
build steps in the [triage eval setup](../README.md). Config validation and
deterministic tests do not need that helper build. Then:

```sh
pnpm run validate:sca
pnpm run eval:sca:smoke
pnpm run eval:sca
node --experimental-strip-types sca/scripts/sca-result.js artifacts/sca-eval.json > artifacts/sca-summary.json
node --experimental-strip-types sca/scripts/baselines.js > artifacts/sca-baselines.json
```

`eval:sca:smoke` selects the first affected/not-affected/unresolved family.
The full suite compares two prompts against identical captured records: the
current static triage skill and a typed-match prompt prototype. This prototype
isolates prompt behavior; it is **not** an end-to-end benchmark of the SDK's
`scanDependencies` orchestration. Run SDK process-boundary tests for that.

The runner stages only label-free case files and its provider adapter in a temporary
directory. It uses the checkout's plugin runtime and the selected Node executable,
including for Promptfoo, Codex, and the security-policy helper. The provider keeps
the existing named read-only filesystem profile, allowing the plugin, staged cases,
Node executable directory, and installed native Codex CLI package. Tool network
access, web search, inherited MCP servers, apps, and plugin/memory context remain
disabled. Per-run provider overrides retain the existing Codex home for saved
logins and token refreshes. Gold labels, scoring scripts, and the corpus manifest
stay outside the model's readable workspace.
No remote target hydration is needed. Model calls use the configured local Codex
authentication and can incur cost. Promptfoo `--no-cache --no-share` is set in
the provided scripts. Existing provider error rows are retained by the `afterEach`
hook even when ordinary assertions never run.

The runner passes inherited MCP server names as one literal configuration table
through the existing launcher, preserving names containing periods. The saved
configuration stays unchanged.

The pinned model is inherited from the existing calibration suite. Record the
actual model, CLI/SDK versions, prompt digests, token usage, run date, and settings
for any comparison. Re-run both prompts after changing a prompt or fixture; do
not compare different fixture/advisory revisions. The fixture source/input
SHA-256 values are checked in `fixtures/corpus.json`.

## Scores and interpretation

The JSON summarizer reports results separately by provider and prompt, including
the three-class confusion matrix and separate model-error/invalid-output columns.
Affected recall includes all affected attempts, including abstentions and failed
executions. Unresolved cases do not count as negative cases. Unjustified decisive
judgments on unresolved cases are explicitly counted. Confirmation precision,
incorrect dismissal rate, dismissal precision, uncertainty handling, decision
coverage, decision accuracy, mechanical citation pass rate, and reviewed evidence
support are separate measures. Undefined denominators produce `null` in the JSON
summary; the live Promptfoo display uses zero-denominator guards.

Repeated runs increase `attempted`, while `uniqueCases` and `advisoryFamilies`
show the number of distinct contexts. Twelve highly related synthetic cases are
not twelve independent assurances of production accuracy. Latency and cost are
reported only where available; `costCoverage` shows missing measurements.

`matchRetention(supplied, retained)` is a deterministic utility for checking each
source/package/version/advisory occurrence. Alias grouping may not lose the
original IDs. It does not infer scanner retention from a model's verdict.

## Human corpus and developer pilot

`corpus/manifest.json` records the still-unfilled 30-case development and 60-case
held-out corpus targets. `corpus/adjudication-template.json` is an empty reviewer
record. Do not fill it by treating a model output or the synthetic fixture label
as a human judgment. Use two independent reviewers, hide model results until
labels are frozen, adjudicate disagreements, and preserve unresolved labels when
evidence is missing. Split by repository and advisory family, including aliases.
Keep nonpublic snapshots and findings out of this public repository.

Before a product accuracy claim, compare four arms on the same captured inputs:
OSV report only, OSV plus inspectable conventional usage evidence, current triage,
and the actual SDK SCA wrapper. Scanner-only arms have no invented application
verdicts; measure their developer review outcomes. Human evidence support,
reviewer agreement, confidence intervals, and cluster-level variation belong in
that pilot report. The two-prompt smoke cannot replace it.

For the proposed developer pilot, collect 15–20 paired review sessions with 5–8
developers and 10–12 update tasks. Counterbalance the order of tools. Measure
median paired review time, correct understanding of scope/uncertainty, corrections
or reopens, accepted updates, and actual lockfile-resolution plus project-check
results. See `corpus/developer-pilot.csv` for an empty recording template. No
developer results or successful upgrade outcomes are claimed by this harness.
