# Standard Scan time allowance comparison

Compare production Standard scans with and without `maxTimeMinutes`. Both
arms call `CodexSecurity.run`, including setup, delegation, canonical artifact
validation, report generation, and completion. The treatment uses the shared
[investigation-time-budget.md](../../plugins/codex-security/references/investigation-time-budget.md)
policy, not an eval-only prompt.

The SDK stamps one shared UTC deadline after setup, immediately before the
first scan turn. The allowance is advisory: there is no abort timer, automatic
continuation, or minimum runtime. Finalization is outside the allowance.

## Run

Use the repository's dependency and
[native-artifact setup](../../plugins/codex-security/native/README.md), then run
from the repository root:

```sh
pnpm --dir sdk/typescript run build:plugin
pnpm --dir sdk/typescript run build:evals
node --experimental-strip-types evals/standard-time-budget/run.mts
```

Rebuild the bundle after plugin changes. This developer eval requires an existing
`OPENAI_API_KEY` or `CODEX_API_KEY` environment variable; saved Codex or
`codex-security login` credentials are intentionally unsupported. It uses the
bundled Codex SDK without reading saved logins, provisioning credentials, or
changing persistent configuration. Production SDK and CLI login support is
unchanged. **Model runs consume usage and have no enforced time or spend cap.**

[experiment.json](experiment.json) selects an explicit model, two pairs
(four scans including delegated work), and five advisory minutes. Both arms
use `xhigh` reasoning and production worker settings. Pairs alternate
baseline-first and treatment-first order. Override settings with a JSON file:

```sh
node --experimental-strip-types evals/standard-time-budget/run.mts /path/to/experiment.json
```

The fields are `model`, `pairs`, and `budgetMinutes`; positive fractional
minutes are accepted. Production deadline validation runs before either arm
starts. Ctrl+C saves the interrupted attempt, stops future arms, and waits for
child processes before cleaning temporary state.

## Fixture and isolation

The synthetic application has tenant authorization, SQL injection, file
traversal, and reflected HTML bugs, each with a safe control. Source and
deployment context go to the model; gold labels and expected locations stay
in the evaluator.

Each arm runs in an opaque temporary directory outside the artifact tree; pair
and variant labels appear only in evaluator reports and archives. After the
client closes, its scan output is archived and its state is removed before the
next arm. If state removal fails, the failed attempt is recorded and the
comparison stops before another arm starts. Gold labels and prior-arm results
are not next to the model's working directory or included in prompts. This is layout separation, not a filesystem
security boundary: production API-key authentication and root-read permissions
remain unchanged. This eval does not test resumption or external publication.

## Results

Artifacts are saved under ignored `reports/`, updated after every attempt:

- `experiment.json`: settings, evaluator/shared-helper, source, full-plugin,
  and built-SDK file hashes, plus SDK/Codex package versions and the selected
  Codex executable paths and SHA-256 hashes, including a `CODEX_CLI_PATH` override.
  npm launchers also record their native executable. Generated reports
  are excluded from evaluator hashes.
- `fixture.json`: synthetic source and held-out gold labels for review.
- `pair-<number>-<variant>/prompt.txt`: the actual first dispatched scan prompt.
- Per-arm `scan/`, `result.json`, and `report.json`: canonical scan artifacts,
  semantic output, grading, usage, elapsed time, and exact failure text.
- `runs.json` and `summary.json`: all attempts and the paired comparison.

Elapsed time is monotonic and includes SDK setup, investigation, finalization,
scan archival, cleanup, and grading, but not subsequent evaluator JSON writing.
A canonical scan that misses a bug still completed successfully. The runner
exits nonzero for execution failures, not low recall.

The grader counts unique gold cases with matching CWE, a `root_control` or
`sink` source location, and authentic source evidence. Other or missing roles
do not earn automatic recall; unmatched findings require adjudication. It
consumes the production contract's repository-relative POSIX paths. Duplicates
do not increase recall.
Safe-control overlaps, unmatched findings, and citation errors are separate
signals; overlaps and unmatched findings require adjudication, not automatic
false-positive labels. Free-text location roles can flag benign context
citations. Preserve raw scores and record adjudication separately: source
matching is a heuristic, not independent exploit validation.

The summary separates execution success from completed-run quality. Paired
deltas are treatment minus baseline and include only complete pairs; excluded
pairs remain explicit. Each attempt's top-level `usage` includes delegated
workers, even when completion or grading fails. Missing usage stays unknown,
cached input is a subset of input tokens, and no dollar cost is inferred.

## Interpretation and checks

Two pairs are a smoke comparison, not statistical evidence. Review findings
without variant labels and compare grounded recall, adjudicated false
positives, completion, tokens, and elapsed time together. More findings or a
longer run alone is not an improvement, and these arms do not have matched
spend. Expand the corpus if both arms saturate the fixture; use more pairs and
pinned public repository revisions before drawing quality/cost conclusions.

After the builds above, run deterministic checks without model calls:

```sh
node --experimental-strip-types --test evals/standard-time-budget/test_*.mts evals/secret-discovery/test_*.mts
```

The integration test uses the real SDK and canonical artifact helpers with
mocked model/workbench boundaries, verifying isolated state, completion, prompt
capture, and parent-plus-worker usage. CI reuses its host native build, builds
the plugin with `build_mcp_app.mjs --native host`, and links it at
`sdk/typescript/_bundled_plugin`; universal release artifacts are not required.
