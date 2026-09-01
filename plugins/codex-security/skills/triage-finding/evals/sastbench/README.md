# SastBench triage-finding eval

This Promptfoo lane measures how accurately the source version of `plugins/codex-security/skills/triage-finding/SKILL.md` triages supplied scanner findings from public SastBench v0.1. It does not measure repository-wide vulnerability discovery.

SastBench contains 2,737 findings: 299 labeled true positive and 2,438 labeled false positive. The JavaScript test generator exposes the scanner claim and the exact affected checkout to Codex while keeping SastBench's label-bearing `finding_id` and ground-truth label out of the rendered prompt. The eval runner stages the skill in a throwaway working directory and uses a deny-by-default Codex permission profile so only that directory, hydrated target repos, and their label-free Git cache plus minimal Codex runtime paths are readable to the model.

Run commands from the repository root. The parent `evals/` directory owns the pinned Promptfoo and Codex SDK dependencies and the ignored `artifacts/` tree.

## Prepare the benchmark

Install dependencies once:

```bash
pnpm --dir plugins/codex-security/skills/triage-finding/evals run setup
```

Install the pinned SastBench checkout and hydrate all 275 repository revisions:

```bash
pnpm --dir plugins/codex-security/skills/triage-finding/evals run sastbench:prepare
```

Preparation verifies the SastBench origin, pinned commit, dataset SHA-256, record counts, target origins, target commits, and clean target worktrees. It must finish before any paid model evaluation begins.

## Verify the harness

Run deterministic tests and ask Promptfoo to load the dynamic test generator:

```bash
pnpm --dir plugins/codex-security/skills/triage-finding/evals run test:sastbench
pnpm --dir plugins/codex-security/skills/triage-finding/evals run validate:sastbench
```

## Run an evaluation

```bash
pnpm --dir plugins/codex-security/skills/triage-finding/evals run eval:sastbench \
  --output ./artifacts/sastbench-results/canary.promptfoo.jsonl
```

To start, it is recommended to use `--filter-range n:m` or `-n m` to constrain the number of test cases.

Both full and representative runs pass `--no-cache --no-share` so results use the current skill and local Promptfoo settings cannot upload benchmark data.

## Run the representative sample

Use the representative sample while iterating on `triage-finding`. It runs 100 of the 2,737 benchmark cases: 40 ground-truth `true_positive` cases and 60 ground-truth `false_positive` cases. In SastBench terminology, `false_positive` is the negative class: the supplied scanner alert is expected to be benign.

The sample reuses the full eval's pinned dataset, hydrated repositories, prompt, provider, assertions, extension, and derived metrics. The sample config inherits the full config and replaces only its description, tag, and test generator.

Validate and run it from the repository root:

```bash
pnpm --dir plugins/codex-security/skills/triage-finding/evals run validate:sastbench:sample
pnpm --dir plugins/codex-security/skills/triage-finding/evals run eval:sastbench:sample \
  --output ./artifacts/sastbench-results/representative-sample.promptfoo.jsonl
```

`eval:sastbench:sample` always passes `--no-cache --no-share` and defaults to 32 concurrent cases, matching the completed full benchmark's proven setting. The prior case latencies imply roughly a 35-minute run, although provider capacity and changes to the skill can change that duration. If capacity errors occur, use Promptfoo's `--retry-errors` mode at lower concurrency so successful rows stay in the same evaluation.

The `representative-100-v1` selection is deterministic. It allocates each class proportionally across scanner evidence-size buckets (`1`, `2-3`, `4-10`, and `11+` locations), then uses seeded systematic sampling ordered by repository, CWE, language, and original case index. It preserves the original opaque case IDs so baseline and candidate skill runs compare the same findings.

Because positives are deliberately oversampled, each test's metadata includes a population weight. The existing SastBench metrics extension applies that weight to its additive counters, so aggregate derived metrics estimate the full 2,737-case benchmark. Per-row Promptfoo pass/fail counts and the `schema_valid`/`strict_case_correct` assertions still describe the 100 executed rows.

Use the same fixed case IDs for baseline and candidate skill runs. The paired case-level changes are the primary iteration signal; run the full benchmark before accepting a material skill change.

Do not substitute `-n 100` for this config. The upstream dataset is ordered, so the first 100 rows are not a representative sample.

## Inspect native metrics

Promptfoo computes the SastBench confusion matrix, strict and decided-only metrics, abstention rates, workflow rates, and error rates while the evaluation runs. The `afterEach` extension adds counters to every row, including provider errors, and weights representative-sample counters back to the full benchmark population. The `derivedMetrics` section in `promptfooconfig.sastbench.yaml` calculates the aggregate results.

### Verdict mapping

SastBench's `false_positive` label is the benchmark's negative class: it means the supplied scanner alert is expected to be benign. The eval maps `triage-finding` verdicts to SastBench predictions as follows:

| SastBench ground truth | `confirmed` | `not_actionable` | `needs_review` | Execution or parse error |
| --- | --- | --- | --- | --- |
| `true_positive` | True positive | False negative | Strict false negative; excluded from decided-only metrics | Strict false negative; excluded from decided-only metrics |
| `false_positive` | False positive | True negative | Strict false positive; excluded from decided-only metrics | Strict false positive; excluded from decided-only metrics |

Strict metrics count every benchmark row. They count `needs_review` and execution or parse errors as incorrect. Decided-only metrics include only valid `confirmed` and `not_actionable` verdicts.

### Aggregate metric definitions

The formulas below use these symbols:

- `TPs`, `TNs`, `FPs`, and `FNs` are the strict confusion-matrix counters.
- `TPd`, `TNd`, `FPd`, and `FNd` are the decided-only counters.
- `W = P + N` is the represented benchmark population. For the full eval it is the number of evaluated rows. For the sample it is the sum of row weights.
- `D` is the weighted number of valid `confirmed` or `not_actionable` decisions.
- `P` is the weighted number of ground-truth `true_positive` cases.
- `N` is the weighted number of ground-truth `false_positive` cases.

The `Group` column uses these categories:

- `Strict` scores every benchmark row. Abstentions and execution or parse errors count as incorrect.
- `Decided only` scores valid `confirmed` and `not_actionable` verdicts. Abstentions and execution or parse errors are excluded.
- `Workflow` measures operational triage outcomes: alerts retained, auto-closed, escalated, or left for analysts.
- `Reliability` measures whether the eval produced a usable, parseable result, independently of classification accuracy.

Every denominator uses `max(denominator, 1)`. An empty denominator therefore produces `0` instead of `NaN`.

| Group | Metric | Exact definition | Interpretation |
| --- | --- | --- | --- |
| Strict | `strict_precision` | `TPs / max(TPs + FPs, 1)` | Of the cases treated as positive by strict scoring, the fraction that are genuine positives. Negative abstentions and errors count as strict false positives. |
| Strict | `strict_recall` | `TPs / max(TPs + FNs, 1)` | Fraction of all genuine alerts explicitly marked `confirmed`. `not_actionable`, `needs_review`, and errors on positive cases reduce strict recall. |
| Strict | `strict_f1` | `2 * TPs / max(2 * TPs + FPs + FNs, 1)` | Harmonic balance between strict precision and strict recall with equal weight. |
| Strict | `strict_f2` | `5 * TPs / max(5 * TPs + FPs + 4 * FNs, 1)` | Precision-recall balance weighted toward recall, so missing a genuine alert matters more than retaining a false alert. |
| Strict | `strict_accuracy` | `(TPs + TNs) / max(W, 1)` | Fraction of the represented population assigned the exact correct decisive verdict. Abstentions and errors are incorrect. |
| Strict | `strict_mcc` | `(TPs * TNs - FPs * FNs) / max(sqrt((TPs + FPs) * (TPs + FNs) * (TNs + FPs) * (TNs + FNs)), 1)` | Matthews correlation coefficient across all rows. It balances both classes in the imbalanced SastBench dataset. The usual range is `-1` to `1`; a degenerate confusion matrix returns `0` through the denominator guard. |
| Decided only | `decided_precision` | `TPd / max(TPd + FPd, 1)` | Among valid `confirmed` decisions, the fraction that are genuine positives. Abstentions and errors are excluded. |
| Decided only | `decided_recall` | `TPd / max(TPd + FNd, 1)` | Among genuine-positive cases with a decisive verdict, the fraction marked `confirmed`. This is not overall recall because positive abstentions and errors are excluded. |
| Decided only | `decided_f1` | `2 * TPd / max(2 * TPd + FPd + FNd, 1)` | Equal-weight precision-recall balance over decisive verdicts only. |
| Decided only | `decided_f2` | `5 * TPd / max(5 * TPd + FPd + 4 * FNd, 1)` | Recall-weighted precision-recall balance over decisive verdicts only. |
| Decided only | `decided_accuracy` | `(TPd + TNd) / max(D, 1)` | Fraction of valid non-abstaining decisions that are correct. |
| Decided only | `decided_mcc` | `(TPd * TNd - FPd * FNd) / max(sqrt((TPd + FPd) * (TPd + FNd) * (TNd + FPd) * (TNd + FNd)), 1)` | Matthews correlation coefficient after excluding abstentions and errors. Read it together with `decided_coverage`. |
| Decided only | `decided_coverage` | `D / max(W, 1)` | Fraction of the represented population receiving a valid `confirmed` or `not_actionable` verdict. Low coverage can make decided-only quality look artificially strong. |
| Workflow | `true_positive_retention` | `(positive cases marked confirmed or needs_review) / max(P, 1)` | Fraction of genuine alerts not automatically closed. `needs_review` counts as retained; an execution or parse error does not. |
| Workflow | `unsafe_closure_rate` | `(positive cases marked not_actionable) / max(P, 1)` | Fraction of genuine alerts the skill would incorrectly auto-close. |
| Workflow | `false_alert_auto_closure_rate` | `(negative cases marked not_actionable) / max(N, 1)` | Fraction of actual false alerts removed without human review. |
| Workflow | `false_alert_escalation_rate` | `(negative cases marked needs_review) / max(N, 1)` | Fraction of false alerts sent to a human instead of being auto-closed. Negative cases incorrectly confirmed or ending in errors are outside this numerator. |
| Workflow | `confirmed_precision` | `(positive cases marked confirmed) / max(all confirmed cases, 1)` | Among alerts placed in the confirmed queue, the fraction that are genuine. Under the current verdict mapping, this is numerically equal to `decided_precision`. |
| Workflow | `abstention_rate` | `(valid needs_review verdicts) / max(W, 1)` | Fraction of the represented population where the skill explicitly declines to decide. Execution and parsing errors are not abstentions. |
| Workflow | `remaining_analyst_workload` | `(confirmed + needs_review + execution or parse errors) / max(W, 1)` | Fraction of the represented alert queue still requiring human handling. Only a valid `not_actionable` verdict removes an alert from this workload, even when that closure is unsafe. |
| Reliability | `execution_or_parse_error_rate` | `(model errors + invalid outputs) / max(W, 1)` | Fraction of the represented population without a usable triage verdict because execution failed or the output could not be parsed as the required contract. |

`schema_valid` and `strict_case_correct` are per-row assertions rather than derived aggregate metrics. `schema_valid` checks the complete `triage-finding/v0` schema. `strict_case_correct` checks the verdict against the binary SastBench label and fails for `needs_review`, malformed output, and provider errors.

Open the Promptfoo viewer to inspect the completed evaluation:

```bash
pnpm --dir plugins/codex-security/skills/triage-finding/evals run pf:view
```

Promptfoo also records cost, latency, and token use without SastBench-specific code.

## Full-run safety

Do not start all 2,737 cases until a representative pilot establishes an approved cost and runtime envelope. Keep the checkout, `SKILL.md`, prompt, configuration, dataset, and Promptfoo dependency versions unchanged throughout one resumable evaluation. See [DESIGN.md](./DESIGN.md) for metric definitions and benchmark limitations.
