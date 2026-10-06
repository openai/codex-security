# SastBench triage-finding eval design

## Evaluation boundary

`triage-finding` classifies supplied vulnerability reports using static repository evidence. SastBench is used here as an alert-triage benchmark, not as evidence that the skill performs repository-wide vulnerability discovery.

The benchmark is pinned to commit `b8d95b7720491b21d039b7504999577ba7ebb12b`. Its original v0.1 dataset has SHA-256 `57c765633bdefc2130d3725dd9648bc49b85456e4dd733c55f49d44d883c9487`, 2,737 cases, 299 true positives, and 2,438 approximate false positives.

## Responsibilities

Promptfoo owns model execution, concurrency, filtering, persistence, pause/resume, retries, per-row counters, derived aggregate metrics, resource usage, and JSONL output.

The SastBench adapter owns only benchmark-specific behavior:

- pinned dataset and checkout validation;
- hydration of exact repository revisions;
- staging of a label-free skill working directory;
- conversion of `to_analyzer` records into scanner-ticket input;
- prevention of benchmark-label leakage;
- triage-result parsing and verdict mapping; and
- emission of additive benchmark counters after each Promptfoo result.

## Label boundary

The model-visible prompt contains the affected checkout, an opaque case ID, and the record's `to_analyzer` data. Ground truth is stored in Promptfoo test metadata. The upstream `finding_id`, `ground_truth`, `metadata.source`, and dataset class statistics are not prompt variables.

The Codex provider runs from a throwaway directory containing only the runtime skill files. A deny-by-default permission profile grants reads only to that directory, the hydrated target repos and their label-free Git cache, and Codex's minimal runtime paths; the label-bearing dataset and Promptfoo harness stay denied.

## Verdict mapping

| Triage verdict | SastBench interpretation |
| --- | --- |
| `confirmed` | predicts true positive |
| `not_actionable` | predicts false positive |
| `needs_review` | abstains |

Strict metrics count an abstention as incorrect for that row. Decided-only metrics exclude abstentions and report coverage. Workflow metrics separately measure true-positive retention, unsafe closure, false-alert auto-closure, false-alert escalation, confirmed precision, abstention, and remaining analyst workload. Model errors and invalid output remain unresolved work.

## Reproducibility

The installer verifies the external repository, commit, dataset hash, and class counts. The model, reasoning effort, filesystem permission profile, approval policy, network policy, and user-level feature isolation are explicit in the Promptfoo configuration. One evaluation must run and resume from an unchanged source checkout.

## Representative sample

The `representative-100-v1` sample is the normal skill-iteration lane. It selects 40 of the 299 positive cases and 60 of the 2,438 negative cases. Selection is deterministic and uses only benchmark metadata available before model execution; it never selects cases based on the current skill's verdict.

Within each ground-truth class, the sampler allocates cases proportionally across evidence-size strata and uses seeded systematic selection ordered by repository, CWE, language, and original case index. Original case IDs are preserved for paired baseline/candidate comparisons.

The sample intentionally changes the class ratio to measure positive safety with useful precision. Each row therefore carries its stratum's inverse sampling weight. The shared metrics extension applies those weights to the confusion-matrix and workflow counters. The full and sample configs consequently use the same derived metric formulas; on a full run every row's weight is one.

## Limitations

SastBench's false-positive class is produced by its benchmark methodology and is not a fully human-adjudicated corpus. Results therefore measure agreement with SastBench labels, not absolute vulnerability truth.

The evaluation measures classification of supplied findings. It does not measure whether an LLM or deterministic scanner discovers vulnerabilities that were never provided as input.
