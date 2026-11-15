# triage-finding calibration dataset

This directory contains OSS seed data for calibrating `$codex-security:triage-finding` beyond the synthetic fixture app used by the current eval harness.

Each case records:

- the repository and pinned commit or commit pair to inspect
- the supplied finding text shape
- the expected triage verdict
- evidence obligations the agent must satisfy, such as reading `SECURITY.md`,
  checking a lockfile version, or comparing vulnerable and fixed commits
- provenance for the gold label

A public advisory identifies the reported vulnerability. The expected verdict describes whether the pinned repository state is `confirmed`, `not_actionable`, or `needs_review` under the `triage-finding/v0` contract.

## Files

- [`triage-calibration-seed.json`](triage-calibration-seed.json) contains the pinned vulnerable and fixed commits.
- [`test-calibration-dataset.mts`](../scripts/test-calibration-dataset.mts) performs deterministic structural validation so future additions do not silently break the dataset shape.
- [`generate-calibration-tests.mts`](../scripts/generate-calibration-tests.mts) supplies test objects directly to Promptfoo and can optionally export them as YAML.
- [`hydrate-calibration-repos.mts`](../scripts/hydrate-calibration-repos.mts) downloads the pinned OSS checkouts under `../artifacts/calibration-repos/` for local eval runs.

## Case Families

- `oss-vuln-fix-pair`: public OSS vulnerabilities with a vulnerable commit and a fix commit. These create paired `confirmed` and `not_actionable` variants for the same advisory.

## Scoring Intent

Use this dataset to score more than final verdict accuracy:

- exact verdict match
- severe error class, especially `confirmed` misclassified as `not_actionable`
- required evidence coverage
- boundary assessment correctness
- `triage-finding/v0` JSON validity
- static-only compliance: no tests, builds, PoCs, app launches, or file edits

Score the cited evidence and the verdict independently. A correct verdict can still be unsupported.
