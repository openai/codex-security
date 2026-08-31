# triage-finding calibration dataset

This directory contains OSS seed data for calibrating `$codex-security:triage-finding` beyond the synthetic fixture app used by the current eval harness.

The dataset is intentionally small and reviewable. It is not a raw dump of every available advisory. Each case records:

- the repository and pinned commit or commit pair to inspect
- the supplied finding text shape
- the expected triage verdict
- evidence obligations the agent must satisfy, such as reading `SECURITY.md`,
  checking a lockfile version, or comparing vulnerable and fixed commits
- provenance for the gold label

The important distinction is that GitHub advisory state is source material, not the answer key. The expected verdict asks whether the pinned repository state is `confirmed`, `not_actionable`, or `needs_review` under the `triage-finding/v0` contract.

## Files

- `triage-calibration-seed.json` is the first OSS-only seed dataset. It contains public vulnerable/fixed commit pairs.
- `../scripts/test-calibration-dataset.js` performs deterministic structural validation so future additions do not silently break the dataset shape.
- `../scripts/generate-calibration-tests.js` converts the dataset into Promptfoo tests at `../tests/calibration-oss.yaml`.
- `../scripts/hydrate-calibration-repos.js` downloads the pinned OSS checkouts under `../artifacts/calibration-repos/` for local eval runs.

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

ELI5: the final label is the short answer, but the evidence obligations check that the agent got the answer for the right reason.
