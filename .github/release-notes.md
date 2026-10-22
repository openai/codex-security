<!-- release-version: 0.6.0 -->

<!-- release-section: highlights:start -->

## Highlights

Codex Security 0.6.0 adds vendor report imports, optional owner suggestions, and hosted remediation commands. Severity classification now uses a built-in rubric and three independent reviews by default; review the model-access and cost changes below before upgrading.

- **Import vendor findings.** Import supported Wiz, Snyk Open Source, Semgrep Code, and Endor Labs reports with `publish findings --to local`, or publish them with `--to cloud`. Read local evidence with `findings imported`. Local imports require no Cloud login or model call and remain separate from assessed scan findings. See the [Wiz](https://github.com/openai/codex-security/blob/npm-v0.6.0/sdk/typescript/docs/cli.md#import-wiz-findings), [Snyk](https://github.com/openai/codex-security/blob/npm-v0.6.0/docs/scanner-imports/snyk.md), [Semgrep](https://github.com/openai/codex-security/blob/npm-v0.6.0/docs/scanner-imports/semgrep.md), and [Endor](https://github.com/openai/codex-security/blob/npm-v0.6.0/docs/scanner-imports/endor.md) format guides.
- **Configurable severity reviews.** `classify-severity` uses a bundled rubric when no custom rubric is supplied. `--runs N` selects 1–10 independent reviews, with three by default. The most common severity wins, with the highest severity breaking ties. ([#1765](https://github.com/openai/codex-security/pull/1765))
- **Optional owner suggestions.** `scan --owner-suggestions` writes a separate owner-suggestion report after supported committed Git scans. Suggestions preserve the completed scan and do not assign users. Owner enrichment is skipped when a scan cost limit is set. ([#1760](https://github.com/openai/codex-security/pull/1760))
- **Hosted patching and source-only verification.** `patch --host` and `verify-fix --host` expose the hosted remediation protocol through the CLI. Ordinary patch and verification commands accept `--verification-mode static` to assess source evidence; omitting it preserves standard verification. Static mode sets the assessment scope and does not enforce a command-execution boundary. See the [hosted remediation guide](https://github.com/openai/codex-security/blob/npm-v0.6.0/sdk/typescript/docs/hosted-remediation.md). ([#1854](https://github.com/openai/codex-security/pull/1854))
- **Policy previews without Python.** Policy diffs now run in Node while preserving diff formatting, cancellation, and source freshness checks. ([#1837](https://github.com/openai/codex-security/pull/1837))

<details>
<summary>Other improvements</summary>

- Patch project-trust overrides are serialized correctly for Codex. ([#1861](https://github.com/openai/codex-security/pull/1861))
- Update Hono and the Linear SDK dependencies. ([#1831](https://github.com/openai/codex-security/pull/1831), [#1852](https://github.com/openai/codex-security/pull/1852))
- Release verification runs test shards in parallel and reports publication progress on the release PR. ([#1798](https://github.com/openai/codex-security/pull/1798))

</details>

<!-- release-section: highlights:end -->

<!-- release-section: upgrades:start -->

## Upgrade notes

### Severity classification requires model access

Classification without `--rubric` previously inherited the scanner's severity without model work. It now requires Codex authentication and model access, using three model calls per uncached finding by default. Set `--runs 1` (SDK: `classificationRuns: 1`) for a single review. All requested reviews must succeed; failures do not fall back to the scanner's severity or save a partial vote.

Older classification checkpoints without a recorded review count, and former inherited assessments without a rubric hash, are reclassified on the next classification request. Changing the review count or rubric also invalidates matching checkpoints. Existing results remain readable, and publication does not silently classify findings. Use `--reprocess` when changing only the model or reasoning effort. See the [classification guide](https://github.com/openai/codex-security/blob/npm-v0.6.0/sdk/typescript/docs/cli.md#classify-finding-severity).

### Policy preview interpreter selection is deprecated

`securityPolicyDiff(draft, python, signal)` retains its call shape, but interpreter strings and paths returned by resolver callbacks no longer select or validate an executable. `previewPolicy()` no longer resolves Python, and `pythonPath` and `PYTHON` do not affect previews. Update integrations that relied on an invalid interpreter failing or a custom executable producing the diff. Explicit resolver callbacks still run for changed drafts and propagate their errors. Omit the second argument in new code, or pass `undefined` when supplying a cancellation signal. Python-dependent generation and other operations are unchanged.

### Import identity and earlier upgrades

Keep a stable source key and acquisition format across vendor imports. Switching formats can create separate records or replace richer evidence with less detail; omitted findings remain stored. Review each provider's format guide before changing inputs.

If upgrading from before 0.5.1, also review the [0.5.1 upgrade notes](https://github.com/openai/codex-security/releases/tag/npm-v0.5.1) and their guidance for earlier versions. Use `openai/codex-security@action-v0.6.0` for the matching GitHub Action, or pin the distribution commit in its companion release after publication.

<!-- release-section: upgrades:end -->
