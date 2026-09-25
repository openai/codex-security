# Codex Security GitHub Action

Run Codex Security scans in GitHub Actions. Scan a repository or pull request,
check findings against a severity threshold, and export JSON, coverage, and
SARIF reports.

## Quick start

Use a GitHub-hosted Ubuntu 24.04 x64 runner on GitHub.com and an OpenAI API key
with access to the selected model. For Amazon Bedrock, see the separate
[workflow example](../examples/github-actions/README.md).

Add your API key as a repository secret named `CODEX_SECURITY_API_KEY`, then
save this workflow in `.github/workflows/codex-security.yml`.
Replace `REPLACE_WITH_REVIEWED_COMMIT` with the full SHA of an Action commit.
When using a fork, replace `openai` with the fork owner.

```yaml
name: Codex Security repository
on:
  workflow_dispatch:
  schedule:
    - cron: '23 7 * * 1' # Mondays at 07:23 UTC

permissions:
  contents: read

jobs:
  security:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: openai/codex-security@REPLACE_WITH_REVIEWED_COMMIT
        with:
          model: gpt-5.6-sol
          effort: high
        env:
          OPENAI_API_KEY: ${{ secrets.CODEX_SECURITY_API_KEY }}
```

The workflow runs weekly on Mondays at 07:23 UTC. To run it manually, use
**Actions → Codex Security repository → Run workflow**.
Findings are report-only by default. Valid partial results produce a warning;
scanner and required reporting errors fail the job. Set `fail-on-severity` to
fail on findings at or above a selected severity when the scan is complete.

## Scan pull requests

Use the same API-key secret and Action commit as above. Check out the PR head
with full history so the Action can resolve the diff.

```yaml
name: Codex Security PR
on:
  pull_request:
    types: [opened, synchronize, reopened, ready_for_review]

permissions:
  contents: read

concurrency:
  group: codex-security-pr-${{ github.event.pull_request.number }}
  cancel-in-progress: true

jobs:
  security:
    if: github.event.pull_request.head.repo.full_name == github.repository
    name: Codex Security
    runs-on: ubuntu-24.04
    timeout-minutes: 60
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          ref: ${{ github.event.pull_request.head.sha }}
          fetch-depth: 0
          persist-credentials: false
      - name: Scan PR changes
        id: security
        uses: openai/codex-security@REPLACE_WITH_REVIEWED_COMMIT
        with:
          scope: diff
          model: gpt-5.6-luna
          effort: medium
          fail-on-severity: high
        env:
          OPENAI_API_KEY: ${{ secrets.CODEX_SECURITY_API_KEY }}
```

This job fails on high or critical findings from a complete scan, or on scanner
and required reporting errors. Valid partial results warn without failing the
job; the severity policy is not evaluated for those results. File and line
annotations are enabled by default.

Use PR scanning for trusted contributors with branches in the calling repository.
To scan Dependabot PRs, also configure `CODEX_SECURITY_API_KEY` as a
[Dependabot secret](https://docs.github.com/en/code-security/reference/supply-chain-security/troubleshoot-dependabot/dependabot-on-actions#accessing-secrets).
The same workflow uses that secret for Dependabot runs and the Actions secret for
other runs. Missing credentials fail with setup guidance.

Fork PRs are skipped by this example. GitHub treats skipped jobs as successful
for required checks; skipped does not mean scanned. `pull_request_target` and
`workflow_run` are not supported.

The scanner uses applicable `SECURITY.md` guidance from the checked-out revision,
including policy changes in the PR. Review those changes alongside the code.

## Scan settings

The Action defaults to `mode: standard` for repository, selected-path, and diff scans.
Keep unrelated credentials and deployment steps in separate jobs.

- Set `paths` to newline-separated files or folders to scan part of a repository.
  This requires repository scope.
- For diff scans outside PR events, set `diff-base`.
- Set `dry-run: 'true'` to check configuration without an API key or model calls.
  Use a separate setup job; dry-run does not assess code or verify model access.

For a Deep scan of a repository or selected paths, add these inputs to the scan step:

```yaml
with:
  mode: deep
  max-time-hours: '2'
```

Deep mode does not support diff scans. `max-time-hours` limits Deep discovery;
finalization can take additional time. It is unset by default, which uses the
CLI's default of 96 hours. Set an explicit budget for Deep scans that leaves
room for finalization within your job timeout and the Action's six-hour scan
limit.

## Reports

The Action writes a job summary and source annotations. Set
`upload-artifacts: 'true'` for downloadable reports, retained for seven days by
default. Reports can contain source code and vulnerability details.

The Action uses the normal Actions job check. Its summary and final log message
distinguish findings above the failure threshold from a scan that could not
complete or a required reporting failure. With `fail-on-severity: none`, findings
are report-only; scanner and required reporting failures still fail the job.

When the CLI returns a valid finalized result with partial coverage, the Action
warns and preserves the available findings and coverage explanations. It sets
`scan-status: incomplete`, `policy-status: not-evaluated`, and
`sarif-upload-ready: false`. Partial coverage alone does not fail the step, even
when `fail-on-severity` is configured or the CLI returns exit code `2`.

A successful Action step therefore does not always mean the security review is
complete. Workflows that require complete coverage can explicitly check the
`scan-status` output after the scan step (which must have `id: security`):

```yaml
- name: Require a complete security review
  env:
    SCAN_STATUS: ${{ steps.security.outputs.scan-status }}
  run: test "$SCAN_STATUS" = completed
```

Scanner failures, interruption, unknown coverage, invalid or missing required
reports, and a changed checkout still fail the step. A partial coverage file
left behind by a failed scan does not make that failure advisory. Required
artifact-upload and runtime-cleanup failures also remain failures.

SARIF is optional. If it cannot be produced, the Action warns and sets
`report-status: partial` and `sarif-upload-ready: false`. Summaries, annotations,
and JSON reports remain available, and the scan outcome is preserved. A requested
artifact upload that fails still fails the job.

### GitHub code scanning

Grant the job `security-events: write` and, for private repositories,
`actions: read`, alongside `contents: read`. Set `id: security` on the scan step,
then add this step after it:

```yaml
- name: Upload security findings
  if: ${{ always() && steps.security.outputs.sarif-upload-ready == 'true' }}
  uses: github/codeql-action/upload-sarif@b96794f015dfd88f77b49b1c93e0fa7110f94c63 # v4.38.0
  with:
    sarif_file: ${{ steps.security.outputs.sarif-path }}
    sha: ${{ steps.security.outputs.scanned-sha }}
    ref: ${{ steps.security.outputs.analysis-ref }}
    category: codex-security-repository
```

Complete scans remain uploadable when findings exceed the severity threshold.
Incomplete scans and dry runs are not uploadable.
Use a distinct category for each scan scope, such as repository and PR scans.
See [GitHub's SARIF upload requirements](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/integrate-with-existing-tools/upload-sarif-file)
for code scanning availability and permissions.

## Runtime

The Action installs a pinned CLI release from npm using a committed dependency
lock. It runs on Linux x64 with Node 24 and Python 3.11 or later; the Ubuntu 24.04
runner supplies these prerequisites. npm and Python are found on the runner's
`PATH`; `actions/setup-node` and `actions/setup-python` can select installations.
Authentication uses `OPENAI_API_KEY`.
Temporary runtime files are removed after the job; reports remain available to
downstream steps.

The Action uses the CLI’s validated JSON result for findings and scan status.
If the CLI exits without a usable result, the Action reports failure and leaves
report paths empty; it does not recover unvalidated partial files from disk.

## Troubleshooting

- **Checkout or history errors:** use the triggering revision, `fetch-depth: 0`
  for PRs, and `persist-credentials: false`.
- **Authentication errors:** check the repository secret and model access.
- **Missing SARIF uploads:** inspect `scan-status`, `report-status`, and
  `sarif-upload-ready`.
- **Incomplete scans:** inspect the warning and coverage report before adjusting
  scope or budget. A successful step with `scan-status: incomplete` has partial
  results, not a completed review or a passed severity policy.

CLI diagnostics stream by default. Set `verbose: 'false'` for lifecycle and
elapsed-time messages only.

## Development

From the repository root:

```bash
npm --prefix github-action ci --ignore-scripts --no-audit --no-fund
npm --prefix github-action run docs
npm --prefix github-action run build
npm --prefix github-action run validate
# Test the published CLI with synthetic scans; no model calls:
npm --prefix github-action/runtime ci --ignore-scripts --no-audit --no-fund
npm --prefix github-action run test:cli
# Linux x64 with Node 24; no model calls:
node github-action/scripts/linux-smoke.mjs
```

Commit source changes and the generated `dist/*.cjs` bundles together.
Validation checks types, tests, Action metadata, documentation, and bundle
reproducibility. CI also tests the result adapter against the pinned CLI and its
SARIF exporter using synthetic scans, runs the packaged Linux smoke test, and
audits the Action and CLI dependency locks. The `@openai/codex-security` dependency in
`runtime/package.json` is the CLI version source. To upgrade, update that exact
pin and regenerate `runtime/package-lock.json`, rebuild the bundles, and run
validation. Verify report compatibility when adopting a new release.

<!-- action-reference:start -->

## Inputs

Inputs are strings. Quote booleans and use newline-separated literal paths for lists.

| Input | Default | Meaning |
| --- | --- | --- |
| `repository` | `${{ github.workspace }}` | Checkout root. Use paths to select folders within the checkout. |
| `scope` | `repository` | repository or diff. Select diff for PR changes only; repository scans the full checkout. |
| `paths` | Unset | Newline-delimited literal repository-relative files or folders. Only for repository scope; no globs. |
| `diff-base` | Unset | Diff base revision. Defaults to the PR merge base; required outside PRs when scope is diff. |
| `mode` | `standard` | standard or deep. Deep supports repository scans, including selected paths; not diff scans. |
| `model` | `gpt-5.6-sol` | Model with access through your API key. Cost limits require CLI pricing support for the model. |
| `effort` | `xhigh` | Reasoning effort: minimal, low, medium, high, xhigh, or max (subject to model support). |
| `max-cost` | Unset | Positive estimated USD stop threshold per invocation. In-flight requests can exceed it; unset means no cost limit. |
| `max-time-hours` | Unset | Positive Deep discovery duration in hours, up to 96. Unset uses the CLI default. Finalization and job timeout are separate. |
| `fail-on-severity` | `none` | none, low, medium, high, or critical. Applies to complete scans. Valid partial results warn; scanner and required reporting errors fail. |
| `verbose` | `true` | Stream bounded, credential-redacted CLI diagnostics to the job log. Set false for lifecycle and elapsed-time messages only. |
| `dry-run` | `false` | Validate local configuration without a scan or API key. Does not verify authentication or model access. Use a separate non-required job. |
| `summary` | `true` | Write a human-readable job summary. |
| `annotations` | `true` | Emit up to 50 source finding annotations; complete findings remain in reports. |
| `upload-artifacts` | `false` | Upload an allowlist of validated reports. Reports may contain source and vulnerability details. |
| `artifact-name` | `codex-security` | Report artifact name; choose distinct names for matrix jobs and multiple invocations. |
| `retention-days` | `7` | Artifact retention, 1–90 days (subject to repository limits). |

## Outputs

All outputs are strings. An empty cost or count means unavailable, not zero.

| Output | Meaning |
| --- | --- |
| `sarif-path` | Absolute validated SARIF file path, or empty when unavailable or withheld. |
| `json-path` | Absolute canonical findings JSON path, or empty when unavailable or withheld. |
| `coverage-path` | Absolute coverage JSON path, or empty when unavailable or withheld. |
| `results-directory` | Runner-local reports directory; do not upload it recursively. |
| `scan-status` | completed, incomplete, failed, or skipped. Valid partial results are incomplete and warn without failing the step. Skipped is reserved for empty diffs or dry-run. |
| `skip-reason` | empty-diff or dry-run when no scan ran; otherwise empty. |
| `policy-status` | passed, failed, or not-evaluated. Incomplete scans are not-evaluated, even when a severity threshold is configured. |
| `report-status` | ready, partial, or failed. Missing optional SARIF yields partial without failing the scan; required reporting failures yield failed. |
| `exit-code` | CLI exit code, or empty if the CLI was not started. Valid partial results may return 2 without failing the Action step. |
| `scanned-sha` | Verified checkout commit SHA. |
| `analysis-ref` | GitHub ref matching the scanned revision. |
| `sarif-upload-ready` | true only for complete, validated reports with a publishable immutable revision. Remains true after severity-policy failure. |
| `critical-count` | Available critical findings, or empty before results are available. |
| `high-count` | Available high findings, or empty before results are available. |
| `medium-count` | Available medium findings, or empty before results are available. |
| `low-count` | Available low findings, or empty before results are available. |
| `informational-count` | Available informational findings, or empty before results are available. |
| `estimated-cost` | Estimated USD cost reported by the CLI. Empty means unavailable, not zero. |

<!-- action-reference:end -->
