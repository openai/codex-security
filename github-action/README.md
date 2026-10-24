# Codex Security GitHub Action

Run Codex Security scans in GitHub Actions. Scan a repository or pull request,
check findings against a severity threshold, and export JSON, coverage, and
SARIF reports.

## Quick start

Use a GitHub-hosted Ubuntu 24.04 x64 runner on GitHub.com or GitHub Enterprise
Cloud on `*.ghe.com`, and an OpenAI API key
with access to the selected model. OpenAI is the default provider. See
[Inference providers](#inference-providers) for Bedrock, OpenRouter, and Fireworks.

Add your API key as a repository secret named `CODEX_SECURITY_API_KEY`, then
save this workflow in `.github/workflows/codex-security.yml`.
Replace `REPLACE_WITH_REVIEWED_COMMIT` with the full SHA of an Action commit.
The matching `action-vX.Y.Z` release lists the full distribution commit SHA
and links to the product changelog after the Action has passed release checks.
When using a fork, replace `openai` with the fork owner.

This example requests Daybreak Blue. Use an API key from a project with Blue
enabled; without Daybreak access, omit `cyber-access-program` or set it to
`standard`. See [Daybreak access and refusals](#daybreak-access-and-refusals).

```yaml
name: Codex Security repository
on:
  workflow_dispatch:
  schedule:
    - cron: "23 7 * * 1" # Mondays at 07:23 UTC

permissions:
  contents: read

jobs:
  security:
    runs-on: ubuntu-24.04
    steps:
      # Configure Bubblewrap and AppArmor so Codex Security can run safely in its sandbox.
      - name: Set up the Ubuntu sandbox
        run: |
          sudo apt-get update
          sudo apt-get install --yes bubblewrap apparmor-profiles
          sudo apparmor_parser -r /usr/share/apparmor/extra-profiles/bwrap-userns-restrict
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: openai/codex-security@REPLACE_WITH_REVIEWED_COMMIT
        with:
          model: gpt-5.6-sol
          effort: high
          cyber-access-program: daybreak_blue
        env:
          OPENAI_API_KEY: ${{ secrets.CODEX_SECURITY_API_KEY }}
```

The workflow runs weekly on Mondays at 07:23 UTC. To run it manually, use
**Actions → Codex Security repository → Run workflow**.
Findings are report-only by default. Set `fail-on-severity` to fail on reported
findings at or above a selected severity. Scanner and required reporting errors
also fail the job. Intentional exclusions and investigation notes do not.

### Ubuntu sandbox setup

Codex Security runs commands inside a sandbox to limit their filesystem and
network access. On the Ubuntu 24.04 runner used above, that sandbox uses
Bubblewrap (`bwrap`), and Ubuntu's AppArmor policy must allow it to create the
required isolated environment.

The setup step installs `bubblewrap` and `apparmor-profiles`, then uses
`apparmor_parser -r` to load the supplied `bwrap-userns-restrict` profile. The
profile permits Bubblewrap's sandbox setup while retaining Ubuntu's broader
AppArmor restrictions. Keep this step before the Action: the CLI checks that
its sandbox works before scanning and fails if it cannot start, for example
with `bwrap: loopback: Failed RTM_NEWADDR: Operation not permitted`.

This setup is specific to the Linux runner. Local macOS scans use the built-in
Seatbelt sandbox and do not need Bubblewrap. See the
[sandbox documentation](https://learn.chatgpt.com/docs/sandboxing) for details.

## Supported GitHub hosts and checkout URLs

The Action supports GitHub.com and GitHub Enterprise Cloud on `*.ghe.com`.
Checkout origins can use HTTPS, SCP-style SSH (`USER@HOST:OWNER/REPO.git`),
or an `ssh://` URL, including an explicit port 22. Repository names and hostnames
are compared without regard to case; a `.git` suffix and trailing slash are optional.

On GitHub.com, `ssh://git@ssh.github.com:443/OWNER/REPO.git` is also supported.
GitHub does not offer this SSH-over-443 endpoint for enterprises on `ghe.com`;
see [GitHub's SSH-over-HTTPS guidance](https://docs.github.com/en/authentication/troubleshooting-ssh/using-ssh-over-the-https-port).

### GitHub Enterprise Cloud

The workflows in this guide also support GitHub Enterprise Cloud with data
residency at `https://SUBDOMAIN.ghe.com`. The Action reads `GITHUB_SERVER_URL`
from the runner and requires the checkout origin to match that host and
`GITHUB_REPOSITORY`. No additional Action input or GitHub token is needed.
Use a reviewed Action commit containing this support.

Keep `persist-credentials: false` and use the triggering repository and revision.
HTTPS origins work with the checkout step above. For SSH origins, GitHub uses
the enterprise subdomain as the username, such as
`example-enterprise@example-enterprise.ghe.com:example/repo.git`.
See [GitHub's SSH guidance](https://docs.github.com/en/enterprise-cloud@latest/admin/data-residency/network-details-for-ghecom#using-ssh-with-ghecom).

Report artifacts use the runner's Actions artifact service. The separate
`github/codeql-action/upload-sarif` step uses the enterprise's code scanning
service and requires the permissions and availability described below.
Enterprise policies must permit the referenced actions. For Bedrock OIDC,
configure AWS trust for the enterprise issuer at
`https://token.actions.SUBDOMAIN.ghe.com`; see
[GitHub's feature differences](https://docs.github.com/en/enterprise-cloud@latest/admin/data-residency/feature-overview-for-github-enterprise-cloud-with-data-residency).

GitHub Enterprise Server remains unsupported. The Linux x64 runtime and
sandbox requirements apply on both supported GitHub Cloud hosts.

## Inference providers

`provider` and `model` map to `codex-security scan --provider` and `--model`.
The CLI configures the provider and validates its model requirements. The Action
uses the same provider names and forwards only the selected provider's credentials:

| `provider`         | Step environment                                       |
| ------------------ | ------------------------------------------------------ |
| `openai` (default) | `OPENAI_API_KEY`, or `CODEX_API_KEY` as a fallback     |
| `amazon-bedrock`   | AWS credentials and region; see the OIDC example below |
| `openrouter`       | `OPENROUTER_API_KEY`                                   |
| `fireworks`        | `FIREWORKS_API_KEY`                                    |

OpenAI retains the `gpt-5.6-sol` default. Other providers require an explicit
model ID your credentials can access. For example, replace the scan step in the
quick start with:

```yaml
- name: Scan with OpenRouter
  uses: openai/codex-security@REPLACE_WITH_REVIEWED_COMMIT
  with:
    provider: openrouter
    model: ${{ vars.INFERENCE_MODEL_ID }}
  env:
    OPENROUTER_API_KEY: ${{ secrets.OPENROUTER_API_KEY }}
```

Use `provider: fireworks` and `FIREWORKS_API_KEY` for Fireworks. These providers
require a reviewed Action revision containing the `provider` input;
`action-v0.3.0` supports OpenAI only. Installation and dry runs receive no provider
credentials. For CLI settings beyond the Action's named inputs, use the
[CLI workflow](../examples/github-actions/README.md).

## Scan with Amazon Bedrock

Set `provider: amazon-bedrock` and supply the exact Bedrock model ID your AWS
identity can invoke. No OpenAI API key or Codex login is needed.

This workflow uses GitHub OIDC to assume an AWS role and passes the temporary
credentials only to the scan step. Configure repository variables `AWS_REGION`,
`AWS_ROLE_ARN`, and `BEDROCK_MODEL_ID`. The role needs permission to invoke that
model, and its OIDC trust policy must restrict access to your repository and
approved branches or environments. See
[AWS credentials configuration](https://github.com/aws-actions/configure-aws-credentials#oidc-configuration-details)
for the role and identity-provider setup.

```yaml
name: Codex Security Bedrock
on:
  workflow_dispatch:

permissions:
  contents: read

jobs:
  security:
    runs-on: ubuntu-24.04
    timeout-minutes: 60
    permissions:
      contents: read
      id-token: write
    steps:
      - name: Set up the Ubuntu sandbox
        run: |
          sudo apt-get update
          sudo apt-get install --yes bubblewrap apparmor-profiles
          sudo apparmor_parser -r /usr/share/apparmor/extra-profiles/bwrap-userns-restrict
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - name: Assume the Bedrock role
        id: aws
        uses: aws-actions/configure-aws-credentials@cbe3b392738ccf3f987d68400dafcf4b0624a56c # v6.2.4
        with:
          aws-region: ${{ vars.AWS_REGION }}
          role-to-assume: ${{ vars.AWS_ROLE_ARN }}
          role-duration-seconds: 3600
          output-env-credentials: false
          output-credentials: true
      - name: Scan with Bedrock
        id: security
        uses: openai/codex-security@REPLACE_WITH_REVIEWED_COMMIT
        with:
          provider: amazon-bedrock
          model: ${{ vars.BEDROCK_MODEL_ID }}
          effort: high
        env:
          AWS_REGION: ${{ vars.AWS_REGION }}
          AWS_ACCESS_KEY_ID: ${{ steps.aws.outputs.aws-access-key-id }}
          AWS_SECRET_ACCESS_KEY: ${{ steps.aws.outputs.aws-secret-access-key }}
          AWS_SESSION_TOKEN: ${{ steps.aws.outputs.aws-session-token }}
```

Replace the Action placeholder with a reviewed commit that includes Bedrock
support. This example is report-only; the usual severity thresholds, summaries,
annotations, artifacts, and SARIF outputs also work with Bedrock.

Both `mode: standard` and `mode: deep` use the selected AWS credentials. Allow
enough time in the AWS role session and job timeout for the scan to finish;
the Action does not renew exported temporary credentials. For PR scans, apply
the same trusted-contributor restrictions as [Scan pull requests](#scan-pull-requests).

You can also supply `AWS_BEARER_TOKEN_BEDROCK` and a region directly to the step.
The Action forwards AWS region, profile, web-identity, and container-credential
settings used by the CLI. It keeps its private home directories, so profiles
must specify absolute `AWS_CONFIG_FILE` and `AWS_SHARED_CREDENTIALS_FILE` paths
instead of relying on the runner's `~/.aws` files. Installation and dry runs
receive no provider credentials; Bedrock scans receive no OpenAI API key.
See [Bedrock setup](../docs/bedrock.md) for model access and authentication, or
the [CLI workflow](../examples/github-actions/README.md) to run without the Action.

## Daybreak access and refusals

Daybreak is optional. You can use the Action with a general-purpose model your
credentials can access under standard safeguards. Some security tasks may trigger
model refusals or API cybersecurity safety blocks. **If a refusal or safety
block aborts the scan, the Action fails**, even with `fail-on-severity: none`.
That setting controls failures caused by findings; it does not suppress scanner
errors. Check the job summary and logs for the reason. A failed scan does not
mean the repository has no vulnerabilities.

For authorized security work that needs reduced refusals,
[request Daybreak access](https://openai.com/form/enterprise-trusted-access-for-cyber/).
After organization approval, enable the required program for the API project
and use a key from that project. Daybreak reduces some refusals but does not
remove every safeguard or guarantee that a scan will complete.

To explicitly select an approved Cyber access program, add
`cyber-access-program: daybreak_blue` to the scan step's `with` settings.
The input also accepts `standard` and `daybreak_red`; choose a program supported
by your model and API project. Leaving it unset preserves CLI defaults.
Selecting `standard` does not require Daybreak approval. Selecting a Daybreak
program does not grant access; an unavailable program or incompatible model
causes the scan to fail.

The API-project instructions above apply to `provider: openai`. For Bedrock,
use an approved model ID and AWS provisioning as described in
[Bedrock setup](../docs/bedrock.md#daybreak-blue-and-red).

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
      # Configure Bubblewrap and AppArmor so Codex Security can run safely in its sandbox.
      - name: Set up the Ubuntu sandbox
        run: |
          sudo apt-get update
          sudo apt-get install --yes bubblewrap apparmor-profiles
          sudo apparmor_parser -r /usr/share/apparmor/extra-profiles/bwrap-userns-restrict
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

This job fails on reported high or critical findings, or on scanner and required
reporting errors. File and line annotations are enabled by default.

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
  Names such as `src/[slug]/page.tsx` are literal paths; glob characters are not expanded.
  This requires repository scope.
- For diff scans outside PR events, set `diff-base`.
- Set `dry-run: 'true'` to check configuration without an API key or model calls.
  Use a separate setup job; dry-run does not assess code or verify model access.

For a Deep scan of a repository or selected paths, add these inputs to the scan step:

```yaml
with:
  mode: deep
  max-time-hours: "2"
```

Deep mode does not support diff scans. `max-time-hours` limits Deep discovery;
finalization can take additional time. It is unset by default, which uses the
CLI's default of 96 hours. Set an explicit budget for Deep scans that leaves
room for finalization within your job timeout.

## Reports

The Action writes a job summary and source annotations. Set
`upload-artifacts: 'true'` for downloadable reports, retained for seven days by
default. Reports can contain source code and vulnerability details.

The job summary includes the configured provider, reported input/cached/output
token usage, and estimated USD cost, including a range when supplied by the CLI.
Missing measurements or pricing appear as `unavailable`; measured zeros remain
zero. Cost estimates are not billing totals.

The Action uses the normal Actions job check. Its summary and final log message
distinguish findings above the failure threshold from a scan that could not
complete or a required reporting failure. With `fail-on-severity: none`, findings
are report-only; scanner and required reporting failures still fail the job.

A completed scan means the configured analysis produced a valid result. Scope
exclusions, deferred investigations, and other coverage notes remain in the
coverage report; they do not create a separate scan outcome or bypass the
findings policy. Completion does not certify that every vulnerability was found.

The Action follows the CLI outcome consistently:

| CLI exit                      | Action result                                                                  |
| ----------------------------- | ------------------------------------------------------------------------------ |
| `0`                           | `scan-status: completed`, `policy-status: passed`; the step succeeds.          |
| `1`                           | `scan-status: completed`, `policy-status: failed`; the step fails on findings. |
| `2` or an interrupted process | `scan-status: failed`, `policy-status: not-evaluated`; the step fails.         |

Usable reports retained after an execution failure remain available, but are not
eligible for SARIF upload. Invalid or missing required reports, a changed
checkout, and requested artifact-upload or runtime-cleanup failures also fail
the step. Empty diffs and dry runs use `scan-status: skipped`.

SARIF is optional. If it cannot be produced, the Action warns and sets
`report-status: partial` and `sarif-upload-ready: false`. Summaries, annotations,
and JSON reports remain available, and the scan outcome is preserved. This report
availability status does not describe scan coverage. A requested
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

Completed scans remain uploadable when findings exceed the severity threshold.
Failed or interrupted scans, empty diffs, and dry runs are not uploadable.
Use a distinct category for each scan scope, such as repository and PR scans.
The Action removes the CLI scan identifier from SARIF automation details so the
uploader can apply that category.
See [GitHub's SARIF upload requirements](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/integrate-with-existing-tools/upload-sarif-file)
for code scanning availability and permissions.

## Runtime

The Action installs a pinned CLI release from npm using a committed dependency
lock. It runs on Linux x64 with Node 24 and Python 3.11 or later; the Ubuntu 24.04
runner supplies Node and Python. The setup step above installs Bubblewrap and
loads Ubuntu's `bwrap-userns-restrict` AppArmor profile. This profile lets
Bubblewrap create the sandbox's user namespace and denies capabilities to its
child processes. It is loaded into the running kernel for the job's runner.
Codex uses the system Bubblewrap from `PATH`.

npm and Python are found on the runner's `PATH`; `actions/setup-node` and `actions/setup-python` can select installations.
Python helpers preserve the selected virtual environment and library settings.
The runner's process tracking marker is retained by the scan coordinator and Deep Scan workers.
OpenAI authentication uses `OPENAI_API_KEY`. With `provider: amazon-bedrock`,
only the selected AWS credential and region settings are forwarded to the scan.
Temporary runtime files are removed after the job; reports remain available to
downstream steps.

The Action uses the CLI’s validated JSON result for findings and scan status.
If the CLI exits without a usable result, the Action reports failure and leaves
report paths empty; it does not recover unvalidated files from disk.

### Request attribution

The Action adds `codex_security_integration=github_action` and
`codex_security_provider` (the configured provider family) through the CLI's existing
`responses_api_metadata` setting. These accompany the CLI's request attribution
on model requests supported by the provider. This attribution contains no
repository, workflow, run, actor, credential, or finding data.
Native managed configuration may override the provider selection before inference.

The Action continues to set `analytics.enabled=false`. Request metadata is
separate from native analytics and does not create an additional telemetry
request or publish scan results to Codex Security Cloud. Requests sent to other
providers do not establish OpenAI-side usage reporting. Summaries, annotations,
and artifact uploads retain their existing controls.

## Troubleshooting

- **Checkout or history errors:** use the triggering revision, `fetch-depth: 0`
  for PRs, and `persist-credentials: false`.
- **Authentication errors:** for OpenAI, check the repository secret and model access.
  For Bedrock, check the AWS identity, session expiry, region, and permission to
  invoke the exact model ID.
- **Sandbox startup errors:** on Ubuntu 24.04, include the sandbox setup step
  shown above. Installing Bubblewrap alone does not load the AppArmor profile.
  A `bwrap: loopback: Failed RTM_NEWADDR: Operation not permitted` error means
  the sandbox could not configure its network namespace. Check that the profile
  loaded successfully before running the Action.
- **Missing SARIF uploads:** inspect `scan-status`, `report-status`, and
  `sarif-upload-ready`.
- **Failed scans:** inspect the CLI diagnostics for execution errors. Scope
  exclusions and deferred investigations in the coverage report do not cause
  execution failures or bypass the severity policy.

CLI diagnostics stream by default. Set `verbose: 'false'` for lifecycle and
elapsed-time messages only.

## Development

From the repository root:

```bash
npm --prefix github-action ci --ignore-scripts --no-audit --no-fund
npm --prefix github-action run docs
npm --prefix github-action run build
npm --prefix github-action run validate
# Test the published CLI with synthetic scans and a local request fixture:
npm --prefix github-action/runtime ci --ignore-scripts --no-audit --no-fund
npm --prefix github-action run test:cli
# Linux x64 with Node 24; no model calls:
node github-action/scripts/linux-smoke.mjs
```

Commit source changes and the generated `dist/*.cjs` bundles together.
Validation checks types, tests, Action metadata, documentation, and bundle
reproducibility. CI also tests the result adapter against the pinned CLI and its
SARIF exporter using synthetic scans. A local inference fixture checks request
attribution and the analytics opt-out with synthetic credentials; it makes no
external model calls. CI also runs the packaged Linux smoke test and audits the
Action and CLI dependency locks. The `@openai/codex-security` dependency in
`runtime/package.json` is the installed CLI version source. Main keeps an already
published CLI baseline so its checks remain runnable while a release PR prepares
the next product version. This development pin does not necessarily track the
latest CLI release. To upgrade it, update it and regenerate
`runtime/package-lock.json`, rebuild the bundles, and run validation.

The `action-vX.Y.Z` release uses the same version as the corresponding
`npm-vX.Y.Z` CLI release. Its distribution commit includes the built bundles and
final runtime lock and differs from the CLI source commit. Pin the full Action
distribution SHA listed in the Action release, which also includes its manifest,
SBOM, and a link to the product changelog. See [the release process](../RELEASING.md)
for publication, verification, and recovery instructions.

<!-- prettier-ignore-start -->

<!-- action-reference:start -->

## Inputs

Inputs are strings. Quote booleans and use newline-separated literal paths for lists.

| Input                  | Default                   | Meaning                                                                                                                                                                                                                      |
| ---------------------- | ------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `repository`           | `${{ github.workspace }}` | Checkout root. Use paths to select folders within the checkout.                                                                                                                                                              |
| `scope`                | `repository`              | repository or diff. Select diff for PR changes only; repository scans the full checkout.                                                                                                                                     |
| `paths`                | Unset                     | Newline-delimited literal repository-relative files or folders. Only for repository scope; no glob expansion.                                                                                                                |
| `diff-base`            | Unset                     | Diff base revision. Defaults to the PR merge base; required outside PRs when scope is diff.                                                                                                                                  |
| `mode`                 | `standard`                | standard or deep. Deep supports repository scans, including selected paths; not diff scans.                                                                                                                                  |
| `provider`             | `openai`                  | Inference provider, matching scan --provider: openai, openrouter, fireworks, or amazon-bedrock. Supply the selected provider's credentials to the step.                                                                      |
| `model`                | Unset                     | Model to scan with, passed to scan --model. Defaults to gpt-5.6-sol for OpenAI; other providers require an explicit model ID. Cost limits require CLI pricing support for the model.                                         |
| `cyber-access-program` | Unset                     | Optional Cyber access program: standard, daybreak_blue, or daybreak_red. Unset preserves CLI defaults. Daybreak selections require approved organization and enabled API project access; model access is checked separately. |
| `effort`               | `xhigh`                   | Reasoning effort passed to Codex; supported values depend on the model and provider.                                                                                                                                         |
| `max-cost`             | Unset                     | Positive estimated USD stop threshold per invocation. In-flight requests can exceed it; unset means no cost limit.                                                                                                           |
| `max-time-hours`       | Unset                     | Positive Deep discovery duration in hours, up to 96. Unset uses the CLI default. Finalization and job timeout are separate.                                                                                                  |
| `fail-on-severity`     | `none`                    | none, low, medium, high, or critical. Fails on reported findings at or above the selected severity. Scanner and required reporting errors also fail.                                                                         |
| `verbose`              | `true`                    | Stream CLI diagnostics to the job log. Set false for lifecycle and elapsed-time messages only.                                                                                                                               |
| `dry-run`              | `false`                   | Validate local configuration without a scan or API key. Does not verify authentication or model access. Use a separate non-required job.                                                                                     |
| `summary`              | `true`                    | Write a human-readable job summary.                                                                                                                                                                                          |
| `annotations`          | `true`                    | Emit up to 50 source finding annotations; complete findings remain in reports.                                                                                                                                               |
| `upload-artifacts`     | `false`                   | Upload an allowlist of validated reports. Reports may contain source and vulnerability details.                                                                                                                              |
| `artifact-name`        | `codex-security`          | Report artifact name; choose distinct names for matrix jobs and multiple invocations.                                                                                                                                        |
| `retention-days`       | `7`                       | Artifact retention, 1–90 days (subject to repository limits).                                                                                                                                                                |

## Outputs

All outputs are strings. An empty cost or count means unavailable, not zero.

| Output                | Meaning                                                                                                                                |
| --------------------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| `sarif-path`          | Absolute validated SARIF file path, or empty when unavailable or withheld.                                                             |
| `json-path`           | Absolute canonical findings JSON path, or empty when unavailable or withheld.                                                          |
| `coverage-path`       | Absolute coverage JSON path, or empty when unavailable or withheld.                                                                    |
| `results-directory`   | Runner-local reports directory; do not upload it recursively.                                                                          |
| `scan-status`         | completed, failed, or skipped. Completed means analysis produced a valid result. Skipped is reserved for empty diffs or dry-run.       |
| `skip-reason`         | empty-diff or dry-run when no scan ran; otherwise empty.                                                                               |
| `policy-status`       | passed, failed, or not-evaluated. Failed or skipped scans are not-evaluated.                                                           |
| `report-status`       | ready, partial, or failed. Missing optional SARIF yields partial without failing the scan; required reporting failures yield failed.   |
| `exit-code`           | CLI exit code, or empty if the CLI was not started. 0 means success, 1 means findings policy failed, and 2 means execution failed.     |
| `scanned-sha`         | Verified checkout commit SHA.                                                                                                          |
| `analysis-ref`        | GitHub ref matching the scanned revision.                                                                                              |
| `sarif-upload-ready`  | true only for validated SARIF from a completed scan with a publishable immutable revision. Remains true after severity-policy failure. |
| `critical-count`      | Available critical findings, or empty before results are available.                                                                    |
| `high-count`          | Available high findings, or empty before results are available.                                                                        |
| `medium-count`        | Available medium findings, or empty before results are available.                                                                      |
| `low-count`           | Available low findings, or empty before results are available.                                                                         |
| `informational-count` | Available informational findings, or empty before results are available.                                                               |
| `estimated-cost`      | Estimated USD cost reported by the CLI. Empty means unavailable, not zero.                                                             |

<!-- action-reference:end -->

<!-- prettier-ignore-end -->
