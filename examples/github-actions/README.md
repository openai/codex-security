# GitHub Actions with Amazon Bedrock

Run Codex Security in a GitHub.com repository using short-lived AWS credentials.
The [workflow](codex-security.yml) scans pull-request changes, supports manual
full-repository scans, and uploads completed findings to GitHub Code Scanning
as SARIF. It does not install a GitHub App or post PR review comments.

The workflow stays in this example directory until you copy it into a repository's
`.github/workflows/` directory. It does not enable scanning in this repository.

## Setup

1. Configure GitHub's OIDC identity provider in AWS and create a role that can
   invoke your approved Bedrock model. Scope the role's permissions to the
   required model or inference profile and region, including streaming invocation
   when required. Follow the
   [AWS credentials action's OIDC setup](https://github.com/aws-actions/configure-aws-credentials#oidc-recommended)
   and [GitHub's AWS OIDC guidance](https://docs.github.com/en/actions/how-tos/secure-your-work/security-harden-deployments/oidc-in-aws).
2. Restrict the role trust policy to your repository. Without a GitHub environment,
   the default OIDC subjects differ by trigger:
   - PR scans: `repo:OWNER/REPOSITORY:pull_request`.
   - Manual and scheduled scans on `main`: `repo:OWNER/REPOSITORY:ref:refs/heads/main`.
     Replace `main` with your default branch. Authorize other branches only if you
     intend to run manual scans there. Require the `sts.amazonaws.com` audience.
3. Add repository Actions variables under **Settings → Secrets and variables →
   Actions → Variables**:

   | Variable           | Value                                                                  |
   | ------------------ | ---------------------------------------------------------------------- |
   | `AWS_ROLE_ARN`     | ARN of the role created above                                          |
   | `AWS_REGION`       | Region where that role can invoke the model                            |
   | `BEDROCK_MODEL_ID` | Exact model or inference-profile identifier approved for this workflow |

   No long-lived AWS access key or OpenAI API key is needed. Bedrock access and
   any required model approvals must already be in place.

4. Confirm GitHub Code Scanning is available for the repository. Private
   repositories need the appropriate GitHub Code Security entitlement. If you
   only want downloadable reports, remove the SARIF upload step and the
   `security-events: write` and `actions: read` permissions.
5. Copy `codex-security.yml` to
   `.github/workflows/codex-security.yml` in the repository you want to scan.
   Review its configuration and merge it into the default branch.
6. In **Actions → Codex Security (Amazon Bedrock) → Run workflow**, select the
   default branch and run a baseline scan. Inspect both the result and coverage
   before relying on the findings. Then open a same-repository test PR to verify
   the diff scan.

GitHub documents the supported repositories and upload permissions in
[Uploading a SARIF file](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/integrate-with-existing-tools/upload-sarif-file).

## Scan behavior

- **Pull requests:** scans GitHub's checked-out PR merge commit against the
  event's immutable base SHA. Full Git history is fetched, and checkout does not
  retain a GitHub credential. Superseded runs are cancelled. Draft, fork, and
  Dependabot-triggered PRs are skipped.
- **Manual runs:** scans the entire selected ref. The role's OIDC trust policy
  must allow that ref.
- **Scheduled runs:** uncomment the schedule after the baseline works to scan
  the default branch weekly. Scans consume Bedrock inference usage.
- **Reasoning:** uses standard mode with high reasoning effort. The explicit
  `model_reasoning_summary="none"` override supports Bedrock models that reject
  reasoning summaries; it does not reduce reasoning effort. Do not combine
  `--mode deep` with `--diff`.
- **Versions:** pins the published CLI to `0.1.27` and actions to commit SHAs.
  Review and test version updates before changing the pins. The Codex runtime is
  supplied by the CLI package; its version is separate from the wrapper version.
- **Duration:** the job and AWS role session are both limited to one hour.
  Adjust both, and the IAM role's maximum session duration, for longer scans.

See the [CLI documentation](../../sdk/typescript/README.md#scan-options-and-output)
for scan settings and the
[Bedrock configuration](../../sdk/typescript/README.md#authentication)
for provider details.

## Results and failure handling

The scan is report-only by default: findings alone do not fail the job. Set
`FAIL_ON_SEVERITY: "high"` to fail when a completed scan finds high or critical
issues. To enforce that result before merging, configure the corresponding
required check in your repository's rules.

| CLI exit code | Workflow result                                                                                           |
| ------------- | --------------------------------------------------------------------------------------------------------- |
| `0`           | Completed scan; export and upload SARIF                                                                   |
| `1`           | Completed scan with a configured severity-policy violation; upload SARIF and keep the job failed          |
| `2`           | Invalid input, incomplete coverage, or runtime error; keep the job failed and do not upload partial SARIF |
| Other nonzero | Keep the job failed; do not upload SARIF                                                                  |

The result JSON and any available report, coverage, findings, and SARIF files
are saved as a seven-day workflow artifact, even after a failed scan or SARIF
upload. Cancelled jobs may not save artifacts. The workflow does not upload the
entire scan directory, local authentication state, or raw agent transcripts.
Reports can still contain sensitive source snippets and vulnerability details;
review repository access and artifact retention accordingly.

Completed SARIF appears under **Security → Code scanning**. Full and diff scans
use separate analysis categories so a partial diff does not replace a full scan.
Use a completed full scan to reassess the full-repository baseline. During setup,
check alert locations, repeat-scan deduplication, and fixed-alert behavior in the
destination repository. Source-root fingerprints help GitHub identify repeated
findings; see [SARIF support](https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support).

## Trust boundary

This example is for trusted contributors on GitHub-hosted Linux runners. A
same-repository PR can modify workflow code and receives model-invocation
credentials when the scan runs. Skipping forks is not a substitute for reviewing
who can push branches. For a wider contributor set, use a protected GitHub
environment with required reviewers and update the OIDC subject to that
environment before enabling this workflow.

Do not change the trigger to `pull_request_target` to scan untrusted PR code with
credentials. Do not add dependency installation, builds, or other PR-controlled
commands to the scanner job. The workflow installs the CLI outside the checkout
before checkout and scopes AWS credential environment variables to the scan step.
It does not give the scanner a `GH_TOKEN` or `GITHUB_TOKEN`.

Only scan code you are authorized to submit to the configured inference provider.
If you supply additional scanner configuration, keep it maintainer-controlled;
do not load native Codex configuration from an untrusted PR.

## Troubleshooting

- **OIDC role assumption fails:** compare the run's trigger/ref with the role's
  allowed subject and audience. A protected environment changes the subject.
- **Bedrock denies the request:** verify model access, model ID, region, and IAM
  permissions. Do not paste credentials into workflow logs or issues.
- **The scan exits with `2`:** inspect the log, result JSON, and coverage report.
  Missing or partial coverage is not a clean security result.
- **SARIF upload fails:** check Code Security entitlement and job permissions.
  The report artifact remains available, but uploading it successfully is a
  separate setup check from completing a scan.
- **A PR run is skipped:** fork, Dependabot, and draft PRs are intentionally
  excluded. Review your trust model before enabling additional contributors.
