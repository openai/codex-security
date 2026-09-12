# GitHub Actions with Amazon Bedrock

The [workflow](codex-security.yml) scans PR changes or, on manual and scheduled
runs, the full repository. It uses short-lived AWS credentials and uploads
completed findings to GitHub Code Scanning as SARIF. It does not install a GitHub
App or post PR comments.

## Setup

1. Configure [GitHub OIDC in AWS](https://github.com/aws-actions/configure-aws-credentials#oidc-recommended)
   and create a role that can invoke your approved Bedrock model or inference
   profile, including streaming invocation when required. Restrict its trust
   policy to your repository and the `sts.amazonaws.com` audience. Without a
   GitHub environment, the subjects are:
   - PRs: `repo:OWNER/REPOSITORY:pull_request`.
   - Manual and scheduled runs on `main`: `repo:OWNER/REPOSITORY:ref:refs/heads/main`.
     Replace `main` with your default branch; allow other branches only if you
     intend to run manual scans there.
2. Add these repository variables under **Settings → Secrets and variables →
   Actions → Variables**:

   | Variable           | Value                                          |
   | ------------------ | ---------------------------------------------- |
   | `AWS_ROLE_ARN`     | ARN of the role created above                  |
   | `AWS_REGION`       | Region where the role can invoke the model     |
   | `BEDROCK_MODEL_ID` | Approved model or inference-profile identifier |

   Bedrock model access must already be enabled. No long-lived AWS access key or
   OpenAI API key is needed.

3. Confirm [GitHub Code Scanning and SARIF upload](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/integrate-with-existing-tools/upload-sarif-file)
   are available. Private repositories need the appropriate GitHub Code Security
   entitlement. For downloadable reports only, remove the SARIF upload step and
   the `security-events: write` and `actions: read` permissions.
4. Copy `codex-security.yml` into the target repository's `.github/workflows/`
   directory, review it, and merge it into the default branch. This example does
   not enable scanning until copied.
5. In **Actions → Codex Security (Amazon Bedrock) → Run workflow**, run a baseline
   on the default branch, then open a same-repository test PR. Check coverage,
   alert locations, deduplication, and fixed-alert behavior in the destination
   repository before relying on the integration.

## Configuration

PR scans compare GitHub's default PR merge checkout against the event's immutable
base SHA. Draft, fork, and Dependabot-triggered PRs are skipped; newer runs cancel
older ones. Uncomment the schedule for weekly full scans after setup works.
Scans consume Bedrock inference usage.

The workflow uses standard mode with high reasoning effort. See
[scan options](../../sdk/typescript/README.md#scan-options-and-output) and
[Bedrock configuration](../../sdk/typescript/README.md#authentication) for details.

Actions are pinned to commit SHAs, and CLI and runtime versions are pinned in the
workflow. Node.js uses the active LTS line.
Review and test updates before changing pins. The job and AWS session each last
at most one hour; for longer scans, adjust both and the IAM role's session limit.

## Results

Findings are report-only by default. Set `FAIL_ON_SEVERITY: "high"` to fail on
high or critical findings, then make the check required in your repository rules
if it should block merging.

| CLI exit code | Workflow result                                                         |
| ------------- | ----------------------------------------------------------------------- |
| `0`           | Completed scan; export and upload SARIF                                 |
| `1`           | Severity-policy violation; upload SARIF and keep the job failed         |
| Other nonzero | Failed or incomplete scan; fail the job without uploading partial SARIF |

For exit `2`, inspect the logs, result JSON, and coverage report: missing coverage
is not a clean security result. Full and diff scans use separate SARIF categories
so a diff does not replace the full-repository baseline.

Reports are saved as seven-day artifacts even after a scan or SARIF upload fails
(cancelled jobs may not save them). Only result JSON, report, coverage, findings,
and SARIF files are uploaded—not authentication state or raw agent transcripts.
Reports can contain sensitive source snippets and vulnerability details; review
repository access and retention accordingly.

## Trust boundary

Use this example only for trusted contributors on GitHub-hosted Linux runners.
A same-repository PR can change workflow code and receives model-invocation
credentials. Skipping forks does not protect against someone who can push a
branch. For a wider contributor set, require reviewers through a protected
GitHub environment and [update the OIDC subject](https://docs.github.com/en/actions/how-tos/secure-your-work/security-harden-deployments/oidc-in-aws).

Do not use `pull_request_target` to scan untrusted PR code with credentials, or
add PR-controlled dependency installs, builds, or commands to this job. The CLI
is installed outside the checkout before checkout; AWS credentials are scoped
to the scan step, and no `GH_TOKEN` or `GITHUB_TOKEN` is passed to the scanner.
Keep any additional scanner configuration maintainer-controlled. Only scan code
you are authorized to submit to the configured inference provider.
