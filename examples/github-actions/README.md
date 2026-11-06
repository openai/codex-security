# GitHub Actions with Amazon Bedrock

The [workflow](codex-security.yml) runs the CLI directly with Amazon Bedrock.
It assumes an AWS role through GitHub OIDC, scans PR changes or a full
repository, and uploads completed findings to GitHub Code Scanning. Choose the
[Codex Security GitHub Action](../../github-action/README.md#scan-with-amazon-bedrock)
if you prefer a scan step with managed CLI installation and sandbox setup.

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
4. Check that the Ubuntu runner can start Bubblewrap. If its AppArmor policy
   restricts user namespaces, follow the [sandbox setup](../../docs/bedrock.md#check-the-sandbox-on-an-ubuntu-ci-runner)
   before checkout and AWS authentication.
5. Copy `codex-security.yml` into the target repository's `.github/workflows/`
   directory, review it, and merge it into the default branch. This example does
   not enable scanning until copied.
6. In **Actions → Codex Security (Amazon Bedrock) → Run workflow**, run a baseline
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
[Bedrock configuration](../../docs/bedrock.md#select-aws-credentials-and-a-model) for details.

To upgrade, change `CODEX_SECURITY_VERSION` to a reviewed CLI release and keep
the action dependencies pinned to full commit SHAs. Repeat the sandbox check,
manual baseline, and test PR on the workflow’s runner. Verify that the diff
uses the PR base and that the resulting SARIF appears under the expected
category. For scans longer than an hour, adjust the job timeout, requested AWS
session duration, and IAM role session limit together.

## Results

Findings are report-only by default. Set `FAIL_ON_SEVERITY: "high"` to fail on
high or critical findings, then make the check required in your repository rules
if it should block merging.

| CLI exit code | Workflow result                                                           |
| ------------- | ------------------------------------------------------------------------- |
| `0`           | Completed scan; export and upload SARIF                                   |
| `1`           | Severity-policy violation; upload SARIF and keep the job failed           |
| Other nonzero | Execution failed or was interrupted; fail the job without uploading SARIF |

For exit `2`, inspect the logs and result JSON for the execution error. Scope
exclusions and deferred investigations do not fail the scan or bypass the
findings policy. Full and diff scans use separate SARIF categories so a diff
does not replace the full-repository baseline.

Reports are saved as seven-day artifacts even after a scan or SARIF upload fails
(cancelled jobs may not save them). Only result JSON, report, coverage, findings,
and SARIF files are uploaded.
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

## OpenAI inference on a sample application

For an OpenAI API-key example with a protected environment, follow the
[Invoice Desk CI guide](../invoice-desk/README.md#ci-and-openai-scans).
