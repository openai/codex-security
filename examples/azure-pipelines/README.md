# Azure Pipelines with Amazon Bedrock

This example runs Codex Security from a centrally owned Azure Pipelines YAML
file against a configured Azure Repos Git repository. It supports manual full
and committed-diff scans, short-lived AWS credentials through OIDC, report
artifacts, and optional SARIF publishing to the target repository's Advanced
Security view. No Codex Security runtime changes or custom extension are needed.

It targets Azure DevOps Services and Microsoft-hosted Linux agents. It does not
enroll repositories, create branch policies, or automatically validate PRs.
Use a trusted tooling repository for the pipeline definition; the target
repository does not need its own pipeline file.

## Setup

1. Copy [`azure-pipelines.yml`](azure-pipelines.yml) into the tooling repository.
   Set `resources.repositories.target.name` to the approved `Project/Repository`
   and adjust the default `targetRef`. Keep the repository name fixed in reviewed
   YAML instead of accepting arbitrary scan targets at queue time.
2. Install the current [AWS Toolkit for Azure DevOps](https://github.com/aws/aws-toolkit-azure-devops/releases)
   extension in your organization. Create an AWS service connection named
   `codex-security-bedrock` with **Use OIDC** and an AWS role ARN; leave access
   keys unset. Follow the [AWS OIDC setup guide](https://aws.amazon.com/blogs/modernizing-with-aws/how-to-federate-into-aws-from-azure-devops-using-openid-connect/).
   Restrict the role trust to the service connection's actual issuer, audience,
   and subject. Authorize only this pipeline to use the connection.
3. Set `awsRegion` and `bedrockModelId` to an available, approved Bedrock model or
   inference profile. Grant the role only the required Bedrock invocation
   permissions for those resources. The requested AWS session is one hour,
   matching the job timeout; configure the role to allow that duration.
4. Create a pipeline pointing at the copied YAML. Grant its project build
   service identity read access to the target repository and authorize the
   repository resource. Cross-project checkout needs explicit access in the
   target project; do not disable project-scoped job authorization to work around
   a missing grant. See [multi-repository checkout permissions](https://learn.microsoft.com/en-us/azure/devops/pipelines/repos/multi-repo-checkout?view=azure-devops).
5. Keep `publishToAdvancedSecurity: false` for artifact-only runs. To enable the
   native findings view, enable the required GitHub Code Security / Advanced
   Security entitlement on the **target** repository and grant the pipeline
   identity permission to publish its results. Then opt in when queuing a run.
   See [third-party SARIF publishing](https://learn.microsoft.com/en-us/azure/devops/repos/security/github-advanced-security-code-scanning-third-party?view=azure-devops).

The YAML pins the CLI, Node, and Python versions and uses current task majors.
Azure Pipelines resolves compatible task updates within those majors. Review
the pinned versions when adopting or upgrading the example.

## Run a scan

Choose **Run pipeline** from the trusted tooling branch, then set:

| Parameter                   | Meaning                                                                                                                |
| --------------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| `targetRef`                 | Target branch or tag, defaulting to `refs/heads/main`.                                                                 |
| `scanMode`                  | `full` for a baseline, or `diff` for changes relative to a base revision.                                              |
| `baseRevision`              | Used only for `diff`; defaults to `HEAD^` (the preceding commit). Prefer an exact base commit SHA for reproducibility. |
| `failOnSeverity`            | `none` is report-only; select a severity to fail on findings at or above it.                                           |
| `publishToAdvancedSecurity` | Opt in to native SARIF publishing after completing its setup.                                                          |

Start with a full scan. For a later committed-diff scan, select the target branch
and a base revision present in that repository's history. The checkout fetches
full history; Codex Security resolves the diff against the checked-out commit.
This scans committed changes, not an automatically discovered PR.

The optional publisher uses the `target` repository resource metadata, not the
tooling repository's build metadata. Keep its alias and
`advancedsecurity.publish.repository` in sync when adapting the YAML. This is
Microsoft's [explicit multi-repository publishing mechanism](https://learn.microsoft.com/en-us/azure/devops/release-notes/2025/sprint-253-update#multi-repository-publishing-scenarios-supported-for-github-advanced-security-for-azure-devops).
Full and diff results use separate categories so a partial diff does not replace
the full-scan baseline. A diff result is still a snapshot of that diff, not a
complete repository inventory; use full scans to track the baseline over time.

## Results and failures

The `codex-security` pipeline artifact contains `result.json`, available
`report.md`, `coverage.json`, and `findings.json`, plus `results.sarif` after a
successful export. Check the JSON/report for findings, coverage, runtime, and
usage; missing or incomplete coverage is not a clean scan.

| Scan exit     | Pipeline behavior                                                                              |
| ------------- | ---------------------------------------------------------------------------------------------- |
| `0`           | Completed scan; export SARIF and retain reports.                                               |
| `1`           | Severity policy failed; still export SARIF and retain reports, but keep the job failed.        |
| Other nonzero | Scan failed or was incomplete; retain available reports without exporting or publishing SARIF. |

An export or publishing failure also fails the job. Cancellation skips the
post-scan steps, so artifacts are not guaranteed for canceled runs. Native
publishing waits for processing; verify the target repository and commit in the
first live run. Local validation cannot prove your organization's OIDC trust,
permissions, model access, or SARIF ingestion.

## Trust and rollout boundaries

- Restrict who can edit or queue this privileged pipeline and use its AWS service
  connection. Treat scanned code and model output as untrusted. OIDC avoids
  long-lived keys; it does not make running untrusted code with credentials safe.
- The CLI is installed before target checkout, outside the repository, with npm
  lifecycle scripts disabled. Checkout does not persist its credential. The AWS
  task supplies temporary credentials only to the scan step; no PAT or Azure
  access token is explicitly passed to the CLI.
- Reports can contain source excerpts and vulnerability details. Restrict artifact
  access and configure your project's pipeline-run retention policy. The example
  retains selected reports, not raw scan state, transcripts, or authentication
  files.
- For automatic Azure Repos PR checks, configure a target-branch **build validation
  policy** and a PR-aware checkout/pipeline design. YAML `pr:` triggers do not
  enable Azure Repos PR validation. Attaching this manual pipeline unchanged to
  a policy would still scan its configured target ref, not necessarily the PR.
  See [Azure Repos PR triggers](https://learn.microsoft.com/en-us/azure/devops/pipelines/repos/azure-repos-git?view=azure-devops#pr-triggers).
