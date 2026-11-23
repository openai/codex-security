# Validation providers

AWS Continuum can assess code findings after a Codex scan finishes. The host
sends findings to AWS and reads the resulting verdicts and issue scores.
The sealed source report, Codex severity and `--fail-on-severity` stay unchanged.
Provider work falls outside Codex cost accounting. Scan cost limits and
`scan --validate` cannot be combined.

## Choose the destination

Install AWS CLI v2.38.5 or later outside the checkout. Configure credentials
and a Region. Run from a Git repository root. The Continuum environment must
have exactly one Git source, matching a remote of the checkout, and no S3
sources. Codex checks the repository before submitting. It cannot establish
that the deployed revision matches the scanned source.

Select a trusted [project file](project-configuration.md#validation-provider-settings)
explicitly. Check the AWS account, environment and Region before starting.

```yaml
scan:
  validation:
    provider: continuum
    continuum:
      environment_id: YOUR_ENVIRONMENT_ID
      aws_region: us-east-1
```

AWS receives the repository, finding identifiers, titles, summaries, severities,
CWEs when available, and paths and line ranges. These fields may contain
sensitive information. Posture questions and other deferred work are excluded.

## Start a scan

```sh
codex-security scan . --validate -c codex-security.yaml
```

Bare `--validate` uses the selected provider or the existing Codex validator
if none is configured. `--validate=NAME` selects a validation provider.
`--provider` selects the inference provider. SDK callers can use
[`validate()`](../sdk/typescript/docs/sdk.md#use-a-validation-provider).

For automatic submission from the plugin, install the packaged plugin or
build it from the full checkout with SDK dependencies installed. Select the
file in scan setup or explicitly request it.

> Scan this repository for security issues using codex-security.yaml.

Review the destination in setup. The plugin saves the selection before the
scan and submits the findings automatically after sealing. Rejoining keeps
the saved settings. A standalone plugin source build has no AWS provider.

## Read the results

Scan completion writes `validation.md` and `validation.json` beside the scan
report. Treat them as sensitive. Read the detailed records in `items` for
the exact identity, evidence, timestamps and disposition of each finding.

| Question                                  | What to check                                                                                                                                                                                     |
| ----------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Did AWS accept the finding?               | `itemId` is the local ID. `findingId`, `findingArn` and `submittedAt` identify the acceptance even if polling failed.                                                                             |
| Whose verdict is this?                    | Check `resultScope` with `verdict`. A unique explicit result for the AWS finding gives scope `finding`. Otherwise the verdict can describe the whole `issue`, even if `issueFindingCount` is one. |
| Did the run finish?                       | Read `terminalStatus`, `disposition`, `unavailable` and `statusMessage`. A partial, uncertain or failed run is deferred. A discarded or declined submission is `not_applicable`.                  |
| Does the result establish the exact flaw? | Codex has not independently reproduced the claim. `claimMatch` stays `unknown` and `severityAfter` equals `severityBefore`.                                                                       |
| What did AWS say about the issue?         | `issueVerdict` can differ from a finding verdict. `providerSeverity` is the issue severity. `reachableFromAttacker` describes the issue. An absent value means unknown.                           |
| How old is the evidence?                  | See `validationArtifactId`, `scoringArtifactId` and `freshness`. `joinedValidatedIssue` indicates pre-existing issue validation. A recent timestamp does not establish the deployed revision.     |

Codex checks issue membership and reads validation runs newest first.
When applicable runs share the newest timestamp, Codex defers the verdict.
Retry after a newer run appears. While a finding is being submitted or
validated, older issue evidence alone does not end polling.
It skips bundles explicitly for other findings when looking for a member
result. A newer failed or partial run for the issue takes precedence over
an older conclusive member result. A reason labelled `FINDING` comes from
submitted context. `GRAPH`, `CODE` and `INFERRED` distinguish deployment
evidence, source evidence and inference.
Issue reachability requires a single score linked to the selected validation
artifact and issue verdict. Missing or ambiguous scoring stays unknown.

## Resume without starting a new scan

Under `continuum-submissions` in private host state, Codex stores each request
and its token until AWS acknowledges it, then replaces the request body with
a receipt. Retries reuse the token or poll the accepted finding. Keep the
same host state, destination and submitted content. A change to any of these
can create a new AWS finding.

Ask the plugin to repeat completion for the same scan ID to resume an
incomplete batch. It can poll finished items again using their receipts.

A finding still marked `SUBMITTED` may be waiting for a build. For `FAILED`,
open `issueUrl` and check the run or ask AWS privately for worker logs.
Polling cannot restart a failed worker. Keep raw artifacts and logs private.

## AWS permissions

The host uses the AWS credential chain. Keep profiles and custom AWS models
outside the checkout. Allow `GetEnvironment`, `GetIntegration`,
`CreateCodeFinding`, `GetCodeFinding`, `GetCodeIssue`,
`ListCodeIssueArtifacts` and `GetCodeIssueArtifact`. See
[AWS Continuum permissions](https://docs.aws.amazon.com/service-authorization/latest/reference/list_continuum.html)
and the [import guide](scanner-imports/continuum.md).
