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
By default the local validation method and summary stay on the host. Setting
`include_local_validation: true` under `continuum` sends both in full, including
any secrets in them. Oversized findings fail individually.

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
the saved settings. If the scan opted into sending local validation text and
you explicitly select a file on rejoin, the file must still opt in for the
same provider, environment, Region and profile. A conflict or unreadable file
disables automatic submission for this scan, including later completion by
the original caller. A batch already uploading may finish. Finish
locally and use `validate --scan` to submit the findings you review. Omit
the file on rejoin to retain the original grant when recovering a scan.
A standalone plugin source build has no AWS provider.

## Review a saved scan before sending

Run the scan without provider validation first. From the original checkout,
find the scan, inspect its occurrence IDs, then review the full sealed
findings. Keep the export private.

```sh
codex-security scans list --json
codex-security scans show SCAN_ID --json
codex-security export --scan SCAN_ID --export-format json --output -
codex-security validate --scan SCAN_ID -c codex-security.yaml OCCURRENCE_ID --format json
```

Pass multiple IDs separated by spaces. **Omitting IDs selects all open
findings.** `--scan latest` selects the latest completed scan for this
directory. Use an explicit scan ID for retries. New submissions require
the registered scan and the original source snapshot. A receipt allows
polling an accepted finding after the checkout changes.

The command returns `schemaVersion`, `scanId`, `status` and `items` in JSON.
Check `status` even on exit code 0. An inconclusive verdict can be incomplete
without a transport error. Exit code 1 can indicate a failure for just one
finding. Check its `findingId` before assuming the upload failed.

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

Issue scoring can lag validation. Codex looks for the newest unambiguous
score tied to the same issue, validation artifact and issue verdict. If
scoring is still pending at the deadline, `scoringPending` is true. The
verdict remains visible and the assessment is incomplete. Retry to refresh
the score.

## Resume without starting a new scan

Under `continuum-submissions` in private host state, Codex stores each request
and its token until AWS acknowledges it, then replaces the request body with
a receipt. Retries reuse the token or poll the accepted finding. Keep the
same host state, destination and submitted content. A change to any of these
can create a new AWS finding.

Ask the plugin to show the completed scan by ID. This reads the saved
result without contacting AWS. Check `validation.retryable` before
requesting another attempt.

> Resume supplemental validation for scan SCAN_ID. Show which findings are
> still waiting and which have finished.

Completion retries pending items and keeps finished assessments. If
`status` is `incomplete` and `retryable` is false, check the individual
run statuses before deciding how to proceed.

For a CLI retry, repeat `validate --scan` with the same ID, project file
and affected occurrence IDs.

A finding still marked `SUBMITTED` may be waiting for a build. For `FAILED`,
open `issueUrl` and check the run or ask AWS privately for worker logs.
Polling cannot restart a failed worker. Keep raw artifacts and logs private.

## Patch and verify a saved occurrence

On the same host, CLI patch and verify-fix and workbench Generate and Verify
can read a saved conclusion without contacting AWS. The workbench keeps its
original submission binding when the CLI validates a subset. For CLI-only
scans, the most recently started validation with an accepted submission
for a single destination takes precedence, even if an earlier request
finishes later. Conflicting destinations or ambiguous evidence can leave
an occurrence without supplemental context.

If two linked scores share a timestamp, `scoringPending` and
`freshness.scoredAt` identify the conflict. Patch and verify keep the
verdict and withhold issue severity and reachability until a newer score
resolves the conflict.

The model receives a limited set of status and scope fields from protected
host state. The live issue member count stays in the reports. A change in
that count alone does not invalidate a saved verdict. AWS identifiers,
provider free text and proof stay out of the remediation context.
The original finding and its remediation tests remain
the criteria for the fix. Apply uses the recorded patch unchanged.

After an upgrade, an `outdated` result needs an explicit refresh. Repeat
plugin completion or rerun the saved CLI command on the original host.
Older results can identify the accepted submission but cannot supply a
remediation conclusion. Preserve the original state directory when moving
between installations. If a failed refresh reports `admissionConflict`,
remediation skips the occurrence. Restore provider access and repeat plugin
completion to establish the submission identity.

An `issueUnlinked` result means AWS returned the finding with no current
issue. Earlier verdicts for that issue cannot supply remediation evidence.
If CLI and plugin results disagree on the current link, refresh the entry
point reporting no link before using the assessment for remediation.

## Inspect AWS evidence and patches

Import is optional. Use the same AWS profile and Region and the
`findingId` returned by validation.

```sh
codex-security import continuum ENVIRONMENT_ID --finding-id FINDING_ID --source-root CHECKOUT --format json
```

A bulk import stores one record per AWS issue. To match contributors, set
`issue_arn` to its ARN, `import_json` to the output of
`publish findings --to local --format json`, and `assessment` to the scan's
`validation.json` or saved validation output.

```sh
jq -r --arg issue "$issue_arn" --slurpfile validation "$assessment" '
  .findings[] | select(.sourceFindingId == $issue)
  | (.evidence.source_data.findings[]?.findingArn // empty) as $arn
  | $validation[0].items[] | select(.findingArn == $arn)
  | [.findingArn, .itemId] | @tsv
' "$import_json"
```

## AWS permissions

The host uses the AWS credential chain. Keep profiles and custom AWS models
outside the checkout. Allow `GetEnvironment`, `GetIntegration`,
`CreateCodeFinding`, `GetCodeFinding`, `GetCodeIssue`,
`ListCodeIssueArtifacts` and `GetCodeIssueArtifact`. See
[AWS Continuum permissions](https://docs.aws.amazon.com/service-authorization/latest/reference/list_continuum.html)
and the [import guide](scanner-imports/continuum.md).
