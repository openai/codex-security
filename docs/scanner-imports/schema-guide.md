# Imported finding identity and evidence

See the [scanner import guides](README.md) for accepted inputs, repository
requirements and export examples.
This reference explains which records a repeat import updates, what the fields
mean and how to interpret the result.

## Choose the record and source key

A source record is identified by its destination repository, stored provider,
source key and source finding ID. Use the same source key for each export of the
same stream, such as an organization, project and branch. A date or run ID in
the key creates a new set of records on each run.

The reader derives the source finding ID from the export. The differences matter
when a finding moves, an advisory affects several packages, or the export format
changes.

| Report                                                                                          | What identifies one record                                                                                                                                                               |
| ----------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [Amazon Inspector](inspector.md), [Endor Labs](endor.md), [SonarQube Cloud](sonar.md)           | Inspector finding ARN, Endor Finding UUID or Sonar issue key. Endor native JSON and SARIF use the same UUID.                                                                             |
| [Wiz](wiz.md)                                                                                   | Package occurrence ID, or a SAST, repository-secret or IaC occurrence ID prefixed with its family. Normalized JSONL uses the supplied ID.                                                |
| [GitHub Dependabot](github-dependabot.md), [code scanning](github-code-scanning.md)             | Host, repository, alert family and alert number. Code scanning also includes the selected ref. Two alerts citing one GHSA remain separate.                                               |
| [GitHub advisories](github-security-advisories.md)                                              | Host, repository or global scope, and GHSA ID. This identifies a disclosure. Check installed packages separately.                                                                        |
| [Snyk Open Source](snyk.md)                                                                     | Native CLI JSON distinguishes manifest, package manager, advisory, package name and version, and dependency path. Plugin and SARIF reports use different identities.                     |
| [Black Duck SCA](blackduck.md), [Veracode Static Analysis](veracode.md)                         | Black Duck combines project version, component version, origin and advisory identity. Veracode scopes a native issue ID to its API origin, application and context.                      |
| [Semgrep CLI or CI reports](semgrep.md), [OpenGrep](opengrep.md)                                | Semgrep prefers a fingerprint and falls back to rule, path and range. OpenGrep groups traces by rule, path and range. Both store provider `semgrep`. Use a separate OpenGrep source key. |
| [Semgrep Platform SAST](semgrep.md#import-selected-semgrep-platform-sast-findings-with-the-sdk) | Deployment, project ID, SAST product, full Git ref and native finding ID. The same occurrence keeps its identity when its file moves.                                                    |

Repeat local imports replace changed evidence for the same identity. Identical
evidence is unchanged, and records omitted from a later report remain stored.
For example, importing Endor SARIF after native JSON for the same UUID can
remove details from the stored snapshot. If one export contains colliding IDs,
inspect the reader’s exclusions or input error before retrying.

## Read the right field

Imported records start with `assessment.state` set to `not_assessed`. The
[evidence schema](../../sdk/typescript/schemas/external-findings.schema.json)
defines the fields the reader can populate.

| Field                          | How to use it                                                                                                                                             |
| ------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `title`, `severity`            | Required source evidence. Severity can be `unknown`. A scanner verdict or suppression can be reported alongside it.                                       |
| `packages[]`                   | Compare an observed `installed_version` with the reported `vulnerable_version_range` and `fixed_versions`. An advisory may supply only a range or fix.    |
| `locations[]`, `code_revision` | Navigate to a reported repository path and line at the scanned revision when available. `details.code.end_line` extends the first location.               |
| `details`                      | Optional context for `sast`, `secret`, `iac` or `advisory` findings. For GHSA, `details.advisory.source` distinguishes repository and global disclosures. |
| `source_data`                  | The vendor fields retained for this record. Keep the original export when you need scan-wide diagnostics or inventory.                                    |

Use finite JSON numbers in evidence and report metadata. Supply integers outside
JavaScript’s safe range as strings to preserve their value. In SDK inputs, use
primitive numbers in plain data fields for predictable JSON exports. Supply
precise decimals as strings if converting a `JSON.rawJSON()` number to a
JavaScript number would round its value.

When you supply normalized findings to the SDK, new imports use their JSON
representation. For example, `new Number(7)` exports as `7`. If its `toJSON()`
returns `9`, the new import uses `9`. The GitHub code-scanning and advisory
readers also apply the Cloud size limit to the evidence they return.

## Operate the two destinations

**Local.** Run `codex-security findings imported PATH --format json` with the
repository path from the preview. Each record includes
`sourceKey`, `sourceFindingId`, `version`, `evidence` and `assessment`.

**Cloud.** Each item includes a `source_finding_id` and an `expected_version`.
Check the per-item result for conflicts. The receipt's source-report,
observation and canonical-finding IDs identify Cloud records. Read the source
report for the imported evidence.

Cloud allows up to 256 KiB and 20 levels of nesting per finding. The publisher
batches up to 100 items and 5 MiB per request. Local file imports do not apply
these Cloud limits.

Select only authorized scanner metadata when collecting a report. Exclude
credential values before import. A reader can retain the entire selected record in
`evidence.source_data`. Confirm the destination before publishing.

Reports, output and saved requests can contain source snippets, private
advisories and secret metadata. Keep the export, preview, import result and
readback private. If a job captures terminal output, redirect standard output
and diagnostics for all three commands to private files outside the checkout.
Keep these files out of job logs and public issues.

### Retry a Cloud submission

A partial result can include accepted records. Inspect the receipts, item
failures and exclusions. If the connection dropped, Cloud may have accepted a
request before the response was lost.

1. If the interrupted result includes `savedSubmission`, keep that checkpoint.
   Preview the original export with `--dry-run --format json` using the same
   build, state directory, Cloud account, endpoint and import settings.
2. Check `accountId`, `destination` and `resumed` in the preview. When `resumed`
   is true, confirm the command to continue with the saved request IDs, bodies
   and expected versions. When it is false, review the fresh submission before
   confirming. If a repository reset retires the old submission and preparation
   returns an error, run `--dry-run` again and review the new destination and
   environment before confirming.

With the SDK, repeat the preparation call that created the submission, using
the same options. For `prepareExternalPublication()`, supply the original
export file. For `prepareNormalizedExternalPublication()`, supply the original
`ExternalFindings`. Check `preview.resumed` before calling `publish()`.
Use the same SDK version throughout a submission when possible.

After an SDK upgrade, retry with the original input. An older SDK could approve
different bytes from those its JSON export contained. When the SDK verifies
the old selection and request bytes, it resumes with the original request IDs
and skips batches that already have receipts. If it cannot verify the original
request, it preserves the checkpoint and stops before uploading. A saved JSON
export can lose information from the original SDK input. If a getter makes it
impossible to identify which findings were approved, the SDK can also stop a
new submission for the same source and destination.

See [results and exit codes](../../sdk/typescript/docs/cli.md#results-and-exit-codes)
for cumulative counts and interrupted readback.
