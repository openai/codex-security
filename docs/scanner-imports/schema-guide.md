# Imported finding identity and evidence

See the [scanner import guides](README.md) for accepted inputs, repository
requirements and export examples.
This reference explains which records a repeat import updates, what the fields
mean and how to interpret the result.

## Choose the record and source key

Keep the same provider and source key for later exports of the same vendor
project and finding family. For example, use
`github.com/OWNER/REPO/dependabot` for Dependabot alerts. An updated local import
under that key replaces evidence for its existing record. A source key that changes with each export creates another record for the same alert.

| Destination                | What identifies the record                                                                                                                                                                             |
| -------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Local workbench            | The checkout path, stored provider, source key and source finding ID. For a repeat import, reuse the exact repository path and source key in the preview.                                              |
| Private Cloud inbox        | The importing owner, provider, source key and vendor occurrence ID. The suggested repository for assessment can change without creating another record. The receipt identifies the private import job. |
| Cloud repository publisher | The destination repository, provider, source key and source finding ID.                                                                                                                                |

Each reader derives the source finding ID from the export. The table shows
which changes can give an occurrence a different ID.

| Report                                                                                | What identifies one record                                                                                                                                                               |
| ------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [Amazon Inspector](inspector.md), [Endor Labs](endor.md), [SonarQube Cloud](sonar.md) | Inspector finding ARN, Endor Finding UUID or Sonar issue key. Endor native JSON and SARIF use the same UUID.                                                                             |
| [ArmorCode](armorcode.md)                                                             | ArmorCode finding ID (`id`) within the source key.                                                                                    |
| [AWS Continuum](continuum.md)                                                         | Continuum finding ARN. A list summary and a detailed response for that ARN identify the same finding.                                                                                    |
| [Tenable One](tenable.md)                                                             | Exact Tenable `finding_id` within the local checkout and a stable tenant/asset source key. Use the Code Repository asset UUID in the key.                                                |
| [Checkmarx SAST](checkmarx.md)                                                        | Checkmarx One uses the similarity ID and result hash. CxSAST scopes the similarity ID and ordered flow to the project and query.                                                         |
| [Wiz](wiz.md)                                                                         | Package occurrence ID, or a SAST, repository-secret or IaC occurrence ID prefixed with its family. Normalized JSONL uses the supplied ID.                                                |
| [GitHub Dependabot](github-dependabot.md), [code scanning](github-code-scanning.md)   | Host, repository, alert family and alert number. Code scanning also includes the selected ref. Two alerts citing one GHSA remain separate.                                               |
| [GitHub advisories](github-security-advisories.md)                                    | Host, repository or global scope, and GHSA ID. This identifies a disclosure. Check installed packages separately.                                                                        |
| [Trivy](trivy.md)                                                                     | Analyzer, advisory, package name, target and package path when available. Use the same source key for a repository, project and branch.                                                  |
| [Snyk Open Source](snyk.md)                                                           | Native CLI JSON distinguishes manifest, package manager, advisory, package name and version, and dependency path. Plugin and SARIF reports use different identities.                     |
| [Snyk monitored project](snyk.md#existing-issues-from-snyk)                           | API origin, organization, project, product and issue key.                                                                                                                                |
| [Black Duck SCA](blackduck.md), [Veracode Static Analysis](veracode.md)               | Black Duck combines project version, component version, origin and advisory identity. Veracode scopes a native issue ID to its API origin, application and context.                      |
| [Semgrep CLI or CI reports](semgrep.md), [OpenGrep](opengrep.md)                      | Semgrep prefers a fingerprint and falls back to rule, path and range. OpenGrep groups traces by rule, path and range. Both store provider `semgrep`. Use a separate OpenGrep source key. |
| [Semgrep Guardian selections](semgrep.md#import-selected-guardian-findings)           | Deployment, repository name, Guardian tool, full ref and exact string ID. Guardian records stay separate from Web API occurrences.                                                       |
| [Semgrep Platform findings](semgrep.md#existing-platform-findings)                    | Deployment, project ID, product, full Git ref and native finding ID. Web API SAST selections and full SAST collections share IDs.                                                        |

Repeat local imports replace changed evidence for the same identity. Identical
evidence is unchanged, and records omitted from a later report remain stored.
For example, importing Endor SARIF after native JSON for the same UUID can
remove details from the stored snapshot. If one export contains colliding IDs,
inspect the reader’s exclusions or input error before retrying.

## Read the right field

Imported records start with `assessment.state` set to `not_assessed`. The
[evidence schema](../../sdk/typescript/schemas/external-findings.schema.json)
defines the fields under `evidence`. Read the normalized fields first. Use the
saved vendor record to investigate a detail the scanner did not expose there.

| Field                                                      | How to use it                                                                                                                                             |
| ---------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `title`, `description`, `severity`                         | The title identifies what the scanner reported. An optional description explains the finding. Severity can be `unknown`.                                  |
| `url`                                                      | Open the scanner finding or advisory supplied by the reader. This link can lead to a vendor portal that requires sign-in.                                 |
| `details.repository.url`, `details.file_url`               | Open the source repository or the reported file. A repository link alone does not identify a file or revision.                                            |
| `advisory_ids[]`, `details.weakness_ids[]`, `details.rule` | CVE and GHSA IDs identify vulnerabilities or advisories. CWEs classify weaknesses. A rule ID identifies the scanner check.                                |
| `packages[]`                                               | Compare an observed `installed_version` with the reported `vulnerable_version_range` and `fixed_versions`. An advisory may supply only a range or fix.    |
| `locations[]`, `code_revision`                             | Navigate to a reported repository path and line at the scanned revision when available. `details.code.end_line` extends the first location.               |
| `details`                                                  | Optional context for `sast`, `secret`, `iac` or `advisory` findings. For GHSA, `details.advisory.source` distinguishes repository and global disclosures. |
| `source_data`                                              | The vendor fields retained for this record. Keep the original export when you need scan-wide diagnostics or inventory.                                    |

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

**Local.** Run `codex-security findings imported PATH` with the repository path
from the preview. In a terminal, the list shows the source key and finding ID,
severity and title. It also shows the first reported package and location,
the primary reference, and a distinct file link when available. Installed,
affected and fixed package versions appear when the scanner supplied them. If the reported
scanner differs from the stored provider, both appear (for example, OpenGrep
and `semgrep`). A rule-ID title can include a short scanner message. Pass `--format json` for
all locations and the complete saved evidence. Each record includes
`sourceKey`, `sourceFindingId`, `version`, `evidence` and `assessment`.

**Private Cloud inbox.** Check the format, size and digest under
`privateImport` in the preview, then inspect the job receipt for errors and
unprocessed findings. Open a finding in the inbox to assess it and publish
the assessment when you're ready to share it.

Reimporting identical evidence for the same occurrence leaves the saved
observation in place. If the job reports `source_order_unknown`, Cloud
received different evidence for an existing finding and needs its current
observation version before replacing it. Check the previous observation and
the new evidence before retrying. A newer scanner timestamp alone cannot
authorize that update.

**Cloud repository publisher.** Each item includes a `source_finding_id` and an `expected_version`.
Check the per-item result for conflicts. The receipt's source-report,
observation and canonical-finding IDs identify Cloud records. Read the source
report for the imported evidence. If this destination requires a known
severity, findings whose scanner reported no severity appear in the preview's
exclusions. The private inbox also accepts unknown severity.

The repository publisher allows up to 256 KiB and 20 levels of nesting per finding. The publisher
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
2. Check `accountId`, `destination` and `resumed` in the preview. If `resumed`
   is true, confirmation continues the saved submission. The repository
   publisher also preserves the original expected versions. If `resumed` is
   false, review the new submission before confirming. If a repository reset
   retired the submission, run another dry run to review the new repository
   and environment.

For a failed or cancelled private job, a fresh preview identifies the previous
job and confirmation starts a new attempt. A lost response from an active job
reuses its original request IDs. After an inbox reset, review the new format,
size and digest before confirming.

With the SDK, repeat the preparation call that created the submission, using
the same options. For `prepareExternalPublication()`, supply the original
export file. For `prepareNormalizedExternalPublication()`, supply the original
`ExternalFindings`. Check `preview.resumed` before calling `publish()`.
Use the same SDK version throughout a submission when possible.

For hosted Semgrep or Snyk imports, finish any pending request before sending
updated evidence for the same finding IDs. Selections with distinct
scanner-issued IDs can proceed independently. If the checkpoint records
only the source, finish that request before starting another for the same
source and destination.

**Resuming across SDK versions.** Keep the SDK input that produced the
checkpoint, including report context and caller-added fields. Serializing it
as JSON can change the values used to identify the approved request. Retry on
the original deployment. If the SDK can verify the saved selection, it reuses
the request IDs and skips batches with receipts. Otherwise it preserves the
checkpoint and stops before uploading. If it cannot identify the approved
findings, a new submission for the same source and destination can also be blocked.

After a repository rename, a checkpoint that records only the repository ID
can still be retried with the original normalized findings and report metadata.
Omit supplemental repository declarations for that retry. A new declaration
requires a matching catalog entry or a URL recorded in the approval.

See [results and exit codes](../../sdk/typescript/docs/cli.md#results-and-exit-codes)
for cumulative counts and interrupted readback.
