# Import external scanner findings

Preview a scanner report with the CLI, then save the findings in the local
workbench or send a supported report to Codex Security Cloud.

## Choose your scanner

The `--provider` value selects the reader for a saved report. To see which
readers your installed CLI supports, run `codex-security publish findings --help`.
The guides cover local and Cloud imports unless an input is marked local only.

| Guide                                                       | `--provider` | Supported input                                                                                 |
| ----------------------------------------------------------- | ------------ | ----------------------------------------------------------------------------------------------- |
| [Amazon Inspector](inspector.md)                            | `inspector`  | Inspector2 `ListFindings` JSON for one Code Security repository                                 |
| [AWS Continuum](continuum.md)                               | `continuum`  | Summaries or selected code finding details for one verified repository                          |
| [Black Duck SCA](blackduck.md)                              | `blackduck`  | BOM-6 vulnerable components for one project version                                             |
| [Checkmarx SAST](checkmarx.md)                              | `checkmarx`  | Checkmarx One CLI JSON or self-managed CxSAST XML for one scan                                  |
| [Endor Labs](endor.md)                                      | `endor`      | Native Finding JSON, or self-contained `endorctl` SARIF with finding UUIDs                      |
| [GitHub code scanning](github-code-scanning.md)             | `github`     | Alerts selected for one repository and Git ref                                                  |
| [GitHub Dependabot](github-dependabot.md)                   | `github`     | Dependency alerts exported from one repository                                                  |
| [GitHub Security Advisories](github-security-advisories.md) | `github`     | Selected repository or global advisories                                                        |
| [OpenGrep](opengrep.md)                                     | `opengrep`   | Native scan JSON, optionally gzip-compressed                                                    |
| [Semgrep](semgrep.md)                                       | `semgrep`    | CLI/CI JSON, SARIF, or Platform Web API reports. Guardian selections support local import only. |
| [Snyk](snyk.md)                                             | `snyk`       | CLI JSON, plugin exports, SARIF, or monitored Code and Open Source issues                       |
| [SonarQube Cloud](sonar.md)                                 | `sonar`      | Issues selected with the signed-in Sonar CLI, or saved issue-search pages                       |
| [Tenable One](tenable.md)                                   | `tenable`    | Selected Code Repository inventory findings (local only)                                        |
| [Trivy](trivy.md)                                           | `trivy`      | Native schema-v2 repository or filesystem JSON, optionally gzip-compressed                      |
| [Veracode Static Analysis](veracode.md)                     | `veracode`   | Findings API pages for one application's policy flaws                                           |
| [Wiz](wiz.md)                                               | `wiz`        | Native JSON, normalized JSONL, or detailed repository package vulnerability CSV                 |

## Preview a report

[Install the CLI](../../README.md#quick-start) and open the repository the
findings apply to. Keep reports and preview output in a private directory
outside that checkout. For commands that use `mktemp`, set `TMPDIR` there
if needed. In CI, redirect stdout and stderr to private files.

**In the terminal**, follow your scanner's guide. Run examples that use
`--repository .` from the checkout root. For a saved report, `publish findings`
with `--to local --dry-run` works offline without a Cloud login or model call.
Add `--format json` to see every finding and exclusion.
For repeat local file imports, reuse the preview's exact `repository` and
`source.source_key` to update matching findings.

**In Codex**, [enable the Codex Security plugin and start a new chat](../agent-workflows.md#get-started).
Ask it to preview the report with your configured model.

> Preview `../reports/endor-findings.json` for this checkout. Show me which
> Endor findings the CLI would import and which it would skip. Stop there.

If you selected specific findings, compare the preview with your selection.
Check for missing, duplicate or unexpected occurrences. For OpenGrep, check
`report.errors` as well as exclusions, even when the findings list is empty.

## Save or publish and verify

These steps cover `publish findings FILE`. For `import sonar`, [use the capture
from the preview for your destination](sonar.md#import-and-verify).

**Save locally.** Remove `--dry-run` and confirm. In automation, use `--yes`
after reviewing the preview.

**Send to Cloud.** Tenable One reports and Semgrep Guardian selections support
local import only. For a Cloud-supported report, keep the file, provider,
source key, and scanner options from your local preview. Change the destination
to `--to cloud`, and pass the connected repository URL or Cloud ID to
`--repository`. Preview again with `--dry-run --format json`. [Cloud setup](../../sdk/typescript/docs/cli.md#preview-and-publish)

Check the account, endpoint, repository, selected findings, and exclusions.
The preview shows where your workspace will store the evidence. A
`privateImport` entry identifies your private inbox and the suggested
repository for assessment. Entries in `requests` identify the repository
environments that will receive the findings. Once you have reviewed the
destination, remove `--dry-run` and confirm.

### Verify the import

For a local import, list the saved findings using the checkout path from the preview.

```sh
codex-security findings imported /path/to/project --format json
```

For a Cloud import, check the receipt for the destination shown in the preview.

| What the Cloud preview shows                      | How to verify the import                                                                                                                                 |
| ------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Private inbox (`privateImport`)                   | Check that `privateJob.status` is `completed` and its counts account for the selected findings, with zero errors or unprocessed rows. Review exclusions. |
| Repository publisher (environments in `requests`) | Check each receipt, the verified and unacknowledged counts, failures, and exclusions.                                                                    |

To inspect published findings in Codex, [connect the Cloud app](../../sdk/typescript/README.md#read-existing-cloud-findings)
and ask for imported findings in the destination repository. For a private import,
ask for your private import history.

If the repository publisher requires a reported severity, the preview excludes
findings whose severity the scanner left unknown. You can keep those findings
in a local import or a private inbox when available.

If `publish findings` stops and returns `savedSubmission`, [resume from that checkpoint](schema-guide.md#retry-a-cloud-submission).

## Troubleshoot Semgrep and Snyk collection

If `import semgrep` or `import snyk` stops with HTTP 429, check the vendor's
`Retry-After` value. Wait for that interval, rerun collection, and preview
the complete export before importing it.

## Work with imported findings

New local findings start as `not_assessed`. To check whether one affects your
code, give its evidence and the matching checkout to the [triage workflow](../agent-workflows.md#choose-a-task).
For a dependency alert, [check the installed version and trace the dependency](github-dependabot.md#identity-and-evidence).

With the SDK, look up a local record by its `id` with
`listLocalExternalFindings({ repository, id })`. Pass `record.evidence` and the
matching checkout to [`security.validate()`](../../sdk/typescript/README.md#validate-an-existing-finding).
Your configured model provider returns a separate assessment.

See [Imported finding identity and evidence](schema-guide.md) for what each
reader stores and how repeat imports work.
