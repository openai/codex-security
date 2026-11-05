# Import external scanner findings

Preview a scanner report before saving its findings locally or sending them
to Codex Security Cloud.

## Preview a report

[Install the CLI](../../README.md#quick-start), then enable imports in the shell
where you run it or start Codex.

```sh
export CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS=1
```

In PowerShell, use `$env:CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS = '1'`.
Keep reports and preview output in a private directory outside the checkout.
For commands that use `mktemp`, set `TMPDIR` there if needed. In CI, redirect
both stdout and stderr to private files.

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

## Choose your scanner

With imports enabled, run `codex-security publish findings --help` to check the
providers in your installed CLI. The guides cover local and Cloud imports
unless an input is marked local only.

| Guide                                                       | Supported input                                                                          |
| ----------------------------------------------------------- | ---------------------------------------------------------------------------------------- |
| [Amazon Inspector](inspector.md)                            | Inspector2 `ListFindings` JSON for one Code Security repository                          |
| [AWS Continuum](continuum.md)                               | Summaries or selected code finding details for one verified repository                   |
| [Black Duck SCA](blackduck.md)                              | BOM component vulnerabilities for one project version                                    |
| [Checkmarx SAST](checkmarx.md)                              | Checkmarx One CLI JSON or self-managed CxSAST XML for one scan                           |
| [Endor Labs](endor.md)                                      | Finding JSON from `endorctl`, or SARIF with finding UUIDs                                |
| [GitHub code scanning](github-code-scanning.md)             | Alerts selected for one repository and Git ref                                           |
| [GitHub Dependabot](github-dependabot.md)                   | Dependency alerts exported from one repository                                           |
| [GitHub Security Advisories](github-security-advisories.md) | Selected repository or global advisories                                                 |
| [OpenGrep](opengrep.md)                                     | Native scan JSON, optionally gzip-compressed                                             |
| [Semgrep](semgrep.md)                                       | CLI/CI JSON, SARIF, Platform Web API reports, or selected Guardian findings (local only) |
| [Snyk](snyk.md)                                             | CLI JSON, plugin exports, SARIF, or monitored Code and Open Source issues                |
| [SonarQube Cloud](sonar.md)                                 | Issues selected with the signed-in Sonar CLI, or saved issue-search pages                |
| [Tenable One](tenable.md)                                   | Selected Code Repository inventory findings (experimental, local only)                   |
| [Trivy](trivy.md)                                           | Native schema-v2 repository or filesystem JSON, optionally gzip-compressed               |
| [Veracode Static Analysis](veracode.md)                     | Findings API pages for one application's policy flaws                                    |
| [Wiz](wiz.md)                                               | Native JSON, normalized JSONL, or detailed repository package vulnerability CSV          |

If you selected specific findings, compare the preview with your selection.
Check for missing, duplicate or unexpected occurrences. For OpenGrep, check
`report.errors` as well as exclusions, even when the findings list is empty.

## Save or publish and verify

These steps cover `publish findings FILE`. For `import sonar`, [use the capture
from the preview for your destination](sonar.md#import-and-verify).

**Save locally.** Remove `--dry-run` and confirm. In automation, use `--yes`
after reviewing the preview.

**Send to Cloud.** Semgrep Guardian captures support local import only. For other
supported files, keep the file, provider, source key and scanner options from
your preview.
Set `--to cloud` and pass the connected repository URL or Cloud ID to
`--repository`. Preview again with `--dry-run`. Check the account, endpoint,
destination, findings, and exclusions. Remove `--dry-run` and confirm. [Cloud setup](../../sdk/typescript/docs/cli.md#preview-and-publish)

Add `--format json` to see which destination your workspace offers.
When the preview includes `privateImport`, confirming sends the findings to
your private inbox with the selected repository and connector. GitHub code scanning,
Dependabot and advisories use the GitHub provider. OpenGrep uses the Semgrep
provider. For Amazon Inspector or AWS Continuum, the CLI and workspace must
support v2 import jobs. For Black Duck, Checkmarx, SonarQube Cloud, Trivy or
Veracode, they must support v3 to use the private inbox.

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

If the repository publisher requires a reported severity, the preview excludes
findings whose severity the scanner left unknown. You can keep those findings
in a local import or a private inbox when available.

If `publish findings` stops and returns `savedSubmission`, [resume from that checkpoint](schema-guide.md#retry-a-cloud-submission).

## Troubleshoot Semgrep and Snyk collection

If `import semgrep` or `import snyk` returns HTTP 429, check `Retry-After`.
Both collectors retry the same GET once when the requested wait is at most
10 seconds. They accept whole seconds or an HTTP date and retry immediately
for zero or a past date. Cancellation stops the wait. A failed request reports
its HTTP status and up to 64 KiB of the vendor response. After the indicated
wait, rerun collection and preview the complete successful output.

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
