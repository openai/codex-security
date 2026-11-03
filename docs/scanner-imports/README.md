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

**In the terminal**, follow your scanner's guide. For a saved report,
`publish findings` with `--to local --dry-run` works offline without a Cloud
login or model call. Add `--format json` to see every finding and exclusion.
Reuse the same checkout and `--source-key` to update matching findings later.

**In Codex**, [enable the Codex Security plugin and start a new chat](../agent-workflows.md#get-started).
Ask it to preview the report with your configured model.

> Preview `../reports/endor-findings.json` for this checkout. Show me which
> Endor findings the CLI would import and which it would skip. Stop there.

## Choose your scanner

Check your version with `codex-security --version`. Support for AWS Continuum,
Black Duck, SonarQube Cloud, Veracode, the Semgrep Platform SDK example, and
Cloud private inbox imports came after [version 0.8.2](https://github.com/openai/codex-security/blob/npm-v0.8.2/sdk/typescript/docs/cli.md#import-vendor-findings-locally).

| Guide                                                       | Supported input                                                                 |
| ----------------------------------------------------------- | ------------------------------------------------------------------------------- |
| [Amazon Inspector](inspector.md)                            | Inspector2 `ListFindings` JSON for one Code Security repository                 |
| [AWS Continuum](continuum.md)                               | Code finding summaries or a detailed finding verified for one repository        |
| [Black Duck SCA](blackduck.md)                              | BOM component vulnerabilities for one project version                           |
| [Endor Labs](endor.md)                                      | Finding JSON from `endorctl`, or SARIF with finding UUIDs                       |
| [GitHub code scanning](github-code-scanning.md)             | Alerts selected for one repository and Git ref                                  |
| [GitHub Dependabot](github-dependabot.md)                   | Dependency alerts exported from one repository                                  |
| [GitHub Security Advisories](github-security-advisories.md) | Selected repository or global advisories                                        |
| [OpenGrep](opengrep.md)                                     | Native scan JSON, optionally gzip-compressed                                    |
| [Semgrep Code](semgrep.md)                                  | CLI/CI JSON, self-contained SARIF, or selected Platform API pages (local SDK)   |
| [Snyk Open Source](snyk.md)                                 | CLI JSON, a Codex plugin export, or SARIF                                       |
| [SonarQube Cloud](sonar.md)                                 | Issues selected with the signed-in Sonar CLI, or saved issue-search pages       |
| [Veracode Static Analysis](veracode.md)                     | Findings API pages for one application's policy flaws                           |
| [Wiz](wiz.md)                                               | Native JSON, normalized JSONL, or detailed repository package vulnerability CSV |

For specific findings, filter by ID or save the complete records for those IDs
if the format allows. Check the IDs, evidence, and exclusions in the preview.
Keep reports and output private. In CI, redirect stdout and stderr to private
files outside the checkout. Set `TMPDIR` there if needed.

## Save or publish and verify

These steps cover `publish findings FILE`. For `import sonar`, [use the capture
from the preview for your destination](sonar.md#import-and-verify).

**Save locally.** Remove `--dry-run` and confirm. In automation, use `--yes`
after reviewing the preview. List the saved findings using the checkout path
from the preview.

```sh
codex-security findings imported /path/to/project --format json
```

**Send to Cloud.** Keep your file, provider, source key, and scanner options.
Set `--to cloud` and pass the connected repository URL or Cloud ID to
`--repository`. Preview again with `--dry-run`. Check the account, endpoint,
destination, findings, and exclusions. Remove `--dry-run` and confirm. [Cloud setup](../../sdk/typescript/docs/cli.md#preview-and-publish)

| What the Cloud preview shows                      | How to verify the import                                                                                                   |
| ------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| Private inbox (`privateImport`)                   | Check the job status, errors, exclusions, and unprocessed count. Open a finding in your inbox to assess it before sharing. |
| Repository publisher (environments in `requests`) | Check each receipt, the verified and unacknowledged counts, failures, and exclusions.                                      |

If the import stops and returns `savedSubmission`, [resume from that checkpoint](schema-guide.md#retry-a-cloud-submission).

## Work with imported findings

New local findings start as `not_assessed`. To check whether one affects your
code, give its evidence and the matching checkout to the [triage workflow](../agent-workflows.md#choose-a-task).
For a dependency alert, [check the installed version and trace the dependency](github-dependabot.md#identity-and-evidence).

With the SDK, pass the record's `evidence` to [`security.validate()`](../../sdk/typescript/README.md#validate-an-existing-finding).
Your configured model provider returns a separate assessment.

See [Imported finding identity and evidence](schema-guide.md) for what each
reader stores and how repeat imports work.
