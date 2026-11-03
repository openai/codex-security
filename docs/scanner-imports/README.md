# Import external scanner findings

Bring an existing scanner report into Codex Security to investigate it against
your checkout.

## Preview a report

[Install the CLI](../../README.md#quick-start) and enable imports in the shell
that runs it or launches Codex.

```sh
export CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS=1
```

In PowerShell, use `$env:CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS = '1'`.

In the terminal, follow your scanner's example. Previewing a saved report with
`publish findings` and `--to local --dry-run` needs no Cloud login, network
connection, or model call. Add `--format json` to see all findings and exclusions.
Reuse the checkout and **source key** (the name for this stream of findings) on
later imports.

With the Codex Security plugin enabled, you can ask Codex to review the preview
with your configured model.

> Preview my saved Endor Labs report at `../reports/endor-findings.json` against
> this checkout. Show me which findings would be imported and which were excluded.
> Stop after the preview.

Check your CLI version with `codex-security --version`. AWS Continuum, Black Duck,
SonarQube Cloud, Veracode, the Semgrep Platform SDK example, and Cloud private
inbox imports were added after [0.8.2](https://github.com/openai/codex-security/blob/npm-v0.8.2/sdk/typescript/docs/cli.md#import-vendor-findings-locally).

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

For selected findings, use the guide's filters or select complete native records
where the format allows. Check that the preview contains the requested IDs and
their evidence, and review any exclusions. Keep reports and command output
private. In CI, direct stdout and stderr to private files outside the checkout.
Set `TMPDIR` there if needed.

## Save or publish and verify

These steps apply to `publish findings FILE`. For an `import sonar` capture,
[use the local or Cloud capture returned by the corresponding preview](sonar.md#import-and-verify).

**Save locally.** Rerun the reviewed command without `--dry-run` and confirm.
In automation, use `--yes` after reviewing the preview. Read back the stored
findings using the checkout path from the preview.

```sh
codex-security findings imported /path/to/project --format json
```

**Send to Cloud.** Keep the same file, provider, source key, and scanner
options. Switch to `--to cloud`, set `--repository` to the connected
repository URL or Cloud repository ID, and run with `--dry-run`. Review the
account, endpoint, destination, findings, and exclusions. Remove `--dry-run`
and confirm to send the report. [Cloud setup](../../sdk/typescript/docs/cli.md#preview-and-publish)

| Cloud preview                                     | What to check after confirmation                                                                                                             |
| ------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| Private inbox (`privateImport`)                   | Check the job status, errors, exclusions, and unprocessed count. Open the finding in your inbox to assess it and choose whether to share it. |
| Repository publisher (environments in `requests`) | Check the per-finding receipts, verified and unacknowledged counts, failures, and exclusions.                                                |

If an interrupted result includes `savedSubmission`, [resume that submission](schema-guide.md#retry-a-cloud-submission).

## Work with imported findings

Local records start as `not_assessed`. To investigate one, give its evidence
and the matching checkout to [the triage workflow](../agent-workflows.md#choose-a-task).
With the SDK, pass the record's `evidence` to [`security.validate()`](../../sdk/typescript/README.md#validate-an-existing-finding)
to get a separate assessment from your configured model provider. For a dependency
alert, [check the installed version and trace the dependency](github-dependabot.md#identity-and-evidence).

See [Imported finding identity and evidence](schema-guide.md) for the fields each
reader retains and what happens on repeat imports.
