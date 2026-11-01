# Import external scanner findings

Choose the guide for your report. Each guide shows how to preview the findings
in a local checkout and which source key to reuse on later imports.

| Guide                                                       | Supported input                                                                 |
| ----------------------------------------------------------- | ------------------------------------------------------------------------------- |
| [Amazon Inspector](inspector.md)                            | Inspector2 `ListFindings` JSON for one Code Security repository                 |
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

## Preview a report

Enable external imports in the shell where you run the CLI.

```sh
export CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS=1
```

In PowerShell, use `$env:CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS = '1'`.
Follow your guide's quick start to collect or select the report. Run examples
that use `--repository .` from the checkout root, or pass the same checkout
path you used previously. Use `--dry-run` to review the repository, source key,
findings, and exclusions.
Keep the export private. In automation, direct stdout and stderr for collection,
preview, confirmation, and readback to private files outside the checkout.
For examples that use `mktemp -d` without a path, set `TMPDIR` to a private
directory outside the checkout if temporary files would otherwise land inside it.

## Save or publish and verify

The steps below apply to `publish findings FILE`. For `import sonar`,
[confirm the capture returned by the Sonar preview](sonar.md#import-and-verify).

**Local workbench.** Run the same command with the same file, checkout, and
source key. Remove `--dry-run` and confirm the prompt.
For noninteractive use, add `--yes` after reviewing that preview. Read back
the stored evidence using the checkout path from the preview:

```sh
codex-security findings imported /path/to/project --format json
```

**Codex Security Cloud.** Use a file-backed ChatGPT login for a deployment that
accepts the provider and a repository environment you can publish to. See
[Cloud setup](../../sdk/typescript/docs/cli.md#preview-and-publish). Keep the
file, provider, source key, and scanner-specific options. Set `--to cloud` and
replace the local checkout in `--repository` with the connected repository URL
or Cloud repository ID. Use the ID if several connectors share the URL.
Run with `--dry-run` first. Check that `cloudApiUrl`
is the intended API endpoint, then review the account, repository, environments,
and exclusions. Remove `--dry-run` and confirm, or use `--yes` after that
review. Check `status`, the `verified` and
`unacknowledged` counts, and the `failures` and `excluded` lists. For a `partial`
result, correct exclusions or resolve version conflicts before starting a new
submission. If an `interrupted` result includes `savedSubmission`,
[resume from that checkpoint](schema-guide.md#retry-a-cloud-submission).

## Work with imported findings

Imported records start with assessment state `not_assessed`. Use the source
evidence to check whether a finding affects your repository. For the identity
of a record, the fields each reader retains, and how repeat imports update
evidence, see [Imported finding identity and evidence](schema-guide.md).

For findings from a completed Codex scan, see
[Track findings in Linear, Jira, or GitHub](../../plugins/codex-security/skills/track-findings/SKILL.md)
or [Export findings for ServiceNow](../../sdk/typescript/docs/cli.md#export-findings-for-servicenow).
