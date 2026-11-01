# Import external scanner findings

Use a scanner report to bring findings into the local Codex Security workbench or
publish them to Codex Security Cloud. Start with the guide for your input. Each
guide shows how to preview the findings before you save or publish them.

| Source                                                                                                                                                            | Input                                                                             |
| ----------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------- |
| [Amazon Inspector](inspector.md)                                                                                                                                  | Inspector2 `ListFindings` JSON for one Code Security repository                   |
| [Black Duck SCA](blackduck.md)                                                                                                                                    | BOM component vulnerability records for one project version                       |
| [Endor Labs](endor.md)                                                                                                                                            | Finding JSON from `endorctl`, or SARIF with finding UUIDs                         |
| [GitHub code scanning](../../sdk/typescript/docs/cli.md#import-github-findings-locally-or-to-cloud)                                                               | Selected alerts from a repository and Git ref                                     |
| [GitHub Dependabot](github-dependabot.md)                                                                                                                         | Dependency alerts exported from one repository                                    |
| [GitHub Security Advisories](../../sdk/typescript/docs/cli.md#import-ghsa-advisories-separately)                                                                  | Selected repository or global advisories                                          |
| [OpenGrep](opengrep.md)                                                                                                                                           | Native scan JSON, optionally gzip-compressed                                      |
| [Semgrep Code](semgrep.md)                                                                                                                                        | CLI/CI JSON, self-contained SARIF, or selected Platform Web API responses (SDK)   |
| [Snyk Open Source](snyk.md)                                                                                                                                       | CLI JSON, a Codex plugin export, or SARIF                                         |
| [SonarQube Cloud](sonar.md)                                                                                                                                       | Selected security issues from the signed-in Sonar CLI or saved issue-search pages |
| [Veracode Static Analysis](veracode.md)                                                                                                                           | Findings API pages for one application's policy flaws                             |
| Wiz ([local preview](../../sdk/typescript/docs/cli.md#import-vendor-findings-locally), [formats and Cloud](../../sdk/typescript/docs/cli.md#import-wiz-findings)) | Native JSON, normalized JSONL or detailed repository package vulnerability CSV    |

## Preview a report

Enable external imports in the shell where you run the CLI.

```sh
export CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS=1
```

In PowerShell, use `$env:CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS = '1'`.
Follow the provider guide to capture or export the report. For a saved file,
add `--dry-run` to the guide’s `codex-security publish findings FILE --to local`
command. Review the destination, findings and exclusions. Repeat without
`--dry-run` and confirm at the prompt. For noninteractive use, pass `--yes`
after reviewing the same report and destination. Keep the source key for
later exports from the same source.

Preview, import and readback output can contain the full scanner evidence.
Run these steps in a private terminal. In automation, direct standard output
and diagnostics for each step to private files outside the checkout.

## Work with imported findings

Run `codex-security findings imported PATH` with the repository path shown in
the local preview. Imported findings have assessment state `not_assessed`. Use
the scanner evidence to check whether the issue affects your repository.

- [CLI import options, destinations and confirmation](../../sdk/typescript/docs/cli.md#import-vendor-findings-locally)
- [How scanner records map to finding IDs and evidence](schema-guide.md)
