# Import Semgrep Code findings

Import native Code CLI or CI JSON to retain severities and available snippets.
Self-contained Semgrep SARIF 2.1.0 is also supported. Either format can be gzipped.

## Quick start

[Enable external imports](README.md#preview-a-report). From the scanned checkout root,
preview a saved SAST report using the repository's credential-free HTTP(S) URL
and a stable key for the organization, project and branch. If you need a report,
[capture one with Semgrep](#ci-artifacts).

For an existing report, set its path in the same shell.

```sh
semgrep_report=../reports/semgrep.json
```

Preview the selected report.

```sh
codex-security publish findings "$semgrep_report" --to local --repository . \
  --provider semgrep --source-repository-url https://github.com/example/project \
  --source-key example/project/main --dry-run --format json
```

## Import and verify

Check the declared source URL against the checkout's Git remote. With an empty
or wholly excluded report, the preview alone does not establish a repository match.
[Save or publish and verify](README.md#save-or-publish-and-verify) using the
same source URL and key. Cloud uses the `semgrep` provider.

## Reference

### CI artifacts

Use a saved artifact from a Code-only `semgrep ci` job. Policy and baseline
determine which matches it contains. Exit 1 can indicate blocking findings
even when the report is valid. Check the job's product selection and exit status.

To create a local report, run Semgrep from the repository root with your
SAST rules. Write to a private directory outside the checkout. After a
successful scan, use that file in the preview above. [Semgrep CLI reference](https://docs.semgrep.dev/cli-reference)

```sh
semgrep_report=
report_dir=$(mktemp -d) &&
  semgrep scan --config /path/to/sast-rules.yaml --json-output "$report_dir/semgrep.json" . &&
  semgrep_report="$report_dir/semgrep.json"
```

### Evidence and identity

Native JSON retains the result, rule, CWE IDs, range, snippets and ignored
state when supplied. SARIF retains the selected rule and result, including
traces and fixes. SARIF `error` imports as high even if the original severity
was critical. Check Cloud exclusions for deeply nested traces.
[Semgrep output fields](https://docs.semgrep.dev/semgrep-appsec-platform/json-and-sarif)

The match ID uses JSON `extra.fingerprint` or SARIF `matchBasedId/v1`.
Reimporting the same fingerprint under the same source key and repository
updates its location. If the fingerprint is absent or says `requires login`,
the ID uses rule, literal path and range. Moving the match then creates a new
record. [Imported evidence and identity](schema-guide.md)

Use SAST-only rules. Identifiable Supply Chain and Secrets results are
excluded, but SARIF can omit the product metadata. Scan errors or unsuccessful
SARIF invocations stop import. Direct artifact URIs and native `%SRCROOT%`
paths can supply locations. Indexed artifacts or unresolved bases remain in
raw evidence and require a fingerprint for identity. Use the original report
for run-wide inventories and timing.

SDK callers pass `sourceRepositoryUrl` to the native or SARIF normalizer.
When using `prepareNormalizedLocalImport` directly, pass the original SARIF
repository references in the third argument's `sourceRepositories`. Use
`{ url, platform: "github" }` for a verified custom GitHub host.

### Existing Platform findings

Guardian, MCP and the Platform findings API return different records. For
this file import, use a Code scan artifact.
[Platform findings API](https://docs.semgrep.dev/semgrep-appsec-platform/semgrep-api)
