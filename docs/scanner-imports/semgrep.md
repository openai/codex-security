# Import Semgrep Code findings

Import a saved Semgrep Code CLI or CI report into the local workbench or Cloud.
Native JSON preserves original severities and snippets when available. The reader
also accepts self-contained Semgrep SARIF 2.1.0. Either format can be gzipped.

## Quick start

From the scanned repository's root, set `report` to the saved report and
`repo_url` to its credential-free HTTP(S) repository URL. Choose a stable source key for this
organization, project and branch. Enable external imports for this shell.

```sh
export CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS=1
report=../reports/semgrep.json
repo_url=https://github.com/example/project
source_key=example/project/main
```

If you need a new report, run Semgrep in the repository root with your SAST
rules. Use a private temporary directory outside the checkout for this run.

```sh
report=
report_dir=$(mktemp -d) &&
  semgrep scan --config /path/to/sast-rules.yaml --json-output "$report_dir/semgrep.json" . &&
  report="$report_dir/semgrep.json"
```

After a successful scan, or with an existing report, preview the selected file locally.

```sh
codex-security publish findings "$report" --to local --repository . \
  --provider semgrep --source-repository-url "$repo_url" \
  --source-key "$source_key" --dry-run --format json
```

## Import and verify

Review the source and destination repositories, findings and exclusions. The
declared source URL must match a comparable configured Git remote when one
is available. Rerun the local preview command without `--dry-run`, confirm
the import, then read back the unassessed records. Local import needs no Cloud account.

```sh
codex-security findings imported . --format json
```

To publish the same report, sign in to a Cloud account with access to the
repository and a deployment that accepts the `semgrep` provider. Preview the
destination, repeat without `--dry-run` and confirm. Check the result's
`verified` count and any exclusions or failures.
[Cloud publication](../../sdk/typescript/docs/cli.md#publish-findings-to-cloud)

```sh
codex-security publish findings "$report" --to cloud --repository "$repo_url" \
  --provider semgrep --source-repository-url "$repo_url" \
  --source-key "$source_key" --dry-run --format json
```

## Reference

### CI artifacts

A saved native JSON report from a Code-only `semgrep ci` job is also accepted.
The job's policy and baseline determine which matches the report contains.
A job can exit 1 for blocking findings and still produce a valid report. Keep
the CI job's product selection and exit status. From your workstation, set
`report` to a private copy of the artifact and follow the local preview above.
[Semgrep CLI reference](https://docs.semgrep.dev/cli-reference)

### Evidence and identity

Semgrep JSON retains the result, rule, CWE IDs, source range, snippets and
ignored state when supplied. SARIF retains the selected rule and result,
including trace and fix evidence. Critical and High both map to SARIF `error`,
which imports as High. Deeply nested traces can exceed Cloud limits and appear
in `excluded`. Keep the original report for run-wide inventories and timing.
[Semgrep output fields](https://docs.semgrep.dev/semgrep-appsec-platform/json-and-sarif)
and [imported evidence](schema-guide.md)

The reader identifies a match by JSON `extra.fingerprint` or SARIF
`matchBasedId/v1` when supplied. Reimporting the same fingerprint under the
same source key and repository updates its location. When Community Edition
omits the fingerprint or returns `requires login`, the rule, literal path and
range identify the match. Moving it creates another record. Omitted records
remain stored.

Use SAST-only rules. Identifiable Supply Chain and Secrets results are
excluded, and SARIF may lack enough product metadata to identify all of them.
Scan errors or unsuccessful SARIF invocations prevent import. SARIF supports
direct artifact URIs and Semgrep's native `%SRCROOT%` paths. Indexed artifacts
or unresolved bases stay in raw evidence and need a fingerprint for identity.
External property files are unsupported.

SDK callers pass `sourceRepositoryUrl` to `normalizeSemgrepFindings`,
`normalizeSemgrepSarif` or `readSemgrepFindings`. The file import forwards
SARIF repository provenance automatically. When calling `prepareNormalizedLocalImport`
directly, pass the original repository references in its third argument's
`sourceRepositories`. Use `{ url, platform: "github" }` for a verified custom
GitHub host.

### Existing Platform findings

This file reader accepts scan reports. Semgrep Guardian, MCP and the Platform
findings API return different records. For this workflow, use a Code scan
artifact. [Guardian for Codex](https://docs.semgrep.dev/semgrep-guardian/ide-setup/codex),
[Semgrep MCP implementation](https://github.com/semgrep/semgrep/blob/fe209763a4a2ccfcdf6434e6c332edc24a2f586e/cli/src/semgrep/mcp/server.py)
and [Platform findings API](https://docs.semgrep.dev/semgrep-appsec-platform/semgrep-api)
