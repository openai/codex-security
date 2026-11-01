# Import Snyk Open Source findings

Import Open Source dependency vulnerabilities from a saved `snyk test` JSON report,
a `snyk-findings-export/v1` plugin bundle or self-contained Open Source SARIF.
Native CLI JSON preserves individual dependency paths and remediation details.

## Quick start

From the repository root, set `report` to a saved native JSON report.
Choose a stable source key for the repository, branch, scan target and format.
For repeat imports, use the exact key from your previous run.
Enable external imports and preview the local destination.

```sh
export CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS=1
report=../reports/snyk-open-source.json
source_key=github.com/example/project/main/root/native-sca
```

If you need a new report, use an authenticated Snyk CLI and the project's
package tooling. For a project with `package.json`, run the following in the
repository root. Use a private temporary directory outside the checkout for
this run. Exit 1 means findings. Other nonzero exits stop acquisition.
[Snyk CLI test](https://docs.snyk.io/developer-tools/snyk-cli/commands/test)

```sh
report_dir=$(mktemp -d) || exit "$?"
report="$report_dir/snyk-open-source.json"
snyk_status=0
snyk test --file=package.json --json-file-output="$report" || snyk_status=$?
if [ "$snyk_status" -gt 1 ]
then
  exit "$snyk_status"
fi
```

Preview the selected report locally.

```sh
codex-security publish findings "$report" --to local --repository . \
  --provider snyk --source-key "$source_key" --dry-run --format json
```

## Import and verify

Review the scan coverage, destination, findings and exclusions. Confirm the
checkout matches the scanned project, especially when the report has no Git URL.
Repeat the local command without `--dry-run`, confirm, then read back the
unassessed records. Local import needs no Cloud login.

```sh
codex-security findings imported . --format json
```

For Cloud, use a signed-in account with access to the connected repository.
Preview the same file and source key, review the destination, then repeat
without `--dry-run` and confirm. Check the result's `verified` count, failures
and exclusions. [Cloud publication](../../sdk/typescript/docs/cli.md#publish-findings-to-cloud)

```sh
codex-security publish findings "$report" --to cloud \
  --repository https://github.com/example/project --provider snyk \
  --source-key "$source_key" --dry-run --format json
```

## Reference

### Native CLI JSON

Use ungrouped output. For several projects under one scan root, replace
`--file=package.json` with `--all-projects --fail-fast` and handle exit codes
as above. Without `--fail-fast`, Snyk can omit results for projects it could
not scan. Project errors in the input stop the import. Keep independent scan
roots in separate reports with separate keys. License records are excluded.
[Snyk multi-project scan options](https://github.com/snyk/cli/blob/main/help/cli-commands/test.md#--fail-fast)

A native occurrence is identified by package manager, manifest, advisory,
package name and version, and dependency path. The reader retains the original
vulnerability, project context and suggested fixes. Paths are target-relative.
An exact Git revision or path from the repository root requires other evidence.
[Native result fields](https://github.com/snyk/cli/blob/main/src/lib/snyk-test/legacy.ts)

### Snyk plugin export

Install the Snyk plugin in Codex and sign in to Snyk. From the repository's
Git root, ask Codex to use `snyk-findings-export` to run an SCA-only scan and
write its export to a file outside the checkout.

```sh
codex plugin marketplace add snyk/studio-recipes
codex plugin add snyk@snyk-studio-recipes
```

Use the saved bundle as `report` and a source key ending in `plugin-sca`.
Check its coverage and limitations. The bundle retains collection context,
ignored status and each selected MCP record. The MCP mapper can shorten
descriptions and omit alternate dependency paths. Its paths are relative to
the scan target. A dirty workspace does not establish an exact scanned commit.
[Official Snyk plugin](https://github.com/snyk/studio-recipes/tree/main/plugins/codex)
and [SCA mapper](https://github.com/snyk/studio-mcp/blob/main/internal/oss/map.go)

### SARIF compatibility

For Open Source SARIF, use `--sarif-file-output` instead of `--json-file-output`
and handle exit codes as above. Use a source key ending in `sarif-sca`.
SARIF groups an advisory's occurrences and exposes one package coordinate.
The reader retains the rule, result and report context. It accepts direct
manifest paths and self-contained reports. Indexed or base-relative manifest
locations and external property files are unsupported.
[Snyk Open Source SARIF formatter](https://github.com/snyk/cli/blob/main/src/lib/formatters/open-source-sarif-output.ts)

### Identities and provenance

Use a separate source key for each acquisition format because each produces
different source IDs. For a given repository and source key, a new ID creates a
record. A changed evidence snapshot updates its version. For example, changing
a plugin scan's `issueCount` can update records whose underlying occurrence
stayed the same. Identical evidence is counted as `unchanged`. Omitting a record
from a later report leaves it stored. The native CLI's `uniqueCount` counts
distinct vulnerabilities across dependency paths. [Imported evidence and identity](schema-guide.md)
and [Snyk count definition](https://github.com/snyk/cli/blob/8b2d0a695c6b1b31f681e32039db958fba6f0c2f/src/lib/snyk-test/run-test.ts#L555)

Known source Git URLs must match a comparable configured Git remote when one
is available locally, or the selected Cloud repository. Use the preview's exclusions to identify skipped
records, including unsupported products and licenses. Snyk Code, Container,
IaC, SBOM results and hosted backlog responses are outside this file import.
