# Import Snyk Open Source findings

Import dependency vulnerabilities from a saved `snyk test` JSON report, a
`snyk-findings-export/v1` plugin bundle or self-contained Open Source SARIF.
Native CLI JSON preserves individual dependency paths and remediation details.

## Quick start

[Enable external imports](README.md#preview-a-report). For a first local import,
set the destination from the checkout root. Choose a key for the repository,
branch, original scan target and format. If you ran Snyk in `services/api`,
replace `root` in the example key with `services/api`.

```sh
snyk_repository=$(pwd -P)
snyk_source_key=github.com/example/project/main/root/native-sca
```

For a repeat import, set `snyk_repository` and `snyk_source_key` to the
previous local preview's exact `repository` and `source.source_key`. Keep the
original destination even if it was a package subdirectory. Changing either
value creates a separate set of records.

Set `snyk_report` to the absolute path of your saved, ungrouped Open Source
JSON report so it still resolves if you change directories.

```sh
snyk_report=/path/to/reports/snyk-open-source.json
```

If you need a new report, [run the Snyk CLI](#native-cli-json) and keep the
`snyk_report` it sets. Preview the selected report.

```sh
codex-security publish findings "$snyk_report" --to local --repository "$snyk_repository" \
  --provider snyk --source-key "$snyk_source_key" \
  --dry-run --format json
```

## Import and verify

Review coverage and exclusions, especially unsupported products and license
records. Check the destination checkout when the report lacks a Git URL.
[Save or publish and verify](README.md#save-or-publish-and-verify) with the
same source key for subsequent exports in this format.

## Reference

### Native CLI JSON

To create a report, run the authenticated Snyk CLI with the project's package
tooling. For a project with `package.json`, run this from its root. Exit 1
means findings. A higher exit code stops acquisition. [Snyk CLI test](https://docs.snyk.io/developer-tools/snyk-cli/commands/test)

```sh
snyk_report=
report_dir=$(mktemp -d) || exit "$?"
snyk_status=0
snyk test --file=package.json --json-file-output="$report_dir/snyk-open-source.json" || snyk_status=$?
if [ "$snyk_status" -gt 1 ]; then
  exit "$snyk_status"
fi
snyk_report="$report_dir/snyk-open-source.json"
```

For several projects under one scan root, use `--all-projects --fail-fast`
in place of `--file=package.json`. Without `--fail-fast`, Snyk can omit
projects it could not scan. Project errors present in the input stop import.
Keep independent scan roots in separate reports with separate keys.

A native occurrence is identified by package manager, manifest, advisory,
package name and version, and dependency path. The reader retains the
vulnerability, project context and suggested fixes. Manifest paths are
target-relative. [Native result fields](https://github.com/snyk/cli/blob/main/src/lib/snyk-test/legacy.ts)

### Snyk plugin export

From the repository's Git root, ask the Snyk plugin's `snyk-findings-export`
skill to run an SCA-only scan and save the bundle outside the checkout.
Use the bundle as input and a key ending in `plugin-sca`. The bundle retains
collection context, ignored status and each selected MCP record. The mapper
can shorten descriptions and omit alternate dependency paths. Paths are
target-relative. A dirty workspace does not establish the scanned commit.
[Install the Snyk plugin](https://github.com/snyk/studio-recipes/tree/main/plugins/codex)
and [SCA mapper](https://github.com/snyk/studio-mcp/blob/main/internal/oss/map.go)

### SARIF compatibility

For SARIF, replace `--json-file-output` with `--sarif-file-output` and keep the
exit-code check above. Use a key ending in `sarif-sca`. SARIF groups an
advisory's occurrences and exposes one package coordinate. The reader
retains the rule, result and report context. Use a self-contained report. Manifest paths are
optional. If present, use direct URIs. Indexed or base-relative manifest
locations are unsupported. [Snyk Open Source SARIF formatter](https://github.com/snyk/cli/blob/main/src/lib/formatters/open-source-sarif-output.ts)

### Identities and provenance

Native JSON, plugin bundles and SARIF produce different source IDs. Give
each format a separate key. Changes in collection context such as a plugin
scan's `issueCount` can update a stored snapshot even if the occurrence
stays the same. [Imported evidence and identity](schema-guide.md)

For native tests of a public GitHub URL, the reader checks the repository in
the report's `path` against the selected destination. Any `#ref` stays in the
saved source evidence.

Known source Git URLs must match a comparable configured local remote when
one is available, or the selected Cloud repository. Snyk Code, Container,
IaC, SBOM results and hosted backlog responses use other formats.
