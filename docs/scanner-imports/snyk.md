# Import Snyk findings

Import dependency vulnerabilities from a saved `snyk test` JSON report, a
`snyk-findings-export/v1` plugin bundle or self-contained Open Source SARIF.
Native CLI JSON preserves individual dependency paths and remediation details.

For existing monitored projects, collect Open Source or Code issues through the Snyk Issues API.

## Existing issues from Snyk

To import a monitored project's existing issues into the local workbench, set
`SNYK_TOKEN` to a read-authorized token for the selected region. See the
[Snyk API access requirements](https://docs.snyk.io/developer-tools/snyk-api/authentication-for-api)
and [Issues API permissions](https://docs.snyk.io/developer-tools/snyk-api/reference/issues).
Select the organization ID, project ID and source repository URL. Open Source
is the default. For a Snyk Code project, add `--snyk-product code`. For a
regional deployment, set `--snyk-api-origin` to its documented API origin.

Run the commands from a trusted directory outside the project checkout. The
example saves a fresh report there and imports it into the checkout at `./project`.

```sh
report=$(mktemp ./snyk-issues.XXXXXX) &&
  codex-security import snyk PROJECT_ID --snyk-org ORG_ID \
    --source-repository-url https://github.com/example/project \
    --format json > "$report" &&
  codex-security publish findings "$report" --to local --provider snyk \
    --source-key ORG_ID/PROJECT_ID --repository ./project --dry-run
```

Confirm the preview, then repeat the publish command without `--dry-run`.
Collection reads open and resolved issues across all pages, including ignored issues.
For Open Source it requests package vulnerabilities. For Code it requests code issues.
The SDK's `collectSnykIssues` defaults to Open Source and returns the same report.
Passing the configured `SNYK_TOKEN` explicitly retains its configured regional
API origin. Pass independently verified `sourceRepositories` in its
dependencies when a private repository uses an SSH target. The offline reader
`readSnykFindings(path, "local")` accepts `snyk-rest-issues/v1` and
`snyk-rest-issues/v2` reports from Snyk REST API version `2026-03-25`.
The collector writes v2 and preserves the original project and issue evidence.
For open Snyk Code issues from an SCM integration, both versions import
repository-relative paths from open coordinates. V2 also imports each
coordinate's reported start line when available. For resolved issues, closed
coordinates, and projects monitored through the CLI or API, read the original
location from `evidence.source_data.issue` in v1 or from the JSON text in
`evidence.source_data.issueJson` in v2.

On HTTP 429, the collector retries the same GET once if `Retry-After` specifies
a wait of 10 seconds or less, in whole seconds or as an HTTP date. Zero or a
past date triggers an immediate retry. Cancellation stops the wait.

Use the same source key on later imports. The issue key within the API
origin, organization, project and product identifies the finding. Replaying the
same evidence leaves the version unchanged. Whitespace, object key order and
equivalent JSON number spellings in v2 native records do not affect replay.
JSON strings remain distinct from numbers. Importing a different capture for
that issue updates the same row, even if the capture is older.

To select a subset in the SDK, filter the normalized report’s `findings`
array. Keep the report’s `snykRestContext` and each selected finding’s
`source_finding_id` and `evidence.source_data`. Every hosted row must retain
the native issue and its generated ID. The verified report context can supply
the monitored project for a row that retains only its original issue. The Cloud
preview includes the verified project and any captured target in the evidence it
will publish.

For a v1 row, keep `source_data.issue` and the original `source_data.numericFields`
when present. If you trim the metadata, keep its matching entries for every
`issue`, `project`, and `target` object you retain. V1 uses those entries to
distinguish exact numbers from strings with the same spelling. For a v2 row,
keep `source_data.issueJson`.
The local workbench stores the verified project and target with that issue,
so the stored row can be imported again. All selected issues must share the
report’s API region, organization, project and product. Keep SCM-integrated
findings separate from CLI- or API-monitored findings. If the report identifies
a native target or its repository URL, retain that evidence in the selected
project and target. Snyk’s optional integration relationship is retained when
the target supplies it.

SDK readers that define their own findings and IDs can use the ordinary
normalized Snyk import with their own evidence and no hosted report context.

The offline reader can interpret SCM aliases recorded in an archived project.
Local import compares the source to the checkout’s configured external Git
remotes. For a checkout with only filesystem remotes or none, the selected
directory is the import destination.
For private source-control hosts, use the same repository URL as the checkout.
SDK callers that have independently verified a GitHub Enterprise or GitLab
repository can pass its canonical HTTPS URL and platform to local or Cloud
preparation. Cloud checks that source against the selected repository.
This allows that repository's standard SSH clone URL and `.git` suffix. For
example, a GitLab repository uses
`sourceRepositories: [{ url: sourceRepositoryUrl, platform: "gitlab" }]`
in the SDK dependencies. Use `platform: "github"` for GitHub Enterprise.
When reading the saved file directly, pass the same verified sources as the
third argument to `readSnykFindings(path, "local", sourceRepositories)`.

To preview the saved issues in Cloud, use the same source key and an authorized repository:

```sh
codex-security publish findings "$report" --to cloud --provider snyk \
  --source-key ORG_ID/PROJECT_ID --repository https://github.com/example/project --dry-run
```

Review the preview and repeat without `--dry-run` to publish. The original Snyk
project must match the selected Cloud repository. If Cloud accepted a request
but the response was lost, repeat the same command to resume the saved request.

For a new normalized SDK import, keep the original Snyk issue and project
evidence alongside its generated finding ID. If you build a projection without
that evidence, supply your own stable finding ID and the source repository URL.
An already approved, pending request resumes with its saved evidence.

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

Use the saved report for an earlier scan. `snyk test` and the Studio plugin’s
`snyk-findings-export` scan the current workspace. Evo MCP’s `query_issues`
retrieves AI asset policy violations. [Studio export scope](https://github.com/snyk/studio-recipes/blob/3752dd05a462184dcce44af3c247f287b41e35de/plugins/codex/skills/snyk-findings-export/SKILL.md#L15-L20) · [Evo MCP tools](https://docs.snyk.io/agent-security/evo-by-snyk/platform-surfaces/evo-mcp-server#policies-and-issues)

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

Known source Git URLs must match a comparable configured local remote when
one is available, or the selected Cloud repository. Snyk Code, Container,
IaC, SBOM results and hosted backlog responses use other formats.
