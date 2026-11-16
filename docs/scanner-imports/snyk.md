# Import Snyk findings

Prefer native `snyk test` JSON for dependency vulnerabilities. It keeps
individual dependency paths and remediation details. You can also import a
`snyk-findings-export/v1` plugin bundle or self-contained Open Source SARIF.

- **I have a file or want to scan my checkout.** [Preview a saved report](#quick-start).
  Choose a separate source key for each file format. [Native CLI JSON](#native-cli-json)
  · [Plugin export](#snyk-plugin-export) · [SARIF](#sarif-compatibility).
- **I need issues from a monitored project.** [Collect from Snyk](#existing-issues-from-snyk)
  with a read-authorized token. Both Open Source and Code projects are supported.

Both routes support local and Cloud imports.

## Quick start

From the checkout root, set the destination and choose a source key for the
repository, branch, original scan target and format. Replace `root` with your target if you scanned a
subdirectory such as `services/api`.

```sh
snyk_repository=$(pwd -P)
snyk_source_key=github.com/example/project/main/root/native-sca
```

For a repeat import, use the exact `repository` and `source.source_key` from
your earlier local preview, even if you used a package subdirectory as the
destination. Changing either value creates a separate set of records.

**Saved report.** Use an absolute path to the ungrouped Open Source JSON from
the scan you want to import.

```sh
snyk_report=/private/path/snyk-open-source.json
```

**Scan with Snyk.** To collect a new report, run the authenticated Snyk CLI
with the project's package tooling. From the directory containing
`package.json`, run this in the same shell. Snyk exits with 1 when it finds
vulnerabilities. A higher exit code stops the export.
[Snyk CLI test](https://docs.snyk.io/developer-tools/snyk-cli/commands/test)

```sh
snyk_report=$(
  snyk_dir=$(mktemp -d) || exit "$?"
  file="$snyk_dir/snyk-open-source.json"
  snyk_status=0
  snyk test --file=package.json --json-file-output="$file" >&2 || snyk_status=$?
  [ "$snyk_status" -le 1 ] || exit "$snyk_status"
  [ -s "$file" ] && printf '%s\n' "$file"
)
```

For several projects under one scan root, replace `--file=package.json` with
`--all-projects --fail-fast` so a scan failure stops collection. Without
`--fail-fast`, Snyk can skip projects. An error in a saved project result
stops import. Use separate reports and keys for independent scan roots.

**Preview the report.**

```sh
codex-security publish findings "$snyk_report" --to local --repository "$snyk_repository" \
  --provider snyk --source-key "$snyk_source_key" \
  --dry-run --format json
```

Check the expected advisories, package versions and excluded records,
especially license findings. If the report lacks a Git URL, confirm the
destination checkout yourself.
[Save locally or publish to Cloud and verify the result](README.md#save-or-publish-and-verify).

## Native CLI JSON

Package manager, manifest, advisory, package name and version, and dependency
path identify each native occurrence. The reader keeps the vulnerability,
project context and suggested fixes. Manifest paths are relative to the scan
target. For native tests of a public GitHub URL, the reader checks the
repository in the report's `path` against the destination. Any `#ref` stays
in the original evidence.
[Native result fields](https://github.com/snyk/cli/blob/main/src/lib/snyk-test/legacy.ts)

## Snyk plugin export

From the Git root, ask the Snyk plugin's `snyk-findings-export` skill to run
an SCA-only scan and save the bundle outside the checkout. Set `snyk_report`
to the bundle and use a key ending in `plugin-sca` for the preview. Like
`snyk test`, the skill scans the current workspace. To import an earlier scan,
use its saved report. Evo MCP's `query_issues` retrieves AI asset policy
violations.
[Install the plugin](https://github.com/snyk/studio-recipes/tree/main/plugins/codex) · [Studio export scope](https://github.com/snyk/studio-recipes/blob/3752dd05a462184dcce44af3c247f287b41e35de/plugins/codex/skills/snyk-findings-export/SKILL.md#L15-L20) · [Evo MCP tools](https://docs.snyk.io/agent-security/evo-by-snyk/platform-surfaces/evo-mcp-server#policies-and-issues)

The bundle keeps collection context, ignored status and each selected MCP
record. Use `evidence.advisory_ids` for the Snyk advisory and its CVE aliases.
The export can shorten descriptions and omit alternate dependency paths.
Paths are relative to the scan target. The reader records a commit
only for a clean workspace with a known revision.
[SCA mapper](https://github.com/snyk/studio-mcp/blob/main/internal/oss/map.go)

## SARIF compatibility

Replace `--json-file-output` with `--sarif-file-output` in the scan command
and keep the exit-code check. Use a source key ending in `sarif-sca`. Snyk
groups an advisory's occurrences and reports one package coordinate. The
reader keeps the rule, result and report context. Use self-contained SARIF
with direct URIs for any manifest locations. Indexed and base-relative
manifest locations are unsupported.
[Snyk Open Source SARIF formatter](https://github.com/snyk/cli/blob/main/src/lib/formatters/open-source-sarif-output.ts)

## Existing issues from Snyk

Set
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
  codex-security import snyk PROJECT_ID --org ORG_ID \
    --source-repository-url https://github.com/example/project \
    --format json > "$report" &&
  codex-security publish findings "$report" --to local --provider snyk \
    --source-key ORG_ID/PROJECT_ID --repository ./project --dry-run --format json
```

Check the repository, issue keys and exclusions. To save locally, repeat the
publish command without `--dry-run` and confirm.

To preview the saved issues in Cloud, use the same source key and an authorized repository:

```sh
codex-security publish findings "$report" --to cloud --provider snyk \
  --source-key ORG_ID/PROJECT_ID --repository https://github.com/example/project --dry-run --format json
```

Review the preview and repeat without `--dry-run` to publish. The original Snyk
project must match the selected Cloud repository. If Cloud accepted a request
but the response was lost, repeat the same command to resume the saved request.

Collection reads open and resolved issues across all pages, including ignored issues.
For Open Source it requests package vulnerabilities. For Code it requests code issues.
[Troubleshoot collection errors and rate limits](README.md#troubleshoot-semgrep-and-snyk-collection).

### Monitored project evidence and SDK selection

The SDK's `collectSnykIssues` defaults to Open Source and returns the same report.
Passing the configured `SNYK_TOKEN` explicitly retains its configured regional
API origin. Pass independently verified `sourceRepositories` in its
dependencies when a private repository uses an SSH target. The offline reader
`readSnykFindings(path, "local")` accepts the collector's `snyk-rest-issues/v2`
report for Snyk REST API version `2026-03-25`. Run the collector again to replace
an archived v1 export. The report preserves the original project and issue
evidence. Open Snyk Code issues from an SCM integration import repository file
paths and reported start lines. For resolved issues, closed coordinates, and
CLI- or API-monitored projects, read the original location from
`evidence.source_data.issueJson`.

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

For a new normalized SDK import, keep the original Snyk issue and project
evidence alongside its generated finding ID. If you build a projection without
that evidence, supply your own stable finding ID and the source repository URL.
An already approved, pending request resumes with its saved evidence.

## Identities and provenance

Native JSON, plugin bundles and SARIF produce different source IDs. Give
each format a separate source key. A change in collection context, such as a
plugin scan's `issueCount`, can update a stored snapshot of the same
occurrence. [Imported evidence and identity](schema-guide.md)

Known source Git URLs must match a comparable local remote when available,
or the selected Cloud repository. Plugin and SARIF reports can identify a
connected GitHub repository by its HTTPS or standard Git SSH clone URL.
For Snyk Code, use the
[monitored project collector](#existing-issues-from-snyk). Container, IaC and
SBOM results fall outside these import routes.
