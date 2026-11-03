# Import Snyk Open Source findings

Prefer native `snyk test` JSON for dependency vulnerabilities. It keeps
individual dependency paths and remediation details. You can also import a
`snyk-findings-export/v1` plugin bundle or self-contained Open Source SARIF.

## Quick start

[Enable external imports](README.md#preview-a-report). From the checkout root,
set the destination and choose a key for the repository, branch, original scan
target and format. Replace `root` with your target if you scanned a
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
record. The mapper can shorten descriptions and omit alternate dependency
paths. Paths are relative to the scan target. The reader records a commit
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

## Identities and provenance

Native JSON, plugin bundles and SARIF produce different source IDs. Give
each format a separate source key. A change in collection context, such as a
plugin scan's `issueCount`, can update a stored snapshot of the same
occurrence. [Imported evidence and identity](schema-guide.md)

Known source Git URLs must match a comparable local remote when available,
or the selected Cloud repository. Snyk Code, Container, IaC, SBOM results
and hosted backlog responses use other formats.
