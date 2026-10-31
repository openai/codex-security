# Import Snyk findings

Vendor finding import and readback require `CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS=1`.
See the [opt-in instructions](../../sdk/typescript/docs/cli.md#import-vendor-findings-locally)
and [how saved scanner reports map to imported evidence](schema-guide.md).

## Existing issues from Snyk

To import a monitored project's existing issues into the local workbench, set
`SNYK_TOKEN` to a read-authorized token for the selected region. See the
[Snyk API access requirements](https://docs.snyk.io/developer-tools/snyk-api/authentication-for-api)
and [Issues API permissions](https://docs.snyk.io/developer-tools/snyk-api/reference/issues).
Select the organization ID, project ID and source repository URL. Open Source
is the default. For a Snyk Code project, add `--snyk-product code`. For a
regional deployment, set `--snyk-api-origin` to its documented API origin.

Run the commands from a trusted directory outside the project checkout. The
example saves the report there and imports it into the checkout at `./project`.

```sh
codex-security import snyk PROJECT_ID --snyk-org ORG_ID \
  --source-repository-url https://github.com/example/project \
  --format json > snyk-issues.json &&
codex-security publish findings snyk-issues.json --to local --provider snyk \
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
the monitored project for a row that retains only its original issue. For a v1
row, keep `source_data.issue` and its `source_data.numericFields.issue` when
present. V1 uses those fields together to distinguish exact numbers from
strings with the same spelling. For a v2 row, keep `source_data.issueJson`.
The local workbench stores the verified project and target with that issue,
so the stored row can be imported again. All selected issues must share an API
region, organization, project and product.

SDK readers that define their own findings and IDs can use the ordinary
normalized Snyk import with their own evidence and no hosted report context.

For private source-control hosts, use the same repository URL as the checkout.
SDK callers that have independently verified a GitHub Enterprise or GitLab
repository can pass its canonical HTTPS URL and platform to the local importer.
This allows that repository's standard SSH clone URL and `.git` suffix. For
example, a GitLab repository uses
`sourceRepositories: [{ url: sourceRepositoryUrl, platform: "gitlab" }]`
in the SDK dependencies. Use `platform: "github"` for GitHub Enterprise.
When reading the saved file directly, pass the same verified sources as the
third argument to `readSnykFindings(path, "local", sourceRepositories)`.

## Fresh Open Source scans

Use the [official Snyk Codex plugin](https://github.com/snyk/studio-recipes/tree/main/plugins/codex)
to collect a fresh workspace scan. The existing
[`publish findings` command](../../sdk/typescript/docs/cli.md#import-snyk-open-source-findings)
accepts its `snyk-findings-export/v1` bundle with `--provider snyk` for local
storage or Cloud publication. For CLI automation, prefer native JSON from
`snyk test`; Open Source SARIF remains a compatibility input.

The workspace scan formats below cover Open Source SCA vulnerabilities. License records in otherwise supported reports appear as explicit
exclusions; they are not imported as vulnerabilities.

```sh
codex plugin marketplace add snyk/studio-recipes
codex plugin add snyk@snyk-studio-recipes
```

Ask Codex: “Use snyk-findings-export to export SCA findings from this repository’s Git root to
snyk-findings.json. Run SCA only.” The plugin uses the local Snyk MCP server and
needs Snyk authentication and the package tooling required by the project. Check
its scan coverage and limitations before importing. Preview local storage with a
repository path; no Cloud login is required:

```sh
codex-security publish findings snyk-findings.json --to local \
  --provider snyk --repository ./project \
  --source-key github.com/example/project/main/root/plugin-sca --dry-run
```

Or preview publication to a connected Cloud repository:

```sh
codex-security publish findings snyk-findings.json --to cloud \
  --provider snyk --repository https://github.com/example/project \
  --source-key github.com/example/project/main/root/plugin-sca --dry-run
```

Remove `--dry-run` from the selected command to review and confirm the import.
The existing `--yes` option allows an already approved, noninteractive import.
Read local records with `codex-security findings imported ./project --format json`.
See the common [local import flow](../../sdk/typescript/docs/cli.md#import-vendor-findings-locally)
or [Cloud publication flow](../../sdk/typescript/docs/cli.md#import-wiz-findings)
for destination requirements, confirmation and result handling. The publisher
imports the saved evidence; it does not start another Snyk scan or assessment.

This adapter imports Open Source SCA vulnerabilities. Other products, licenses
and SBOM results in a mixed plugin bundle appear as exclusions. It preserves the
complete selected finding, native MCP record, collection context, availability
states and coverage limitations. Ignored status remains source evidence; it does
not mark the finding fixed or assessed locally or in Cloud. A dirty workspace retains its
revision in the original evidence without claiming it as the exact scanned commit.

The MCP output is a projection: its SCA mapper shortens descriptions and can omit
alternate dependency paths. The plugin cannot recover data its MCP server did
not return. See the [official SCA mapper](https://github.com/snyk/studio-mcp/blob/main/internal/oss/map.go).
The bundle's composite occurrence identity includes package version and dependency
path. Keep the same source key for each repository, branch and scan target across
exports. A change to the composite identity produces a new source ID; changing
only the evidence preserves that ID. Plugin v1 paths are relative to the scan
target and do not carry its Git-root offset. They remain in original evidence
without being projected as repository locations or package manifest paths.

### How to read import counts

For the same repository and source key, `created` means a new source identity.
For an existing identity, `updated` means the whole evidence snapshot changed;
`unchanged` means it did not. These counts describe imported Snyk evidence, not
new vulnerabilities, fixes, or Codex assessments.

Each plugin finding retains its collection context. If a scan's `issueCount`
falls from three to two, both remaining findings can get a new version even if
neither occurrence changed. Their source IDs stay the same, and omitting the
third finding does not close it. Native CLI JSON likewise retains the project's
[`uniqueCount`](https://github.com/snyk/cli/blob/8b2d0a695c6b1b31f681e32039db958fba6f0c2f/src/lib/snyk-test/run-test.ts#L555)
when supplied. It counts distinct vulnerabilities, not dependency-path
occurrences: two paths to the same advisory contribute one to the count.
Keep the original evidence; do not edit or strip scan metadata to suppress updates.

### Native CLI JSON

For automation, use the [Snyk CLI](https://docs.snyk.io/developer-tools/snyk-cli/commands/test)
with `--json-file-output`. This preserves native descriptions, dependency paths,
identifiers and remediation evidence before the MCP or SARIF projections. For
example, run from the selected repository root:

```sh
snyk_status=0
snyk test --file=package.json --json-file-output=snyk-open-source.json || snyk_status=$?
if [ "$snyk_status" -gt 1 ]; then
  exit "$snyk_status"
fi
codex-security publish findings snyk-open-source.json --to cloud \
  --provider snyk --repository https://github.com/example/project \
  --source-key github.com/example/project/main/root/native-sca --dry-run
```

Snyk exits 1 when it finds vulnerabilities. Other failures must stop acquisition;
do not publish an older report after a failed scan. `snyk test --json` emits the
same result to stdout. A single project object and the array produced by
`--all-projects` under one scan root are supported. For multiple projects, replace
`--file=package.json` with `--all-projects --fail-fast` and keep the exit-code
handling above. Snyk's [`--fail-fast` option](https://github.com/snyk/cli/blob/main/help/cli-commands/test.md#--fail-fast)
stops the scan when a project fails. Without it, Snyk continues and omits
vulnerability results for projects it could not scan. Keep independent scan roots
in separate reports and source keys; identical manifest and dependency paths from
different roots otherwise have ambiguous identities. A project error in the
supplied JSON stops the import, including an error mixed with successful results.
A successful empty scan has zero findings; a license-only report instead lists
its records as exclusions. Use the default ungrouped JSON output;
`--group-issues` combines package and dependency-path fields and is not supported.

The mapper follows the CLI's [native result types and dependency-path producer](https://github.com/snyk/cli/blob/main/src/lib/snyk-test/legacy.ts).
It preserves the complete selected vulnerability and the surrounding project
context. Identity uses the package manager, literal display manifest (falling back
to the target file), advisory, package name/version and dependency path. Different
occurrences remain separate. A duplicate identity is excluded rather than merged.
Native JSON does not establish a Git-root offset, repository URL or exact scanned
revision: paths and scan context stay in original evidence, without being claimed
as repository locations or manifest paths. Suggested upgrades and fixed versions
remain source advice, not verified patches.

To store this JSON locally, use the same file, provider and source key with
`--to local --repository .` from the repository root. No Cloud login is required.

### SARIF compatibility

Existing Open Source SARIF exports are still accepted. Generate one with
`snyk test --file=package.json --sarif-file-output=snyk-open-source.sarif` and
handle the exit code as above. For multiple projects, use `--all-projects --fail-fast`
with the same exit-code handling. Import with `--provider snyk` and a stable source
key ending in `sarif-sca`. The mapper follows the
[Open Source SARIF formatter](https://github.com/snyk/cli/blob/main/src/lib/formatters/open-source-sarif-output.ts).
It retains the selected rule, result and report context. Unrelated artifact
inventories are omitted when direct manifest locations do not depend on them;
indexed context and matching artifact metadata are retained. Empty
external-reference containers are accepted; reports with actual external property
references remain unsupported. SARIF groups an advisory's occurrences and exposes
one package coordinate, so native JSON is preferable for preserving individual
dependency paths and remediation fields. Manifest paths are literal target-relative
paths, including percent characters, without a Git-root offset. They stay in
original evidence with synthetic line numbers instead of being projected as
repository locations or package manifest paths. Snyk
Code, Container, IaC, external SARIF property files and indexed or base-relative
manifest locations are unsupported.

### Identities and provenance

All three formats support either destination, but their source IDs differ. Use
one acquisition format consistently for a repository, branch and scan target,
with a stable source key. Use a separate key if switching formats; the importer
does not guess equivalence between plugin occurrences, native JSON occurrences
and SARIF advisory groups. Switching does not remove earlier imported records.

Unsafe or absolute paths remain in original evidence. Known source repository
claims must match the selected Cloud repository or, for local imports when Git
remotes are configured, one of those remotes. For Cloud publication, standard SSH
remotes on the selected connected GitHub or GitHub Enterprise host match its HTTPS
repository when using the default SSH port or port 22. The public
`ssh://git@ssh.github.com:443/owner/repository.git` endpoint also matches
`github.com`. Other hosts, nondefault SSH ports and explicit HTTPS ports remain
distinct; the importer does not infer an Enterprise host from the artifact alone.
Unknown repository context requires the user to select the correct destination.
Gzip and UTF-8 BOM input are supported. Records exceeding the destination's
field or total-size limits appear as exclusions in the preview, without
truncation. Inspect preview exclusions before importing. Synthetic tests do
not establish live tenant, plugin-runtime or deployed Cloud compatibility.
