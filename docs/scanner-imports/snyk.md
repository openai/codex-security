# Snyk finding imports

Vendor finding import and readback require `CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS=1`.
See the [opt-in instructions](../../sdk/typescript/docs/cli.md#import-vendor-findings-locally)
and [how saved scanner reports map to imported evidence](schema-guide.md).

## Hosted Open Source and Code

Read issues from one monitored project with a regional `SNYK_TOKEN` in the
environment. Snyk requires Enterprise API access and the token permissions
`org.read`, `org.project.read` and `org.project.snapshot.read`.
[API authentication](https://docs.snyk.io/developer-tools/snyk-api/authentication-for-api)
and [Issues API](https://docs.snyk.io/developer-tools/snyk-api/reference/issues).

To collect Open Source issues, set `ORG_UUID` and `PROJECT_UUID` to the
organization and manifest project IDs. Supply the project's HTTP(S) Git URL.

```sh
codex-security import snyk "$PROJECT_UUID" --snyk-org "$ORG_UUID" \
  --source-repository-url https://github.com/example/project \
  --format json > snyk-hosted.json &&
codex-security publish findings snyk-hosted.json --provider snyk --to local \
  --repository ./project --source-key "$ORG_UUID/$PROJECT_UUID/open-source" --dry-run
```

For Code, use the `sast` project's ID, add `--snyk-product code` and choose a
separate source key. The default API origin is `https://api.snyk.io`. Use
`--snyk-api-origin` for `https://api.us.snyk.io`, `https://api.eu.snyk.io` or `https://api.au.snyk.io`.
Before sending `SNYK_TOKEN`, the collector checks the selected region against
the first enabled endpoint in [Snyk's REST configuration order](https://github.com/snyk/cli/blob/5f54805f14097c22cb13f11e064247c3c522dcda/src/lib/config/index.ts#L45-L60).
From highest to lowest priority, the settings are
`API_V3_URL`, `SNYK_API_V3_URL`, `API_REST_URL`, `SNYK_API_REST_URL`,
`SNYK_API`, then `SNYK_CFG_ENDPOINT`. Snyk requires the exact uppercase names
`SNYK_API_V3_URL` and `SNYK_API_REST_URL` even on Windows. A literal
`false` or `FALSE` disables either override. Other values expand `${NAME}`
references once from the caller's environment. For example,
when a REST override points to Europe and the general endpoint points to the US, select
`--snyk-api-origin https://api.eu.snyk.io`. If the region is saved only in
the Snyk CLI configuration file, select it explicitly here as well.
When a Snyk user or service access token carries an API host, that host must
also match the selected region, including for tokens supplied through the SDK.

The collector checks the selected repository URL against the project target
when Snyk supplies one. Standard Git SSH targets can match HTTPS repository
URLs on GitHub.com, GitHub Enterprise Cloud (`*.ghe.com`), GitLab.com, and
Bitbucket.org. A custom GitHub Enterprise host also requires GitHub SCM
provenance from the Snyk project. When a separately fetched target identifies
its integration, an SCM project requires a supported integration from the same
provider family, such as GitHub Enterprise and its GitHub Server App.
On custom hosts, keep the exact `.git` suffix spelling unless the project
supplies a matching target URL from its GitHub Enterprise or GitLab integration.

For Open Source projects, Snyk CLI can record a local Git path and a hosted
repository as the same HTTP target. The importer rejects these ambiguous
targets during collection and saved-report replay. Set the project's target
explicitly with
[`snyk monitor --remote-repo-url=https://git.example.test/team/repo.git`](https://docs.snyk.io/developer-tools/snyk-cli/commands/monitor#--remote-repo-urlurl)
and collect a new export. When Snyk supplies no target URL, the collector
uses the repository selected with `--source-repository-url`.

The collector uses Snyk REST version `2026-03-25` and reads every page of open
and resolved issues for that project and product, including ignored issues.
The SDK's `collectSnykIssues` returns the same `snyk-rest-issues/v1` report. `normalizeSnykIssues` and `readSnykFindings`
can replay it offline. The export preserves [exact numeric values and their types](schema-guide.md#numeric-fields-in-hosted-exports). Keep the same source key across exports. The importer
uses Snyk's issue key within the API origin, organization, project and product
to identify updates. Duplicate keys in one export are excluded. When preparing
a REST export yourself, keep the UTC marker or offset in `updated_at` so replay
uses the same timestamp in every time zone.

On HTTP 429, the collector retries the same GET once if `Retry-After` specifies
a wait of 10 seconds or less, in whole seconds or as an HTTP date. Zero or a
past date triggers an immediate retry. Cancellation stops the wait.

Native evidence retains issue status, ignored state and coordinates. Package
versions or Code locations are projected only when the issue and coordinate
are both open. Code regions retain Snyk's original line numbering. Missing
records on a later import leave earlier occurrences in place.

## Local Open Source scans

Use the [official Snyk Codex plugin](https://github.com/snyk/studio-recipes/tree/main/plugins/codex)
to collect a fresh workspace scan. The existing
[`publish findings` command](../../sdk/typescript/docs/cli.md#import-snyk-open-source-findings)
accepts its `snyk-findings-export/v1` bundle with `--provider snyk` for local
storage or Cloud publication. For CLI automation, prefer native JSON from
`snyk test`; Open Source SARIF remains a compatibility input.

**Local scan scope: Open Source SCA vulnerabilities only.** License findings,
Snyk Code, Container, IaC and SBOM results are outside these three local scan
formats. License records in otherwise supported reports appear as explicit
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

## Identities and provenance

All collection formats support either destination, but their source IDs differ. Use
one acquisition format consistently for a repository, branch and scan target,
with a stable source key. Use a separate key if switching formats; the importer
does not guess equivalence between plugin occurrences, native JSON occurrences
and SARIF advisory groups, or between workspace scans and hosted Issues.
Switching does not remove earlier imported records.

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
