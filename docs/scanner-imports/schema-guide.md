# How saved scanner reports map to imported evidence

The **reader** selected by `publish findings --provider` interprets a saved
scanner export. Acquisition produces the artifact:
for example, `snyk test` scans a workspace, while `codex-security import github`
retrieves selected code-scanning alerts. File ingestion reads the saved report.
Use the mappings to decide what one record represents, whether a later export
updates it, and what evidence a consumer can use. For setup and confirmation,
see
[import vendor findings locally](../../sdk/typescript/docs/cli.md#import-vendor-findings-locally).

## Choose the record and source key

For private Cloud imports, the identity is the importing owner, provider,
source key and vendor occurrence ID. Keep the source key stable across retries
and unique to the vendor project or repository in which occurrence IDs are
unique. Choosing a different assessment target does not create another source
identity. The CLI sends the reviewed selection as `security.findings.v1` and
reports a private import-job receipt. A canonical finding ID becomes available
after explicit Cloud assessment and publication.

A stored source record is scoped to **destination repository + provider + source
key + source finding ID**. Choose the key for the stream you intend to replay,
not the export date. A CVE or GHSA names an advisory; a CWE or rule ID describes
a class of issue. Neither identifies a particular installed dependency, code
location, or affected asset. Matching titles, packages or advisories are reasons
to investigate records together, not instructions to merge them.

| Reader and accepted input                                                                                                                                                                           | Source finding ID basis                                                                                                                                 | Keep the source key stable for             |
| --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------ |
| [Wiz package JSON or detailed CSV](../../sdk/typescript/docs/cli.md#package-vulnerability-inputs); CSV requires `CloudPlatform=GitHub` and `CloudProviderURL` for a GitHub repository `/tree/<ref>` | Vendor occurrence `id` (CSV: `ID`), not the CVE                                                                                                         | Tenant and finding family                  |
| [Wiz named repository collections](../../sdk/typescript/docs/cli.md#sast-repository-secrets-and-iac-inputs)                                                                                         | `sast:<id>`, `secret:<id>`, `iac:<id>`                                                                                                                  | Tenant and finding family                  |
| [Endor Finding JSON or endorctl SARIF](endor.md)                                                                                                                                                    | Finding `uuid` or SARIF `properties["finding-uuid"]`                                                                                                    | Namespace, project and context             |
| [Amazon Inspector Code Security ListFindings JSON](inspector.md)                                                                                                                                    | Full Inspector finding ARN                                                                                                                              | AWS account, Region and repository project |
| [Snyk Open Source CLI JSON, plugin v1 or SARIF](snyk.md)                                                                                                                                            | CLI: manager, manifest, advisory, package/version and dependency path; plugin: supplied composite; SARIF: advisory, manifest set and project when known | Repository, branch, scan target and format |
| [Semgrep Code CLI/CI JSON or SARIF](semgrep.md)                                                                                                                                                     | Fingerprint; otherwise rule, literal path and start/end lines and columns                                                                               | Organization, project and branch           |
| [SonarQube Cloud capture or native issue-search pages](sonar.md)                                                                                                                                    | Sonar issue key                                                                                                                                         | Cloud instance, org, project and ref       |
| [GitHub Dependabot repository REST alerts](github-dependabot.md)                                                                                                                                    | Host, repository and alert number                                                                                                                       | Host, repository and Dependabot family     |
| [GitHub saved `import github` output](../../sdk/typescript/docs/cli.md#import-github-findings-locally-or-to-cloud)                                                                                  | Host, repository, alert number and hash of selected ref                                                                                                 | Host, repository and code-scanning family  |
| [GitHub saved `import github-advisories` output](../../sdk/typescript/docs/cli.md#import-ghsa-advisories-separately)                                                                                | Host, repository **or** global scope, and GHSA ID                                                                                                       | Separate advisory stream from alerts       |
| [Black Duck BOM-6 collection or selected rows](blackduck.md)                                                                                                                                        | Project version, component version, origin, advisory source and advisory name                                                                           | Deployment, project and version            |
| [Veracode Static Analysis Findings API pages](veracode.md)                                                                                                                                          | API origin, application and context, and native issue ID                                                                                                | Deployment, application and static policy  |

Within **one input**, duplicate IDs are ambiguous, not corroboration. Wiz and
GitHub reject a selection with duplicate accepted IDs. Endor, Snyk and Semgrep
exclude every record with the colliding identity. Black Duck rejects duplicate occurrences in a complete collection, and excludes all colliding rows in an explicit selection.
Veracode rejects a capture that repeats an issue ID for the same scan type.
Inspect the source and select
the intended occurrence; don't rename records simply to make them import. Across
**separate local imports**, changed evidence updates the same record; omission
does not delete or resolve it. Cloud publication sends an expected version;
resuming a saved request keeps that value. An item error such as
`version_conflict` or `stale_source_snapshot` can reject an update instead of
replacing a newer report. Inspect the item error and current source report
before preparing a fresh submission.

## Interpret the provider evidence

- **Wiz:** `detailedName`, version, advisory and fixed version describe a
  package occurrence. Repository-branch paths can be manifests; container paths
  cannot. JSON prefers `vendorSeverity` over `severity`; repository CSV uses
  `Severity`, then `VendorSeverity`, then `CVSSSeverity`. Keep named
  `sastFindings`, `secretInstances` or `iacFindings` nodes with a repository URL
  or matching inventory. SAST can map a range, snippet, CWE and vendor verdict;
  repository secrets map detector and validation metadata, not a scanned
  revision from the introduced commit; IaC maps expected/actual configuration,
  not proof of deployment. The Wiz file reader does not map workload secrets,
  cloud configuration or external network scans. It also accepts explicitly
  normalized JSONL: supply the reviewed `source_finding_id` and `evidence`,
  retaining the raw row. The reader does not infer a mapping for other CSV
  profiles.
- **Amazon Inspector.** Supply a complete export for one repository project.
  A matching native URL or the operator's full project ARN mapping establishes
  the Git host. Local import and Cloud replay check the destination again.
  Each finding ARN identifies one occurrence. Duplicate ARNs exclude all
  colliding rows. Package and code evidence retain the native finding.
- **Endor Labs:** Prefer a complete native Finding, array or `list.objects`.
  `spec.level`, dependency paths/versions, advisory aliases, source SHA and
  primary SAST/AI SAST locations map when present. The project UUID does not
  verify the repository. Proposed upgrades, reachability and dismissals remain
  source claims. SARIF keeps the rule/result and direct locations but reports
  `unknown` severity, not CVSS or diagnostic level. Importing SARIF over native
  JSON for the same UUID **replaces**, rather than enriches, its snapshot.
- **Snyk CLI, plugin and Open Source SARIF:** Prefer ungrouped native
  `snyk test` JSON for package versions,
  dependency chains, advisory aliases and fix advice. A different dependency
  path can be another occurrence of the same advisory. Plugin evidence can be
  abbreviated; SARIF groups occurrences. Scan-target-relative manifests are not
  Git-root locations, and a synthetic SARIF line 1 is not a code finding. The
  formats do not reconcile their IDs. Licenses, Code, Container, IaC and
  platform backlog are outside these Open Source file formats.
- **Semgrep Code CLI and SARIF:** Supply `--source-repository-url` for these
  file formats. JSON `extra.fingerprint` or
  SARIF `matchBasedId/v1` survives a location change; without a usable
  fingerprint, a move creates a new record. Use the mapped rule, range, snippet
  and CWE to locate code. Ignored/suppressed is source state. JSON distinguishes
  Critical from High; both become diagnostic `error`, mapped to High, in Semgrep
  SARIF. Inspect the selected result for trace/fix details. Platform/MCP
  envelopes and general Supply Chain/Secrets feeds are not Code CLI or SARIF exports.
- **OpenGrep.** Use native JSON and supply `--source-repository-url`. The
  [OpenGrep guide](opengrep.md) covers export and occurrence identity.
- **SonarQube Cloud.** Use [the Sonar import workflow](sonar.md) to capture
  security issues for one project and branch or PR through the authenticated
  Sonar CLI. Keep the capture to import and publish the same native evidence.
  The issue key identifies the occurrence. The rule identifies the check that
  raised it.
- **GitHub:** For code scanning, the selected instance supplies path/range, ref
  and commit. The rule's `security_severity_level` supplies severity; diagnostic
  `error` alone means `unknown`. An alert-wide dismissal takes precedence over
  instance state. For GHSA, a repository disclosure identifies its publisher; a
  global disclosure has no source repository. Both can carry CVE aliases,
  affected ranges and patched versions. Neither proves installation or
  applicability. Both readers require saved collector output.
- **GitHub Dependabot.** Use `gh api --paginate` to save native repository
  alert pages as JSONL for the `github` reader. Each alert identifies the
  matched package, manifest and vulnerable range. The embedded advisory supplies advisory IDs.
  Each alert number has its own history, including when several alerts cite the
  same GHSA. GitHub secret-scanning alerts remain outside the file reader.

## Read the right field

- The
  [evidence schema](../../sdk/typescript/schemas/external-findings.schema.json)
  separates the source ID from `evidence`. Its required `title` and `severity`
  are reported evidence, not a Codex rating. Severity is one of `critical`,
  `high`, `medium`, `low`, `informational`, or `unknown`; source status,
  confidence, verdicts and fix advice do not change `assessment.state`.
- `packages[].installed_version` is an observation; `vulnerable_version_range`
  is a claim about affected versions; `fixed_versions` is source guidance. Use
  `locations[].path/line` for repository navigation and optional
  `details.code.end_line` for the first location. Missing evidence stays
  missing; don't fill in a commit from the current checkout.
- Optional `details.kind` is **not** a universal scanner taxonomy. Its values
  are `sast`, `secret`, `iac` and `advisory`. Package occurrences from Wiz/Snyk
  and native Endor findings use top-level fields without requiring a kind. For
  an advisory, inspect `details.advisory.source`, not the chosen destination, to
  distinguish repository and global scope.
- Use `source_data` to inspect what the reader actually received: e.g. a Wiz
  row, Endor Finding, Snyk vulnerability plus project context, Semgrep result or
  GitHub collector envelope. It's selected evidence, not necessarily the whole
  export: unrelated scan inventories can be omitted and plugin or SARIF output
  may already be lossy. Retain the input privately if collection scope matters.

## Operate the two destinations

Local readback returns `sourceKey`, `sourceFindingId`, `version`, `evidence` and
`assessment` alongside the local record ID. The Cloud publisher sends
`source.provider` and `source.source_key` with an expected version, source
finding ID and evidence for each item. Receipt IDs for the source report,
observation and canonical finding are **destination** references, not vendor
occurrence IDs. Use the source report for evidence, not the receipt counts.

**One project, local triage.** From a checkout with a saved native Snyk report
outside it:

```sh
export CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS=1
codex-security publish findings ../reports/snyk.json --to local --provider snyk \
  --repository . --source-key example/project/main/root/native-sca --dry-run --format json
```

Check the selected repository, IDs, evidence and exclusions. Repeat without
`--dry-run` and confirm; then run
`codex-security findings imported . --format json`. Workbench SQLite stores the
snapshot and version. Repeating identical evidence is unchanged. A source
repository claim is checked against configured remotes when available; when
provenance is absent you must verify the target yourself. These records remain
`not_assessed`, separate from `findings list` and completed scans. To
investigate, compare the reported installed version or location against the
selected revision; import alone is not validation.

**Many repositories, reviewed publication.** Partition complete exports by
repository and source namespace first; don't attach a fleet-wide export to one
destination. For example, preview one Endor project and context against its
connected repository:

```sh
codex-security publish findings ../reports/endor-project-main.json --to cloud \
  --repository https://github.com/example/project --provider endor \
  --source-key example-namespace/example-project/main --dry-run --format json
```

This reads authorized destination state; it doesn't upload. Check the account,
repository, environments, eligible records and exclusions before confirming.
Local file imports do not apply the Cloud evidence limits. Cloud limits include
256 KiB per finding, depth 20 and 5 MiB per request; an oversized record is
excluded, not truncated. For example, 240 eligible findings for one destination
require at least three requests at the 100-item ceiling, possibly more for size
or environment boundaries.

Read the
[result and recovery contract](../../sdk/typescript/docs/cli.md#results-and-exit-codes):
`partial` (exit 1) can include acknowledged records alongside exclusions or item
errors. Correct the rejected records; do not treat the whole selection as
failed. After `interrupted` (exit 2), a lost response is **not** proof of
rejection. A reset can also fail during preparation. Inspect the error,
receipts, cumulative counts and unacknowledged items before choosing how to
recover:

- **`savedSubmission` identifies an existing checkpoint:** rerun the same
  approved command with unchanged input, source key, destination and endpoint to
  resume its saved requests. This also applies if the initial request was saved
  but persisting a later receipt failed.
- **No resumable checkpoint:** a repository reset retires the old request, and
  an initial checkpoint-write failure may leave no request to resume. Inspect
  the destination and correct the error; run a fresh `--dry-run` and get fresh
  approval before publishing. Do not blindly replay a command containing
  `--yes`.

Verified source-report readback is evidence of import, not a security
assessment, UI visibility or a vendor state change.

**Privacy.** Reports, full JSON previews, local state and saved Cloud request
bodies can contain source snippets, secret metadata, internal paths, private
advisories and vendor links. Select only authorized metadata (not credential
values), keep artifacts outside the checkout with restricted access and review
the destination before uploading. Don't paste raw evidence or checkpoints into
public tickets, CI logs or PRs. The readers do not promise to redact them.
