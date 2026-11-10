# Import Wiz findings

Import Wiz package vulnerabilities, SAST findings, repository secrets or IaC
findings from native JSON or normalized JSONL. For repository package
vulnerabilities, you can also use a detailed CSV report. All three formats
support gzip.

## Quick start

This example imports package vulnerabilities from a repository branch.

**Saved report.** Choose the file for your repository and branch or build.
With a connected Wiz account, list findings for the repository and family,
then retrieve the selected records by Wiz finding ID. If a pull request
scan event omits occurrence IDs, request a native export of the selected findings. Raw Code & Build Scan events contain scan metadata. Summaries and Wiz Issues use different formats.

**Export from Wiz.** In **Vulnerability Findings**, filter by repository,
branch or build, and findings where available. Choose **Save as → Report**,
then **Repository Branch**, **JSON** and **Detailed** columns. Download the
completed report outside the checkout.

**Preview the report.** From the checkout root, set the path and replace
`TENANT_ID` with your Wiz tenant ID. Reuse the key for that tenant and
finding family across exports and project filters.

```sh
report=../reports/wiz-packages.json
codex-security publish findings "$report" \
  --to local --repository . --provider wiz \
  --source-key TENANT_ID/vulnerability-finding --dry-run --format json
```

Check the assets, builds and exclusions. For selected IDs, verify that
`findings[].source_finding_id` lists each requested occurrence once and no
others, and that `excluded` is empty. Compare the exact IDs. A package uses
the bare Wiz finding ID. SAST, repository secrets and IaC use the prefixes in
the [format table](#finding-formats-and-ids).
[Save locally or publish to Cloud and verify the result](README.md#save-or-publish-and-verify)

## Finding formats and IDs

| Native JSON finding family | Where to put the records                                 | Occurrence ID |
| -------------------------- | -------------------------------------------------------- | ------------- |
| Package vulnerabilities    | Individual records or `data.vulnerabilityFindings.nodes` | Wiz ID        |
| SAST                       | `data.sastFindings.nodes`                                | `sast:<id>`   |
| Repository secrets         | `data.secretInstances.nodes`                             | `secret:<id>` |
| IaC                        | `data.iacFindings.nodes`                                 | `iac:<id>`    |

**Paginated API or MCP results.** Check each finding and inventory page
for GraphQL `errors`, even if it contains nodes. Resolve errors before
combining pages. In one JSON object, put the selected nodes under their
original collection name. If findings need inventory to identify their
repository, include all inventory pages' nodes under
`data.versionControlResources.nodes`. Keep the final page info for each
collection.

## Package vulnerability inputs

JSON can contain a single finding, an array of selected findings, a detailed
vulnerability report or a complete `data.vulnerabilityFindings.nodes`
collection. JSONL can hold one package record per line. Preserve `id`, `name`,
`detailedName`, `vulnerableAsset.id` and `vendorSeverity` or `severity`, plus
available package, image and repository metadata. JSON uses `vendorSeverity`
when present, then `severity`. A reported `NONE` becomes `unknown`. The Wiz
finding ID identifies the occurrence. Many occurrences can share a CVE.

For GitHub Enterprise branch assets, keep `vulnerableAsset.cloudProviderURL`
and either `nativeType: "github#repositoryBranch"` or both
`type: "REPOSITORY_BRANCH"` and `cloudPlatform: "GitHub"`. The reader uses
the repository in that URL to check the import destination.

Detailed package CSV requires `ID`, `Name`, `DetailedName`, `AssetID`, `WizURL`,
`CloudPlatform` and `CloudProviderURL`. The platform must be GitHub and the
provider URL must identify a repository branch. That repository must match a
comparable checkout remote, when present, or the selected Cloud repository.
The same check applies when replaying parsed CSV rows as normalized JSONL.

CSV rows use `ID` as their occurrence ID. Severity comes from `Severity`, then
`VendorSeverity`, then `CVSSSeverity`. The reader preserves every cell under
`source_data.row`, including extra columns and quoted multiline values. A Git tree URL does not establish the branch or revision. The last-detected time does not establish when the record was updated.
Duplicate headers, malformed CSV, invalid UTF-8 and duplicate IDs among
importable rows stop the import. Review any excluded rows.

Raw package findings retain their reported severity and source data. Only
repository-branch file paths become source locations. Container and workload
paths stay in the vendor evidence. External network scans fall outside this
mapping.

## SAST, repository secrets, and IaC inputs

Keep findings under the [named collections](#finding-formats-and-ids). Bare
arrays of these families are ambiguous. An export can include several named
collections. For secrets, the resource must have `type: "REPOSITORY_BRANCH"`.

Each finding needs a verified repository URL. Keep its `repository.url` or
include the matching inventory under `data.versionControlResources.nodes`.
For secrets, the repository is under `resource.typedProperties.repository`.
The reader joins on `repository.id` and takes `repository.url` from the
matching inventory record. Inventory node IDs, `providerID`, names and Wiz
UUIDs cannot serve as Cloud repository IDs. When the finding and inventory
both supply a URL, they must agree. Cloud checks this source against the
connected repository.

Keep the inventory node's `platform` field. `GITHUB` allows case-insensitive
repository matching on custom GitHub Enterprise hosts. Duplicate inventory
entries for a repository ID must agree on platform and URL. Branch names are
preserved literally.

```json
{
  "data": {
    "sastFindings": {
      "nodes": [
        {
          "id": "finding-42",
          "name": "Untrusted query construction",
          "severity": "HIGH",
          "repository": { "id": "source-repository-1" },
          "filePath": "src/query.ts",
          "startLine": 10,
          "endLine": 12
        }
      ]
    },
    "versionControlResources": {
      "nodes": [
        {
          "repository": {
            "id": "source-repository-1",
            "url": "https://github.com/example/project"
          }
        }
      ]
    }
  }
}
```

## Preserved evidence

Each finding retains its original node in `source_data`. The typed
`evidence.details` fields expose the kind, verified repository, upstream
status and the following fields when Wiz supplies them.

| Family             | Evidence retained in typed fields                                                                                                              |
| ------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| SAST               | CWE IDs, first location's end line and snippet, scanner origin and verdict, remediation instructions                                           |
| Repository secrets | Detector rule, type, confidence, vendor validation status, encryption/management flags, introduced commit when supplied                        |
| IaC                | Rule IDs and name, first location's range and matched content, platform, expected/actual content, separate file link, remediation instructions |

Assess the finding separately from Wiz's status or verdict. A secret's
introduced commit describes when it appeared. Only an explicit scan revision
identifies the scanned code. A logical IaC resource in the report does not
establish a deployment. Original timestamps stay in `source_data`. Only an
explicit update time maps to the whole-second `source_updated_at`. SAST
creation time, package last-detected time and IaC last-seen time retain their
original meanings.

## Convert CSV reports

For SAST and repository-secret CSV, including gzipped CSV, map the actual
column headers to normalized JSONL. Preserve each original row in
`evidence.source_data` and set `evidence.details.kind` and
`evidence.details.repository.url` after verifying the repository. Use the same
prefixed occurrence ID as the corresponding API finding. Normalized JSONL
preserves the ID you supply. Correct missing finding IDs and severities in Wiz.

- **Repository secrets.** Select `path` and `lineNumber` for navigation,
  detector fields under `rule`, and `vcsDetails.initialCommitHash` for the
  introduced commit. The standard secret metadata API omits path and line.
  Keep credential values out of the metadata selection.
- **IaC.** Select `filePath`, `startLine`, `endLine`, `rule.id`, `rule.shortId`,
  `expectedContent`, `foundContent`, `matchContent` and repository/branch
  metadata. Use repository-relative source locations. An end line requires a
  start line.

For example, one complete line of normalized package input looks like this.

<!-- prettier-ignore -->
```jsonl
{"source_finding_id":"vendor-finding-42","evidence":{"title":"Vulnerable example package","severity":"high","source_data":{"id":"vendor-finding-42"}}}
```

Use valid UTF-8 for all inputs and export integers outside JavaScript's safe
range as strings. Read `excluded` in the preview for record-level errors.
