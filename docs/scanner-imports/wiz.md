# Import Wiz findings

Import Wiz package vulnerabilities, SAST findings, repository secrets or IaC
findings from native JSON or normalized JSONL. For repository package
vulnerabilities, you can also use a detailed CSV report. All three formats
support gzip.

## Quick start

[Enable external imports](README.md#preview-a-report). This example imports
repository package vulnerabilities.

**Saved report.** Choose the file for your repository and branch or build.
With a connected Wiz account, list findings for the repository and family,
then retrieve the selected records by Wiz finding ID. If a pull request
scan event omits occurrence IDs, request a scoped native capture.

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
others, and that `excluded` is empty. Include the family prefix shown below.
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

**CSV and normalized JSONL.** Detailed package CSV requires a GitHub
repository-branch URL and preserves each original cell. For other families,
use their named JSON collection or map the fields to normalized JSONL.
[Wiz format reference and repository mapping](../../plugins/codex-security/skills/publish-findings/references/wiz-import.md#finding-formats)
