# Import Wiz findings

Import saved Wiz package vulnerabilities, SAST findings, repository secrets or
IaC findings. The file reader accepts native JSON, normalized JSONL and detailed
repository package vulnerability CSV, including gzip-compressed files.

## Quick start

For a package vulnerability export, select the repository in Wiz **Vulnerability
Findings**, choose **Save as → Report**, then select **Repository Branch**,
**JSON** and **Detailed** columns. Download the completed report outside the
checkout. From the destination checkout root, set the path and replace `TENANT_ID`
with your stable Wiz tenant identifier.

```sh
export CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS=1
report=../reports/wiz-packages.json
codex-security publish findings "$report" \
  --to local --repository . --provider wiz \
  --source-key TENANT_ID/vulnerability-finding --dry-run --format json
```

## Import and verify

Check that the preview covers the intended assets or builds and review excluded
records. Reuse the source key for the same tenant and finding family across
exports and project filters. [Save or publish and verify](README.md#save-or-publish-and-verify).

## Reference

- **Native JSON.** Package vulnerabilities accept individual records or
  `data.vulnerabilityFindings.nodes`. SAST, repository secrets and IaC require
  the named `data.sastFindings.nodes`, `data.secretInstances.nodes` or
  `data.iacFindings.nodes` collection.
- **Paginated API or MCP results.** Check every finding and inventory page for
  GraphQL `errors`, even when the page contains nodes. If any page reports an
  error, resolve it and collect a complete selection before combining pages.
  Put the selected nodes under the original collection name in one JSON object. If
  findings use inventory to identify their repository, finish the inventory
  pages too and combine their nodes under `data.versionControlResources.nodes`
  in the same object. Retain the final page info for each collection. An array
  or JSONL stream of GraphQL page envelopes cannot be imported.
- **CSV.** Use **Detailed** repository package vulnerability columns. The reader
  requires a GitHub repository-branch URL and preserves each original cell.
  Other finding families require native JSON or an explicit normalized mapping.
- Package findings retain the Wiz occurrence ID. SAST, repository secrets and
  IaC use `sast:`, `secret:` and `iac:` ID prefixes. See the
  [Wiz format reference](../../plugins/codex-security/skills/publish-findings/references/wiz-import.md#finding-formats)
  for required fields, repository mapping and normalized JSONL.
