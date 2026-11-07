# Import Checkmarx SAST findings

Use `--provider checkmarx` for a completed Checkmarx One scan (CLI JSON) or
self-managed CxSAST scan (XML). Both formats support gzip. If you need the report,
[collect an existing scan with Codex](#collect-an-existing-scan-with-codex) or
[export one scan manually](#export-one-scan-manually).

## Preview, import and verify

From the matching checkout, preview the report with its verified Git URL.
Choose a source key for the product, tenant or instance, project and ref.
Reuse it for later exports from that stream.

```sh
report=/private/path/checkmarx-results.json
codex-security publish findings "$report" --to local --repository . \
  --provider checkmarx --source-repository-url https://github.com/example/project \
  --source-key checkmarx-one/example-tenant/example-project/main/sast \
  --dry-run --format json
```

For CxSAST, use the XML path and a key such as `cxsast/example-instance/example-project/main/sast`.
Check `report.scanId`, the SAST findings and any exclusions. A confirmed local import
with exclusions saves the accepted findings and exits with status 1. Use the same
file for confirmation and retries. [Save or publish and verify](README.md#save-or-publish-and-verify).

## Collect an existing scan with Codex

Ask **publish-findings** for the full scan from a trusted session. Supply a native
Python 3.10+ interpreter and vendor tools installed outside the scanned source tree.

> Preview the full Checkmarx One scan `SCAN_ID` for `example-project` on `main`.
> Its repository is `https://github.com/example/project`.

- **Checkmarx One** uses `cx` 2.3.23+ with your signed-in profile or a complete
  environment login. Use `CX_CONFIG_FILE_PATH` for a specific trusted profile.
  On mixed scans, `cx` retrieves all engines and may also generate an SCA package report.
- **CxSAST** uses Java, CxFlow 1.6.37+ and your trusted SAST-only profile with
  the `CxXml` writer. Verify the completed scan ID, project and owning team's full path
  in the selected server’s **Projects & Scans → All Scans** view before collection.
  CxFlow fetches by ID and exports the full XML even when issue-tracker filters are set.
  Session credentials require confirmation for that server. [CxSAST All Scans](https://docs.checkmarx.com/en/34965-46419-viewing-results-from-all-scans.html)

If you need a subset or your tools differ from the collector requirements
above, supply a native export from your usual environment. Keep reports in
a private directory outside the checkout.
[Supported sign-in and collection settings](../../plugins/codex-security/skills/publish-findings/references/checkmarx-import.md).

## Export one scan manually

For **Checkmarx One**, use the signed-in CLI from outside the checkout. Set
`cx_path` to the installed executable, `scan_id` to the selected scan, and
`report_root` to a private directory. Use the printed file after a successful export.
[Checkmarx One results](https://docs.checkmarx.com/en/34965-68640-results.html)

```sh
report_dir=$(mktemp -d "$report_root/checkmarx.XXXXXXXX") &&
  "$cx_path" results show --scan-id "$scan_id" --report-format json \
    --output-path "$report_dir" --output-name checkmarx-results &&
  printf '%s\n' "$report_dir/checkmarx-results.json"
```

For **CxSAST**, open the selected scan and choose **Create Report → XML**.
Review the result filters before generating the file. [Generate a CxSAST report](https://docs.checkmarx.com/en/34965-46423-generating-scan-result-reports.html).

## Identity and evidence

Checkmarx One combines `similarityId` and `data.resultHash` to identify each occurrence.
CxSAST uses the project, query, path similarity ID and ordered path nodes,
or the reported result location for a path without nodes. Moving a node can
create a new occurrence. [Checkmarx similarity IDs](https://docs.checkmarx.com/en/34965-205026-similarity-id.html)

Findings start as `not_assessed` and retain the native severity, triage state,
paths and snippets in `evidence.source_data`. A scan may cover a directory or
archive. Verify how its paths map to the checkout before investigating a finding.
