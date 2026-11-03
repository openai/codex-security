# Import Checkmarx SAST findings

Use `--provider checkmarx` with either a Checkmarx One CLI JSON report or a
self-managed CxSAST XML scan report. Choose a completed scan and verify its
project, source repository and branch. Enable external imports in the
environment where Codex or the CLI runs.

```sh
export CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS=1
```

## Collect an existing scan with Codex

Ask the **publish-findings** skill to preview a particular scan in your checkout.

> Preview Checkmarx One scan `SCAN_ID` for project `example-project` on `main`.
> Its repository is `https://github.com/example/project`.

For self-managed CxSAST, include the full team path and project name. If you
already have a supported report, give Codex its path and skip collection.

For Checkmarx One, Codex uses your signed-in vendor `cx` executable. Supply
its absolute installation path if the name is ambiguous. If you set
`CX_CONFIG_FILE_PATH`, use the absolute path to your trusted CLI configuration.
For CxSAST, supply the absolute paths to your CxFlow JAR and trusted SAST-only
configuration.
The profile must have the `CxXml` file writer enabled. The collector requests
the existing scan in project mode and selects only the XML file writer.
[Checkmarx One results](https://docs.checkmarx.com/en/34965-68640-results.html) · [CxFlow project retrieval](https://github.com/checkmarx-ltd/cx-flow/blob/v1.7.14/docs/Execution.md) · [CxFlow XML configuration](https://github.com/checkmarx-ltd/cx-flow/blob/v1.7.14/docs/Bug-Trackers-and-Feedback-Channels.md#cxxml)

Codex checks the scan ID in the exported file. For CxSAST, it also checks the
team and project. Review the preview for the requested repository before
confirming the import.
Codex reuses the same file after confirmation. The helper creates a private
temporary directory for its report. Remove that directory after readback and
any retries, or ask Codex to keep it for later use.

## Export one scan manually

**Checkmarx One.** In a shell authenticated with the Checkmarx One CLI, set
`scan_id` to the completed scan's ID and `report_dir` to a private directory
outside the checkout. This retrieves the existing results. [Checkmarx One CLI results](https://docs.checkmarx.com/en/34965-68640-results.html)

```sh
cx results show --scan-id "$scan_id" --report-format json \
  --output-path "$report_dir" --output-name checkmarx-results
report="$report_dir/checkmarx-results.json"
source_key=checkmarx-one/example-tenant/example-project/main/sast
```

The CLI JSON report contains `scanID`, `totalCount` and `results`. When a scan
includes multiple engines, the import lists results from engines other than
`sast` in its exclusions. A confirmed local import with exclusions saves the
accepted SAST results and exits with status 1. Check the counts and exclusion
reasons before retrying. Keep the scan envelope and the exported rows together.

**Self-managed CxSAST.** In the project's **All Scans** view, choose the scan
and select **Create Report**. Select **XML**, review the result filters and
generate the report. Save it in a private directory outside the checkout.
[Generate a CxSAST scan report](https://docs.checkmarx.com/en/34965-46423-generating-scan-result-reports.html)

```sh
report=/private/path/checkmarx-results.xml
source_key=cxsast/example-instance/example-project/main/sast
```

## Preview, import and verify

Replace the example source key with one for your Checkmarx instance or tenant,
project, branch and product. Reuse it for later exports from the same stream.
Use a separate key for each product when moving from CxSAST to Checkmarx One.

From the matching checkout, supply its verified, credential-free HTTP(S) Git
URL and preview the report.

```sh
codex-security publish findings "$report" --to local --repository . \
  --provider checkmarx --source-repository-url https://github.com/example/project \
  --source-key "$source_key" --dry-run --format json
```

Check the SAST results, reported paths, exclusions and destination. To save
locally, repeat the command without `--dry-run` and confirm. Read back the
stored evidence with `codex-security findings imported . --format json`.
For a Cloud deployment that accepts the `checkmarx` provider, follow the
[Cloud preview and publication steps](README.md#save-or-publish-and-verify).

## Identity and evidence

One query can produce several results with the same Checkmarx similarity ID.
For Checkmarx One, the reader combines `similarityId` with `data.resultHash`.
For CxSAST, it combines the project ID, query ID and path's `SimilarityId`
with the ordered path nodes. For a path without nodes it uses the result's
reported location. A source change that moves a node can create a new record.
[Checkmarx similarity IDs](https://docs.checkmarx.com/en/34965-205026-similarity-id.html)

Inspect the query, reported severity, triage state and path evidence in the
preview. The scan ID identifies which run supplied the evidence. Imported
findings start as `not_assessed`. Reimporting the same occurrence updates
changed evidence, and an identical report produces unchanged records. Results
omitted by a report filter stay stored. [Imported finding identity and evidence](schema-guide.md)
