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

For self-managed CxSAST, include the full team path and project name. Use the
exact spelling shown in CxSAST for non-ASCII team characters. If you
already have a supported report, give Codex its path and skip collection.

Run collection in the operator's trusted login environment, without running a
project build or loading environment settings from the scanned source. Codex
starts collection from a trusted private directory outside the scanned source.
For local and Cloud imports, it supplies the source root separately whenever
the checkout or unpacked source is available.
Provide trusted absolute paths outside the source tree for the native Python
3.10+ interpreter and vendor tools. For `cx` and Java, use native binaries or
symlinks to them. For Checkmarx One, supply your signed-in `cx` executable.
If you set `CX_CONFIG_FILE_PATH`, use an absolute path to
your trusted profile. For CxSAST, supply Java, the CxFlow JAR and a SAST-only
configuration file. Enable the `CxXml` file writer and declare any required
Spring configuration imports in that file. The collector retrieves the existing
scan in project mode and selects only the XML file writer. It runs CxFlow with
your chosen configuration, writes its logs in a private directory and ignores
inherited JVM startup options for that process. If either product requires a
custom shell launcher, or CxFlow requires a JVM option or agent, export the
report with your usual setup and give Codex the file.
[Checkmarx One results](https://docs.checkmarx.com/en/34965-68640-results.html) · [CxFlow project retrieval](https://github.com/checkmarx-ltd/cx-flow/blob/v1.7.14/docs/Execution.md) · [CxFlow XML configuration](https://github.com/checkmarx-ltd/cx-flow/blob/v1.7.14/docs/Bug-Trackers-and-Feedback-Channels.md#cxxml)

Codex checks the scan ID in the exported file. For CxSAST, it also checks the
team and project. Review the preview for the requested repository before
confirming the import.
Codex reuses the same file after confirmation. The helper creates a private
temporary directory for its report. If you set `TMPDIR` or `TEMP`,
point it outside the scanned source tree. Remove the report directory after
readback and any retries, or ask Codex to keep it for later use.

## Export one scan manually

**Checkmarx One.** From a trusted directory outside the checkout, set `cx_path`
to the absolute path of the signed-in Checkmarx CLI, `scan_id` to the chosen
scan ID and `report_root` to a private directory outside the checkout.
[Checkmarx One CLI results](https://docs.checkmarx.com/en/34965-68640-results.html)

```sh
source_key=checkmarx-one/example-tenant/example-project/main/sast
report=
report_dir=$(mktemp -d "$report_root/checkmarx.XXXXXXXX") &&
  "$cx_path" results show --scan-id "$scan_id" --report-format json \
    --output-path "$report_dir" --output-name checkmarx-results &&
  report="$report_dir/checkmarx-results.json"
```

Continue only after the export succeeds. In the preview, compare `report.scanId`
with the scan ID you requested before confirming the import.

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

The scan ID identifies which run supplied the evidence. Checkmarx can scan a
repository, directory or archive. Both reports retain filenames and lines in
`evidence.source_data`. Checkmarx One uses `row.data.nodes` and CxSAST uses
`nodes` or `result` when the path has no nodes. The reader leaves `locations`
empty. Verify how the scanned sources map to the checkout before using a
reported path to investigate a finding.

Inspect the query, reported severity and triage state in the preview. Imported
findings start as `not_assessed`. Reimporting the same occurrence updates
changed evidence, and an identical report produces unchanged records. Results
omitted by a report filter stay stored. [Imported finding identity and evidence](schema-guide.md)
