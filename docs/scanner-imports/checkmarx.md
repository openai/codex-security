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

For self-managed CxSAST, open **Projects & Scans → All Scans** on the server
selected in your CxFlow profile. Verify the completed scan ID, the project
name and the full path of the team that owns that scan. If names repeat, open the project under the
intended team and check **View Project Scans**. Codex can use trusted read-only
scan metadata or ask you to confirm those details directly from that view. CxFlow
retrieves the report by scan ID, so supply an XML export from the selected
scan if its project and team cannot be verified before retrieval.
[Viewing results from All Scans](https://docs.checkmarx.com/en/34965-46419-viewing-results-from-all-scans.html)

Request the full CxSAST scan when using automatic collection. CxFlow exports the
full XML even when its issue-tracker profile filters by severity or query. For
a subset, supply XML exported with the desired filters. Checkmarx One also
retrieves every engine in the selected scan before import selects SAST results.
You can supply a CLI JSON report exported to the desired scope.

Use a trusted Codex session with your existing Checkmarx sign-in. If you
started Codex from a build or IDE that loads libraries or shell startup files
from the scanned project, start a clean session or supply an exported report.
Codex starts collection from a private directory outside the source tree.
For local and Cloud imports, it supplies the source root separately whenever
the checkout or unpacked source is available.
Provide trusted absolute paths outside the source tree for the native Python
3.10+ interpreter and vendor tools. For `cx` and Java, use native binaries or
symlinks to them.

For Checkmarx One, use your installed `cx` and existing sign-in. To select
a saved profile, set `CX_CONFIG_FILE_PATH` to its trusted absolute path.
The collector uses that profile with its stored credentials. Without an
explicit profile, it uses a complete environment login if present, or the
default saved profile. For an environment login, use `CX_APIKEY` or provide
`CX_CLIENT_ID`, `CX_CLIENT_SECRET`, `CX_BASE_URI` and `CX_TENANT` together.
For a separate OAuth server, also set `CX_BASE_AUTH_URI`. Confirm the tenant
and server for that login before collecting. The collector keeps an
environment login separate from credentials stored in a profile.

For CxSAST, supply Java and a released CxFlow JAR, version 1.6.37 or later.
The collector checks the JAR version before retrieving a named scan. For an
older or unrecognized JAR, supply an XML export from the selected scan.
[CxFlow 1.6.37 release notes](https://github.com/checkmarx-ltd/cx-flow/releases/tag/1.6.37)

In a trusted SAST-only configuration, set the Checkmarx server address and
enable the `CxXml` file writer. Keep
the profile and everything it loads outside the source tree and under your
control. CxFlow runs in a fresh environment. The collector forwards only three
credential variables from your session (`CHECKMARX_USERNAME`, `CHECKMARX_PASSWORD`
and `CHECKMARX_CLIENT_SECRET`). Set a custom `checkmarx.client-id` in the profile
if your server requires one. [CxFlow credential settings](https://github.com/checkmarx-ltd/cx-flow/blob/v1.7.14/docs/Tutorials.md#L382-L390)

The collector retrieves the existing scan in project mode, selects the XML file
writer and writes logs in a private directory. If CxFlow cannot look up the
exact project name, export XML from that project in CxSAST. This applies to
project names containing Chinese, Japanese or Korean characters with CxFlow
1.7.14. If CxFlow needs other environment variables or custom JVM options,
export XML with your usual setup. If either product requires a shell launcher,
give Codex its exported report.
[Checkmarx One results](https://docs.checkmarx.com/en/34965-68640-results.html) · [CxFlow project retrieval](https://github.com/checkmarx-ltd/cx-flow/blob/v1.7.14/docs/Execution.md) · [CxFlow XML configuration](https://github.com/checkmarx-ltd/cx-flow/blob/v1.7.14/docs/Bug-Trackers-and-Feedback-Channels.md#cxxml)

Codex checks the scan ID in the exported file. For CxSAST, it also checks the
team and project. Review the preview for the requested repository before
confirming the import.
Codex uses the exact report path printed by the collector for the preview,
confirmed import and any retries. The helper creates a private
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
