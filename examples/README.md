# Examples

| Task | Example |
| --- | --- |
| Scan an app, inspect a finding, patch it and verify the repair | [Invoice Desk walkthrough](invoice-desk/walkthrough.md). Copy only the synthetic app into the scan target. |
| Supply your own validation test | [Custom validation demo](custom-validation/README.md). Run the local HTTP test on its own or let a model-backed scan invoke it. |
| Scan pull requests and repositories with GitHub Actions | [GitHub Actions with Amazon Bedrock](github-actions/README.md) uses AWS OIDC and saves SARIF and readable reports. |
| Scan Azure Repos from a central pipeline | [Azure Pipelines with Amazon Bedrock](azure-pipelines/README.md) runs manual full or committed-diff scans. |
| Import Tenable One findings | [Tenable One export guide](../docs/scanner-imports/tenable.md) shows how to select findings for a local checkout or connected Cloud repository. |
| Prepare a ServiceNow AVIT export | [AVIT template](servicenow-avit-template.csv). Replace the synthetic application and assignment values before using it as input to [export findings for ServiceNow](../sdk/typescript/docs/cli.md#export-findings-for-servicenow). |
| Preview a Codex Security findings CSV for Cloud | [Findings CSV template](findings.csv). Add one row per finding and preview the file as shown below. |

## Preview a findings CSV

Use this CSV format with `publish scan --to cloud`. For reports exported by a scanner,
follow its [provider guide](../docs/scanner-imports/README.md). To try the Cloud CSV
preview, copy the header-only [template](findings.csv) and append this synthetic row.

```csv
occ_e79cb19591e696572a1c22be,csf_852f90d6e1177502ff113d4a,Archive entry can escape the output directory,The archive writer uses the entry path without checking containment.,high,high,open,,,Validate each destination before writing.,src/extract.py,41,44
```

Keep every column in the template. Leave `close_reason` empty for an open finding.
For a closed finding, use `already_fixed`, `wont_fix`, or `false_positive`. A
`note` is required for the last two reasons and optional otherwise. Leave
`end_line` empty if the location has only a start line.

Replace the path below with your populated copy. The dry run validates the file
and previews the findings without uploading them.

```bash
codex-security publish scan --to cloud --csv /path/to/findings.csv --dry-run --json
```

See [Publish completed scans](../sdk/typescript/docs/cli.md#publish-completed-scans)
when you are ready to upload.

## npm package

The examples above live in the source repository. The npm package includes the
plugin's sample scan bundles. Use the [current report and manifest](../plugins/codex-security/examples/completed-scan/)
to see what a scan produces. The [legacy bundle](../plugins/codex-security/examples/legacy-completed-scan/)
illustrates how to read older scans that reference a separate coverage file.
