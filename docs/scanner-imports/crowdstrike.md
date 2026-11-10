# Import CrowdStrike findings locally

Use a saved JSON report from `fcs scan iac` in the CrowdStrike Falcon Cloud Security (FCS) CLI 4.x. The reader imports each entry in `rule_detections` as one misconfiguration or secret finding. It works offline and does not run the FCS CLI. Reports in the older `violations` format and image scan reports are not supported.

## Create the report

FCS writes each detection's `file` relative to the directory where the CLI runs, not relative to `--path`. Run the scan from the checkout root so that the paths are checkout-relative. Write the report to a private directory outside the checkout.

```sh
cd /path/to/checkout
fcs scan iac --path . --report-formats json --output-path /private/path/fcs-report
```

The CLI saves the report as `<timestamp>-scan-results.json` in the output directory. A scan of a subdirectory, such as `--path infra`, also gives checkout-relative paths when it runs from the checkout root. A remote `git::` scan gives paths from the repository root. Import it into a checkout of that repository. The [FCS GitHub Action](https://github.com/CrowdStrike/fcs-action) runs the CLI from the workspace root.

## Preview, save and read back

Verify the HTTPS clone URL independently and use a checkout with a matching Git fetch remote. The FCS report does not identify the repository.

```sh
codex-security publish findings /private/path/fcs-report/TIMESTAMP-scan-results.json \
  --provider crowdstrike --to local --repository /path/to/checkout \
  --source-repository-url https://github.com/example/project \
  --source-key example/project/main --dry-run --format json
```

Check the paths in `evidence.locations` against the checkout. A detection whose file is absolute or outside the checkout is listed under `excluded`. Remove `--dry-run` and confirm to save. Run `codex-security findings imported /path/to/checkout --format json` to read back the findings and their initial `not_assessed` Codex assessment.

## Read the evidence and repeat an import

- `details.kind` is `secret` for the Secret Management rule category and `iac` for all others. The report does not include secret values.
- `details.configuration.actual` is the FCS `reason`, and `details.configuration.expected` is its `recommendation`. Module remediation guidance, when present, is appended to `details.remediation_instructions`.
- `evidence.source_data` keeps the native rule, without its detection list, and the one detection.

FCS has no stable detection ID. The reader identifies a detection by rule UUID, file, line, resource type, resource name and reason. Keep the same source key for one repository and branch. When a later scan reports a detection on a different line, it is imported as a new finding, and the earlier finding stays stored. CrowdStrike reports support local import only.
