# Import CrowdStrike findings locally

Use a saved JSON report from `fcs scan iac` in the CrowdStrike Falcon Cloud Security (FCS) CLI 4.x. The reader imports each entry in `rule_detections` as one misconfiguration or secret finding. It works offline and does not run the FCS CLI. Reports in the older `violations` format and image scan reports are not supported.

## Create the report

FCS writes each detection's `file` relative to the directory where the CLI runs, not relative to `--path`. Run the scan from the root of the directory you will import into, and write the report outside it.

```sh
cd /path/to/project
fcs scan iac --path . --report-formats json --output-path /private/path/fcs-report
```

The CLI saves the report as `<timestamp>-scan-results.json`. A scan of a subdirectory, such as `--path infra`, also gives correct paths when it runs from the root. A remote `git::` scan gives paths from the repository root.

The [FCS GitHub Action](https://github.com/CrowdStrike/fcs-action) runs the CLI from the workspace root, so its JSON report matches a checkout of the same commit. Set `report_formats: json` and an `output_path`, upload that directory as a workflow artifact, and download it outside your checkout.

## Preview, save and read back

The project does not need to be a Git checkout.

```sh
codex-security publish findings /private/path/fcs-report/TIMESTAMP-scan-results.json \
  --provider crowdstrike --to local --repository /path/to/project \
  --source-key example/project/main --dry-run --format json
```

Every detection's file must exist in `--repository`. If one does not, the import stops and names the file. Select the directory that FCS scanned, or scan again from its root.

Add `--source-repository-url https://github.com/example/project` to record the repository. With it, findings get typed `iac` or `secret` details. If `--repository` is a Git checkout, the URL must match one of its fetch remotes. Without it, each finding keeps its title, severity, location and the native FCS rule and detection in `evidence.source_data`.

Remove `--dry-run` and confirm to save. Run `codex-security findings imported /path/to/project --format json` to read back the findings and their initial `not_assessed` Codex assessment. CrowdStrike reports support local import only.

## Read the evidence

- With a repository URL, `details.kind` is `secret` for the Secret Management rule category and `iac` for all others. `details.configuration.actual` is the FCS `reason`, and `details.configuration.expected` is its `recommendation`. The report does not include secret values.
- A detection in a local Terraform module points to the module file. FCS also reports a copy at the module call, and both are imported.
- A detection in a registry or Git module names the calling file. Its location is the call line from `module_remediation`, or no line if FCS does not state one.
- `evidence.source_data` keeps the FCS version, the native rule without its detection list, and the one detection.

## Repeat an import

FCS has no stable detection ID. The reader identifies a detection by rule UUID, file, line, resource type and name, reason and module path. Keep the same source key for one project and branch. When a later scan reports a detection on a different line, it is imported as a new finding, and the earlier finding stays stored.
