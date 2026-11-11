# Import CrowdStrike findings locally

Use a saved JSON report from `fcs scan iac` in the CrowdStrike Falcon Cloud Security (FCS) CLI 4.x. The reader imports each detection in `rule_detections` as one misconfiguration or secret finding. It works offline and does not run the FCS CLI. Reports in the older `violations` format and image scan reports are not supported. CrowdStrike reports support local import only.

## Create the report

FCS writes each detection's `file` relative to the directory where the CLI runs, not relative to `--path`. Run the scan from the root of the directory you will import into, and write the report outside it. The output directory must exist, and its name must not contain a dot.

```sh
cd /path/to/project
reports=$(mktemp -d "${TMPDIR:-/tmp}/fcs-report-XXXXXX")
fcs scan iac --path . --report-formats json --output-path "$reports"
report=$(find "$reports" -name '*-scan-results.json')
```

FCS exits with a nonzero code when detections match `--fail-on`, which by default is any detection. The report is saved if the output shows `Results saved to file`. A scan of a subdirectory, such as `--path infra`, also gives correct paths when it runs from the root.

The [FCS GitHub Action](https://github.com/CrowdStrike/fcs-action) runs the CLI from the workspace root. When `path` is a directory in a checkout at the workspace root, its JSON report matches a checkout of the same commit. Set `report_formats: json` and an `output_path`, upload that directory as a workflow artifact, and download it outside your checkout.

### Scan a remote repository

A `git::` scan clones the default branch, and the report does not record the commit. FCS has no branch or commit option, but the URL accepts `?ref=` with a branch, tag or commit. Pin the scan to a commit and check out the same commit.

```sh
repository_url=https://github.com/example/project
checkout=/path/to/project
reports=$(mktemp -d "${TMPDIR:-/tmp}/fcs-report-XXXXXX")
commit=$(git ls-remote "$repository_url.git" HEAD | cut -f1)
fcs scan iac --path "git::$repository_url.git?ref=$commit" \
  --report-formats json --output-path "$reports"
report=$(find "$reports" -name '*-scan-results.json')
git clone --quiet "$repository_url.git" "$checkout"
git -C "$checkout" checkout --quiet --detach "$commit"
```

To scan another branch, replace `HEAD` with `refs/heads/BRANCH`. Paths start at the repository root. If the URL ends with a subdirectory, such as `.git//infra?ref=...`, paths start at that subdirectory. Use `"$checkout/infra"` as `--repository`. If the checkout is at a different commit, the import stops at the first file that changed.

A report of a `git::https://` URL names its repository. The import records that URL, without the subdirectory or `?ref=`, as the findings' repository. If you also pass `--source-repository-url`, both must name the same repository, or the import stops.

## Preview, save and read back

The project does not need to be a Git checkout.

```sh
codex-security publish findings "$report" --provider crowdstrike --to local \
  --repository /path/to/project --source-key example/project/main \
  --dry-run --format json
```

Every detection's file must exist in `--repository` with the content that FCS scanned, which the report records as `file_sha256`. If a file is missing or changed, the import stops and names it, because the reported lines might no longer be correct. Select the directory and commit that FCS scanned, or scan again from its root. Different line endings also count as a change, for example in a Windows checkout of a report from a Linux CI runner.

Add `--source-repository-url https://github.com/example/project` to record the repository of a local scan. With a repository URL, findings get typed `iac` or `secret` details. If you pass the URL and `--repository` is a Git checkout, the URL must match one of its fetch remotes. Without a URL, each finding has a title, severity, description and location, and `evidence.source_data` keeps the native FCS rule and detection.

Remove `--dry-run` and confirm to save. Run `codex-security findings imported /path/to/project --format json` to read back the findings and their initial `not_assessed` Codex assessment. To check a finding against the code, see [Work with imported findings](README.md#work-with-imported-findings).

## Read the evidence

This shortened report has one detection. The reader keeps its file and line as the finding location.

```json
{
  "fcs_version": "4.3.0",
  "path": ".",
  "scan_uuid": "00000000-0000-4000-8000-000000000001",
  "rule_detections": [
    {
      "rule_name": "Sensitive Port Is Exposed To Entire Network",
      "rule_uuid": "00000000-0000-4000-8000-000000000002",
      "rule_category": "Networking and Firewall",
      "severity": "High",
      "platform": "Terraform",
      "detections": [
        {
          "file": "infra/main.tf",
          "line": 4,
          "resource_type": "aws_security_group",
          "resource_name": "example",
          "reason": "aws_security_group[example] 'SSH' (Port:22) is public",
          "recommendation": "aws_security_group[example] 'SSH' (Port:22) should not be public"
        }
      ]
    }
  ]
}
```

- With a repository URL, `details.kind` is `secret` for the Secret Management rule category and `iac` for all others. `details.configuration.actual` is the FCS `reason`, and `details.configuration.expected` is its `recommendation`. FCS names the attribute that holds a secret, not its value.
- A detection in a local Terraform module points to the module file. FCS also reports a copy at the module call, and both are imported.
- A detection in a registry or Git module names the calling file. Its location is the call line from `module_remediation`, or no line if FCS does not state one.
- `evidence.source_data` keeps the FCS version, the native rule without its detection list, and the one detection. For a `git::` scan, it also keeps the scanned URL without `?ref=`.

## Repeat an import

FCS has no stable detection ID. The reader identifies a detection by rule UUID, file, line, resource type and name, reason and module path. Keep the same source key for one project and branch. When a later scan reports a detection on a different line, it is imported as a new finding, and the earlier finding stays stored.
