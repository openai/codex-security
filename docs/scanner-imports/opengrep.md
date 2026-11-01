# Import OpenGrep findings

Import native OpenGrep JSON into the local workbench or Cloud. The reader
accepts plain or gzipped reports and preserves OpenGrep observations, including
available traces and scan diagnostics.

## Quick start

From the scanned repository's root, set `report` to the saved JSON and
`repo_url` to its credential-free HTTP(S) repository URL. Choose an OpenGrep-specific source key
for the organization, project and branch. Enable external imports for this shell.

```sh
export CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS=1
report=../reports/opengrep.json
repo_url=https://github.com/example/project
source_key=opengrep/example/project/main
```

If you need a new report, run OpenGrep in the repository root with your rules.
Use a private temporary directory outside the checkout for this run.

```sh
report=
report_dir=$(mktemp -d) &&
  opengrep scan --config /path/to/rules.yaml --json --output "$report_dir/opengrep.json" . &&
  report="$report_dir/opengrep.json"
```

Native JSON includes traces when available. Use `--verbose` for skipped-target
details. SARIF and normalized JSONL are unsupported.
[OpenGrep output options](https://github.com/opengrep/opengrep/blob/main/src/osemgrep/cli_scan/Scan_CLI.ml)
and [JSON formatter](https://github.com/opengrep/opengrep/blob/main/src/osemgrep/reporting/Cli_json_output.ml)

After a successful scan, or with an existing report, preview the selected file locally.

```sh
codex-security publish findings "$report" --to local --repository . \
  --provider opengrep --source-repository-url "$repo_url" \
  --source-key "$source_key" --dry-run --format json
```

## Import and verify

Check the findings, exclusions and scan diagnostics. The declared source URL
must match a comparable configured Git remote when one is available. Repeat the
local command without `--dry-run`, confirm, then read back the stored evidence.
Local import needs no Cloud login.

```sh
codex-security findings imported . --format json
```

For Cloud, sign in to an account with access to the target repository and
environment. The deployment must support the `semgrep` provider. Preview the
same file, review the destination, then repeat without `--dry-run` and confirm.
Check the result's `verified` count, failures and exclusions.

```sh
codex-security publish findings "$report" --to cloud --repository "$repo_url" \
  --provider opengrep --source-repository-url "$repo_url" \
  --source-key "$source_key" --dry-run --format json
```

## Reference

### Provider identity and evidence

`--provider opengrep` selects the reader. Both destinations store the source
provider as `semgrep` and identify OpenGrep in `details.scanner_origin`. Keep a
distinct OpenGrep source key. The rule, path and range identify an occurrence.
Moving a match or changing its Windows path spelling can create another record.
Omitted records remain stored.

Multiple traces at one occurrence are grouped. The original rule level,
snippets, ignored state and fingerprints remain in the evidence. Normalized
severity is `unknown` because OpenGrep levels such as `ERROR` describe rule
matches. For Cloud, review exclusions for oversized traces. If individually
valid traces together exceed 256 KiB, the whole occurrence is excluded.
[Imported evidence](schema-guide.md)

### Diagnostics and coverage

A report can contain matches alongside parse errors or timeouts. Check the
scanner's exit status and the preview's `report.errors`, even when the findings
list is empty. A successful import confirms storage only. Cloud requires at
least one supported finding.

The CLI returns run-wide metadata in `report`. Stored findings keep the scanner
version, raw observations in `source_data.results` and diagnostic count in
`source_data.scan_error_count`. Retain the original JSON for run-wide details.
[OpenGrep error classification](https://github.com/opengrep/opengrep/blob/main/src/core/Core_error.ml)
and [skipped targets](https://github.com/opengrep/opengrep/blob/main/src/osemgrep/reporting/Output.ml)

### Assess an imported finding locally

Copy the record's `id` from local readback. Load the record with the SDK's
`listLocalExternalFindings({ repository, id })`. On a `CodexSecurity` instance,
call `security.validate({ repositoryPath, finding: record.evidence })` with
`repositoryPath` set to the checkout for the scanned revision. Validation sends the evidence to your configured model provider and
returns a separate assessment. The stored import remains `not_assessed`.
[SDK validation example](../../sdk/typescript/README.md#validate-an-existing-finding)
and [host-provided validation](../../sdk/typescript/docs/validate-records.md)
