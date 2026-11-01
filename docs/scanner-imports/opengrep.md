# Import OpenGrep findings

Import native OpenGrep JSON, plain or gzipped, to retain observations,
available traces and scan diagnostics.

## Quick start

[Enable external imports](README.md#preview-a-report). From the scanned
checkout root, preview the saved JSON using its credential-free HTTP(S) repository
URL and an OpenGrep-specific source key. To get a new report,
[run OpenGrep locally](#diagnostics-and-coverage).

For an existing report, set its path in the same shell.

```sh
opengrep_report=../reports/opengrep.json
```

Preview the selected report.

```sh
codex-security publish findings "$opengrep_report" --to local --repository . \
  --provider opengrep --source-repository-url https://github.com/example/project \
  --source-key opengrep/example/project/main --dry-run --format json
```

## Import and verify

Check the findings, exclusions and `report.errors`, including when the
findings list is empty. Keep `--provider opengrep` for
[local import or Cloud publication](README.md#save-or-publish-and-verify).
Both destinations store `semgrep` as the provider and record OpenGrep in
`details.scanner_origin`.

## Reference

### Provider identity and evidence

Use a distinct OpenGrep source key for the organization, project and branch.
The rule, path and range identify an occurrence. Moving a match or changing
its Windows path spelling can create a new record.

Multiple traces at one occurrence are grouped. Evidence retains the rule
level, snippets, ignored state and fingerprints when supplied. Severity is
`unknown` because OpenGrep levels such as `ERROR` describe rule matches.
If individually valid traces together exceed the Cloud 256 KiB limit, the
whole occurrence is excluded. [Imported evidence](schema-guide.md)

### Diagnostics and coverage

To create a report, run OpenGrep with your rules from the repository root
and save native JSON outside the checkout. Add `--verbose` for skipped-target
details. Preview the file after the scan succeeds.
[OpenGrep output options](https://github.com/opengrep/opengrep/blob/main/src/osemgrep/cli_scan/Scan_CLI.ml)

```sh
opengrep_report=
report_dir=$(mktemp -d) &&
  opengrep scan --config /path/to/rules.yaml --json --output "$report_dir/opengrep.json" . &&
  opengrep_report="$report_dir/opengrep.json"
```

The reader accepts native JSON only. A report can contain matches alongside
parse errors or timeouts. Check the scanner's exit status and retain the
original JSON for run-wide details. The preview includes run metadata in
`report`. Stored findings keep the version, raw observations in
`source_data.results` and the diagnostic count in `source_data.scan_error_count`.
Cloud needs at least one supported finding.

### Assess an imported finding locally

Use the local record's `id` with `listLocalExternalFindings({ repository, id })`.
On a `CodexSecurity` instance, pass `record.evidence` to
`security.validate({ repositoryPath, finding: record.evidence })` using the
checkout for the scanned revision. This sends evidence to your configured
model provider and returns a separate assessment. The stored import remains
`not_assessed`. [SDK validation example](../../sdk/typescript/README.md#validate-an-existing-finding)
and [host-provided validation](../../sdk/typescript/docs/validate-records.md)
