# Import OpenGrep findings

Use native OpenGrep JSON, plain or gzipped. A scan can return matches alongside
parse errors or timeouts. The preview shows both.

## Quick start

Run these commands from the root of the scanned checkout. Use a saved report or
generate one with OpenGrep.

**Saved report.** Set the path to your OpenGrep JSON file.

```sh
opengrep_report=../reports/opengrep.json
```

**Run OpenGrep.** Supply your rules and save the report outside the checkout.
Add `--verbose` for details about skipped targets. Check the scan's exit status.
[OpenGrep output options](https://github.com/opengrep/opengrep/blob/main/src/osemgrep/cli_scan/Scan_CLI.ml)

```sh
opengrep_report=
report_dir=$(mktemp -d) &&
  opengrep scan --config /path/to/rules.yaml --json --output "$report_dir/opengrep.json" . &&
  opengrep_report="$report_dir/opengrep.json"
```

**Preview the report.** Replace the example URL with the checkout's
credential-free HTTP(S) URL. Choose a distinct OpenGrep source key for your
organization, project and branch.

```sh
codex-security publish findings "$opengrep_report" --to local --repository . \
  --provider opengrep --source-repository-url https://github.com/example/project \
  --source-key opengrep/example/project/main --dry-run --format json
```

Check the findings, exclusions and `report.errors`, even if the findings list
is empty. A zero-result report with scanner errors fails the import. In the
Cloud preview, compare `findings` and `excluded` by `source_finding_id`.
An oversized trace can be excluded while other traces for the same occurrence
are retained. If the remaining group still exceeds 256 KiB, the reader
excludes the whole occurrence.
Keep `--provider opengrep` for both destinations.
[Save or publish and verify](README.md#save-or-publish-and-verify).

## Provider identity and evidence

Both destinations store `semgrep` as the provider and `OpenGrep` in
`details.scanner_origin`. The rule, path and range identify each occurrence.
Moving a match or changing the spelling of a Windows path can create a new
record. [Imported evidence](schema-guide.md)

The title is the rule ID and the description is the rule's message. The reader
groups traces at the same occurrence and keeps snippets, ignored state and
fingerprints when present. OpenGrep levels such as `ERROR` describe rule
matches, so the vulnerability severity is `unknown`. The local workbench,
private Cloud inbox and v3 Cloud repository publisher accept that value.

## Diagnostics and coverage

Keep the original report for run-wide diagnostics. The preview includes the
scan metadata in `report`. Each stored finding keeps the scanner version, the
observations in `source_data.results` and the diagnostic count in
`source_data.scan_error_count`.
