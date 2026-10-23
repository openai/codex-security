# Import Semgrep Code findings

Prefer native **Semgrep Code/SAST CLI or CI JSON** for this reader. It preserves
the scanner's original severity and source evidence. Self-contained SARIF 2.1.0
is a compatibility path. Both formats may be plain or gzip-compressed.

This reader does not accept Platform API, Guardian or MCP response envelopes,
or a general Supply Chain or Secrets feed. Those products and acquisition
contracts require separate mappings; installing a plugin does not change the
formats accepted here.

To produce JSON locally, run the following from the source repository root with
your selected SAST rules. This runs a new scan; it does not retrieve earlier
findings from Semgrep AppSec Platform.

```sh
semgrep scan --config /path/to/sast-rules.yaml --json-output semgrep.json .
codex-security publish findings semgrep.json --to local \
  --provider semgrep --source-key ORGANIZATION/PROJECT/BRANCH \
  --source-repository-url https://github.com/example/project \
  --repository . --dry-run --format json
```

Existing CI jobs can add `--json-output semgrep.json` to their SAST scan and pass
that artifact to the publisher. With authenticated `semgrep ci`, select `--code`;
its output follows the job's policy and PR/baseline scope and may contain only new
blocking findings. It is not a complete inventory of Platform findings.
[CLI output and scope reference](https://docs.semgrep.dev/cli-reference).

Review the findings, source repository and exclusions, then repeat the command
without `--dry-run` and confirm the import, or add `--yes` after review. Local
imports require no Cloud login and store unassessed evidence in the workbench
SQLite database. Read it with `codex-security findings imported . --format json`.
Repeated imports with the same source identity update the same records; omitted
records remain stored. See the movement behavior under Evidence and identity.
They do not create a completed scan or automatically assess or patch findings.

For Cloud, use the same report and source selection with a Cloud destination:

```sh
codex-security publish findings semgrep.json --to cloud \
  --provider semgrep --source-key ORGANIZATION/PROJECT/BRANCH \
  --source-repository-url https://github.com/example/project \
  --repository https://github.com/example/project --dry-run --format json
```

Keep the same source key for one organization, project and branch across runs.
`--source-repository-url` declares where the report came from; the importer checks
it against configured local Git remotes or the Cloud destination. Cloud requires
an authorized repository and support for the `semgrep` provider. Local SARIF
imports also check every original `versionControlProvenance.repositoryUri` on
accepted findings. Unknown Git hosts keep case-sensitive repository paths.

## Existing Platform findings

Semgrep's official
[Guardian Codex plugin](https://docs.semgrep.dev/semgrep-guardian/ide-setup/codex)
can select and inspect existing findings. Its output is not accepted by this
reader. A Platform importer needs a mapping qualified against the hosted tools'
actual responses, repository/ref filters and pagination using an authorized test
tenant. The separate local `semgrep mcp` server also exposes `semgrep_findings`,
but its current tool
returns a limited list without continuation metadata. It cannot establish a
complete export. [Official MCP implementation](https://github.com/semgrep/semgrep/blob/fe209763a4a2ccfcdf6434e6c332edc24a2f586e/cli/src/semgrep/mcp/server.py).

For an automated acquisition path, Semgrep's
[findings API](https://docs.semgrep.dev/semgrep-appsec-platform/semgrep-api) supports
pagination with a Web API token. Its Platform finding objects
need their own mapping into the shared publisher; they are not CLI `results`
objects. Do not rename an API/MCP response to `semgrep.json` or reconstruct a scan
report from a summary. No manual website export is required for either path.

## Evidence and identity

JSON preserves original severity, rule, CWE IDs, source range, snippets when
available and ignored state. SARIF retains its selected result and rule, including
trace and fix evidence. Its Critical and High ratings both become diagnostic
`error`, displayed here as High; prefer JSON when that distinction matters.
Original evidence stays in `source_data`, and source state stays separate from a
Codex assessment.

Both local and Cloud file imports currently apply the shared Cloud evidence
bounds, including a maximum JSON depth of 20. Deeply nested native taint traces
can exceed that bound and are excluded with a reason in the preview. The reader
preserves accepted source evidence without flattening or truncating traces.

Keep the supplied JSON `extra.fingerprint` or SARIF `matchBasedId/v1`
fingerprint. If a later report supplies the same fingerprint after the code
moves, importing it under the same repository and source key updates that record
with the new range; the raw fingerprint stays in `source_data`.

Community Edition may omit the fingerprint or emit `requires login`. The fallback
identity uses the rule, literal path and range. Moving such a finding creates a
second record, and the earlier record remains stored. The importer does not
infer that they are the same finding, merge them or delete the earlier record.
Read back both with `codex-security findings imported . --format json` before
selecting evidence for assessment. A current checkout does not establish the
report's revision or branch.

The adapter accepts SAST only. Select SAST rules or a Code-only CI scan, since
SARIF may omit enough product metadata to distinguish Secrets. Identifiable
Supply Chain and Secrets records are excluded. Reports with scan errors,
unsuccessful SARIF invocations or scan-error notifications are rejected. The
preview reports invalid findings and duplicate source identities before import.

SARIF supports direct artifact URIs and Semgrep's native `%SRCROOT%` marker without
a base definition. Native paths retain literal percent characters; direct URIs
are decoded once. Indexed artifacts and unresolved bases remain in original
evidence without mapped repository locations. CE records with these references
are excluded because they lack a usable identity. JSON scan-wide path inventories
and timing tables are omitted from individual findings. SARIF artifact inventories
are omitted when they are unrelated to the selected finding; required inventories
retain their original entries and indexes. Empty external-property reference
containers are accepted, while actual external file references are rejected.

SDK callers pass `{ sourceRepositoryUrl }` to `normalizeSemgrepFindings`,
`normalizeSemgrepSarif`, or `readSemgrepFindings`. When passing that normalized
output directly to `prepareNormalizedLocalImport`, supply the original SARIF
repository references in the third argument's `sourceRepositories`; the file
importer forwards them automatically. For an independently known GitHub custom
host, use `{ url, platform: "github" }` for its references. The Semgrep file reader
accepts native reports, not normalized JSON/JSONL exports.
See the [native output fields](https://docs.semgrep.dev/semgrep-appsec-platform/json-and-sarif).
