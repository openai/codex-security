# Import OpenGrep findings

Import native OpenGrep JSON, including gzip-compressed reports, into the local
workbench or Cloud. This reader accepts scanner output, not SARIF, normalized
JSONL, or an API summary. It preserves findings as unassessed scanner evidence.

From the source repository root, run OpenGrep with your selected rules:

```sh
opengrep scan --config /path/to/rules.yaml --json --output opengrep.json .
codex-security publish findings opengrep.json --to local \
  --provider opengrep --source-key opengrep/ORGANIZATION/PROJECT/BRANCH \
  --source-repository-url https://github.com/example/project \
  --repository . --dry-run --format json
```

Native JSON includes dataflow traces when the scanner produces them.
`--dataflow-traces` controls text and SARIF rendering; it is not required for JSON.
See OpenGrep's [output options](https://github.com/opengrep/opengrep/blob/main/src/osemgrep/cli_scan/Scan_CLI.ml)
and [JSON formatter](https://github.com/opengrep/opengrep/blob/main/src/osemgrep/reporting/Cli_json_output.ml).

Review the source repository, findings, exclusions, diagnostics, and destination.
Repeat the import without `--dry-run` to confirm interactively, or add `--yes`
after reviewing the preview. Local imports require no Cloud login or model call.
Read the stored evidence with:

```sh
codex-security findings imported . --format json
```

For Cloud, use the same report and source namespace with a Cloud destination:

```sh
codex-security publish findings opengrep.json --to cloud \
  --provider opengrep --source-key opengrep/ORGANIZATION/PROJECT/BRANCH \
  --source-repository-url https://github.com/example/project \
  --repository https://github.com/example/project --dry-run --format json
```

`--source-repository-url` is required and declares where the report came from.
The importer checks it against configured local Git remotes or the selected
Cloud repository. It does not infer the scanner's revision from the current
checkout. Cloud preview requires the existing ChatGPT login and an authorized
repository and environment; review the preview before approving the upload.

## Provider identity and evidence

`--provider opengrep` selects the OpenGrep reader. Local storage and Cloud use the
existing `semgrep` source-provider contract for compatibility, while typed
`scanner_origin` identifies **OpenGrep**. The preview shows this mapping. This
does not add a native OpenGrep provider to the Cloud service. Cloud publication
requires that deployment to support the existing Semgrep import contract;
successful local imports do not verify hosted availability.

Keep an OpenGrep-specific source key, such as
`opengrep/ORGANIZATION/PROJECT/BRANCH`, stable across runs. Occurrence IDs use the
rule, path, and source range. Multiple dataflow traces for the same occurrence
are grouped into one finding, retaining their original results. Moving a match
creates a new record; the earlier record remains stored. The raw scanner
fingerprints remain evidence and do not override this location-based identity.
Omitting a finding from a later report does not close or delete it.

The adapter retains rule metadata, source ranges, snippets, traces, ignored state,
and original severity. Normalized severity is `unknown`: OpenGrep rule levels
such as `ERROR` or `WARNING` are not a verified vulnerability severity. Ignored
matches remain source evidence, separate from a Codex assessment. Importing a
report does not assess findings, apply fixes, or create a completed Codex scan.

## Diagnostics and coverage

OpenGrep can return matches alongside parse failures, partial parsing, timeouts,
and other diagnostics. Warning diagnostics can accompany exit code 0 with the
default `--no-strict`; `--strict` changes warning handling, while `--error`
separately makes findings produce exit code 1. Inspect the report's diagnostics
and the scanner's exit status. Neither zero findings nor a successful exit
establishes complete coverage. See OpenGrep's
[error classification](https://github.com/opengrep/opengrep/blob/main/src/core/Core_error.ml).

The JSON preview and result retain the native report envelope, without `results`,
in `report`, including diagnostics and path metadata for an empty local report.
Individual stored findings retain the original observations in
`source_data.results` and a `source_data.scan_error_count`. Their compact
`source_data.report` retains only the scanner version, keeping scan-wide metadata
such as diagnostics and matching explanations outside each finding's evidence
budget. Full report metadata is
returned by the SDK and CLI; it is not saved as a separate durable scan record.
Keep the original JSON if you need the complete run metadata later.
Add OpenGrep's `--verbose` when collecting
skipped-target details; its [output handling](https://github.com/opengrep/opengrep/blob/main/src/osemgrep/reporting/Output.ml)
can omit those details otherwise.

Publication status describes import processing and acknowledged records, not
scanner coverage. A `complete` publication does not resolve scan diagnostics or
establish a clean security result. Cloud publication requires at least one
supported finding; an empty report can still be previewed locally with its
metadata. Review exclusions before approving either destination.

## Assess an imported finding locally

Copy an imported record's `id` from `findings imported --format json`. Use an
authorized checkout corresponding to the report's revision, then pass its
evidence to the existing SDK validator:

```ts
import {
  CodexSecurity,
  listLocalExternalFindings,
} from "@openai/codex-security";

const repositoryPath = "/path/to/repository";
const [record] = await listLocalExternalFindings({
  repository: repositoryPath,
  id: "IMPORTED_FINDING_ID",
});
if (!record) throw new Error("Imported finding not found.");

const security = new CodexSecurity();
try {
  const assessment = await security.validate({
    repositoryPath,
    finding: record.evidence,
  });
  console.log(record.id, assessment.disposition);
  console.log(assessment.report);
} finally {
  await security.close();
}
```

Validation uses configured Codex authentication and assesses source in a read-only,
offline session. It returns an assessment without running tests or PoCs, changing
the imported record's `not_assessed` state, or publishing it. See
[standalone validation](../../sdk/typescript/README.md#validate-an-existing-finding)
for dispositions and report handling. Hosts that already provide model execution
can use [validateRecords](../../sdk/typescript/docs/validate-records.md) instead.
