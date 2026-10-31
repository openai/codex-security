# Import Semgrep Code findings

Vendor finding import and readback require `CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS=1`.
See the [opt-in instructions](../../sdk/typescript/docs/cli.md#import-vendor-findings-locally)
and [how saved scanner reports map to imported evidence](schema-guide.md).

Prefer native **Semgrep Code/SAST CLI or CI JSON** for this reader. It preserves
the scanner's original severity and source evidence. Self-contained SARIF 2.1.0
is a compatibility path. Both formats may be plain or gzip-compressed.

For existing Semgrep Platform SAST findings, the SDK can
[import selected finding IDs](#import-selected-semgrep-platform-sast-findings-with-the-sdk)
from Web API responses. The CLI file reader accepts the CLI/CI reports described below.

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
can select and inspect existing findings. The separate local `semgrep mcp` server
also exposes `semgrep_findings`. Its output lacks continuation metadata.
[Official MCP implementation](https://github.com/semgrep/semgrep/blob/fe209763a4a2ccfcdf6434e6c332edc24a2f586e/cli/src/semgrep/mcp/server.py).

The [Semgrep Web API](https://docs.semgrep.dev/semgrep-appsec-platform/semgrep-api)
supports project lookups and paginated findings queries with a Web API token.
Supply its original JSON responses to the
[SDK selection adapter](#import-selected-semgrep-platform-sast-findings-with-the-sdk).
The adapter requires native finding IDs and repository/ref evidence.

## Evidence and identity

JSON preserves original severity, rule, CWE IDs, source range, snippets when
available and ignored state. SARIF retains its selected result and rule, including
trace and fix evidence. Its Critical and High ratings both become diagnostic
`error`, displayed here as High; prefer JSON when that distinction matters.
Original evidence stays in `source_data`, and source state stays separate from a
Codex assessment.

Cloud imports apply the service's evidence limits, including a maximum JSON
depth of 20. A deeply nested taint trace can exceed that bound and be excluded
with a reason in the Cloud preview. Local storage does not impose the Cloud
size or depth limits. Neither path flattens or truncates accepted traces.

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

### Import selected Semgrep Platform SAST findings with the SDK

Capture the project lookup and Findings API pages as original response text.
Pass a fully qualified ref, such as `refs/heads/topic` or `refs/tags/topic`, exactly as it appears in the findings.
Supply the HTTP(S) repository URL you independently associate with the target checkout.
The project URL and any finding URL must match this spelling. An exact finding URL
identifies the repository even if its display label has changed. A finding without a URL
must carry the project ID and a repository name that equals the namespace-qualified,
decoded path in the operator-supplied URL. A conflicting project ID is always rejected.
The local importer checks the checkout using its existing repository rules.

```ts
const selected = normalizeSelectedSemgrepPlatformFindings({
  deployment,
  ref,
  sourceRepositoryUrl,
  projectResponse,
  findingsResponses,
  findingIds,
});
const prepared = await prepareNormalizedLocalImport(
  selected,
  { provider: "semgrep", sourceKey, repository: checkout },
  { sourceRepositories: [{ url: sourceRepositoryUrl }] },
);
if (prepared.preview.excluded.length) {
  console.error(prepared.preview.excluded);
} else {
  await prepared.import();
}
```

Keep the same source key on replay. Finding identity includes the deployment, project ID,
SAST product, full ref, and native finding ID. Pass selected finding IDs as positive
decimal strings without leading zeros. Semgrep emits 64-bit finding IDs. The adapter
also accepts larger positive integer IDs in saved responses without rounding. The
stored evidence includes the selected finding and the project's ID, name and URL.
A record without a native rule name or message is excluded during preview.

Changes to key order or equivalent numeric spellings such as `2` and `2.0` leave
the stored record unchanged. Only repository-relative files become locations. Names
with URI-like prefixes and directory-only paths remain in the native evidence.
