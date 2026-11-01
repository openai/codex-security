# Import Semgrep findings

Vendor finding import and readback require `CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS=1`.
See the [opt-in instructions](../../sdk/typescript/docs/cli.md#import-vendor-findings-locally)
and [how saved scanner reports map to imported evidence](schema-guide.md).

Prefer native **Semgrep Code/SAST CLI or CI JSON** for this reader. It preserves
the scanner's original severity and source evidence. Self-contained SARIF 2.1.0
is a compatibility path. Both formats may be plain or gzip-compressed.

To import selected existing Code findings, see [Existing Platform findings](#existing-platform-findings).

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

Use the SDK to select exact IDs from **Semgrep Code (SAST)**. The official
[Guardian Codex plugin](https://docs.semgrep.dev/semgrep-guardian/ide-setup/codex)
can help identify them. For import, save the native
[project response](https://docs.semgrep.dev/api-reference/v1/projectsservice/get-project-details)
and the [Findings API pages](https://docs.semgrep.dev/api-reference/v1/findingsservice/list-code-supply-chain-or-ai-powered-detection-findings)
for that deployment, project ID and fully qualified Git ref (for example,
`refs/heads/release` or `refs/tags/release`), using `issue_type=sast` and
`dedup=false`. Use a Web API token with read access. Read through the pages
until you have the requested IDs. Use a project with an HTTP(S) repository URL.
For Git fetch URLs on an IP address, use its canonical spelling in the checkout
(for example, `127.0.0.1` or `[::1]`) so the HTTP host identifies the same source.
Each selected finding must match the requested ref. When the finding includes
a repository URL or project ID, each must match the selected project. If the URL
is absent, the native project ID and full repository name must match the decoded
path of the project URL.

Pass the response text directly to the selector to preserve numeric IDs and
other numeric evidence exactly. Keep the responses and selection together in a
private directory outside the checkout. Run this example in that directory
with the SDK installed. Local preview compares the project URL with Git’s
named fetch URLs offline. If a checkout only has legacy or unreadable Git remote
metadata, configure a normal named fetch URL first, for example
`git remote add scanner-origin <verified-url>`. Checkouts with empty or absent
legacy remote directories can also use Git's default fetch source. With legacy
metadata present, use a named remote with a nonempty final URL entry. The local
Git and SSH clients control SSH command overrides and DNS routing.

```js
import { readFile, writeFile } from "node:fs/promises";
import { selectSemgrepPlatformFindings } from "@openai/codex-security";

const selected = selectSemgrepPlatformFindings({
  deployment: "example",
  ref: "refs/heads/release",
  projectResponse: await readFile("project.json", "utf8"),
  findingsResponses: [await readFile("page-0.json", "utf8")],
  findingIds: ["101", "103"],
});
await writeFile("selected.json", JSON.stringify(selected), {
  flag: "wx",
  mode: 0o600,
});
```

Preview and import the saved selection into the local workbench:

```sh
codex-security publish findings /path/to/private/selected.json --to local --provider semgrep \
  --repository /path/to/project --source-key example/project/release/platform --dry-run
```

After review, repeat without `--dry-run` and confirm the import. Reusing the
same source key updates the same records, keyed by deployment, project ID,
product, ref and finding ID. Semgrep's native signed 64-bit IDs match across the SDK
and file workflows. For synthetic IDs above that range, the two workflows can
produce different keys, even from a new capture. To replay those IDs, use the
same workflow and preserve the original ID spelling and JSON type (number or
string).

Replay preserves the exact ref of an existing selection, including an older
short ref. The archive reader compares the stored ref as literal identity text
and never evaluates it as a Git revision. For URL-less rows with a matching
native repository ID and ref, the saved-file reader also accepts the complete
percent-encoded repository path. New captures require the decoded path.
Importing the same findings reports unchanged
records even if the API reordered JSON object keys. Use a separate source key
for CLI scans. The selected native finding is retained as JSON text in
`source_data.semgrepPlatformFindingJson`, including locations that cannot be mapped to the repository.
Relative Windows paths use forward slashes in projected code locations. If a
POSIX filename contains a literal backslash, consult the original
`location.file_path` for its exact spelling. The API row does not identify
the path convention. For a custom GitHub Enterprise host, supply the trusted
repository URL and `platform: "github"` in the SDK `sourceRepositories` option
when selecting and preparing the records. For an independently known self-managed
GitLab instance, `platform: "gitlab"` allows its HTTPS web and clone URLs to
differ by the usual `.git` suffix. For an internationalized hostname, use its
ASCII (Punycode) spelling in the Git SSH remote. OpenSSH can send the literal
UTF-8 hostname to DNS while the HTTPS project URL uses its ASCII spelling.

When passing normalized findings to the SDK, keep each generated Semgrep
`source_finding_id` with the native row it identifies. To migrate a row to a
caller-managed identity, use an opaque ID of your own. The generated Semgrep ID
requires the original scoped evidence on every import.

In a marked Platform export or selection, a partial legacy v1 object in
`source_data.finding` must retain its original collection scope when it
contains a repository ID, URL or name, a `ref` value (including `null`), or a
recognized `product` or `issue_type` (`sast`, `code`, `sca`, or `ai_sast`).
A non-null `found_dependency` or `vulnerability_identifier` also identifies
a Supply Chain finding, even when the row omits its product.
Keep the deployment, project, ref and product alongside the native finding,
including when you change its storage ID. For rows with canonical
`source_data.semgrepPlatformFindingJson`, the SDK checks that serialized
native finding. If unrelated SDK metadata uses the same v1 fields, move it to
another key such as `source_data.ticket`, or submit those rows in an ordinary
normalized batch without the Platform report marker or scope.

To publish the selection to Cloud, use the same file and source key:

```sh
codex-security publish findings selected.json --to cloud --provider semgrep \
  --repository https://github.com/example/project --source-key example/project/release/platform --dry-run
```

The publisher checks the original project's repository against the authorized destination, including
Supply Chain findings with no typed repository field. After reviewing the
preview, repeat without `--dry-run`.

New marked approvals that include caller-managed rows record the collection
scope for retry. On older approvals, the publisher checks the repository and
any scope retained by the original native records. A caller-managed row can
lack the original collection scope. Changing supplemental display metadata on
a retry cannot change the approved request bytes, account or destination.


## Collect a Platform project and branch

With a Web API token in `SEMGREP_APP_TOKEN`, collect all findings returned for a
project, exact ref and product. The collector looks up the project ID, requests
every page with server-side deduplication disabled, and stops on a failed or
overlapping page. Offset pagination does not provide a point-in-time snapshot.
For a multi-page result the collector also checks whether the first page's
membership has changed. Retry the collection if it reports a change.

A finding that identifies its repository only by name can use the project name,
the Git URL path, or the final path component of either. For any other name,
at least one finding in the collection must pair that name with the project's
repository ID or a matching repository URL. That finding can appear on any
page. Collection fails if the name has no such match. When one finding proves another
finding’s alias, the importer saves the verified label and resolved project ID in
`source_data.repositoryWitnessJson` on the name-only finding. The proving finding
retains its original repository fields in `source_data.semgrepPlatformFindingJson`.

SDK callers can pass a verified GitHub Enterprise repository as
`sourceRepositories: [{ url, platform: "github" }]` to
`collectSemgrepPlatformFindings` and the local reader. The reference must match
the selected project. It allows equivalent GitHub path casing, `.git` suffixes
and supported SSH URLs on that host.

Run the following commands from a trusted working directory outside the project
checkout. Each collection gets a new owner-only file. A failed collection
leaves earlier exports available for replay.

```sh
export CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS=1
report=$(mktemp ./semgrep-backlog.XXXXXX) &&
  codex-security import semgrep example/project --semgrep-deployment example \
    --semgrep-ref refs/heads/topic --semgrep-product sast --format json > "$report" &&
  codex-security publish findings "$report" --to local --repository /path/to/project \
    --provider semgrep --source-key example/project/topic --dry-run --format json
```

To preview this saved backlog in Cloud, keep its source key and choose the authorized repository.

```sh
codex-security publish findings "$report" --to cloud --provider semgrep \
  --repository https://github.com/example/project --source-key example/project/topic --dry-run
```

Use `--semgrep-product sca` for Supply Chain or `ai_sast` for AI-powered
detection. The default is `sast`. Use `--source-repository-url` on collection
when the project has no repository URL. The report records that mapping in
`sourceRepositoryUrl`, and stored finding evidence retains a null native project URL.
For SSH projects, the report stores the original address in `nativeProjectUrl` and the resolved HTTP(S) address in `project.url`.
It records any supplied mapping separately. Save the complete output from a successful
command. The importer checks the recorded finding count and repository/ref
claims. It retains each original finding as JSON text so large IDs survive replay. The reader also accepts saved v1 project exports with native object rows and decimal type witnesses.

To import a collected backlog with the TypeScript SDK, pass the normalized
report to the local importer. Reuse the source key when replaying the report.
You may filter the normalized findings array and retain the original read count.
Only submitted findings are imported.

```ts
const findings = normalizeSemgrepPlatformFindings(report);
const prepared = await prepareNormalizedLocalImport(findings, {
  provider: "semgrep",
  sourceKey: "example/project/topic",
  repository: checkout,
});
await prepared.import();
```

Supply Chain findings include native package versions, matching fix recommendations
and advisory IDs when Semgrep supplies them. With the same source key, importing identical Code findings that qualify for individual
selection reports them as unchanged when switching between a selection and a full collection.
See the [Semgrep Findings API](https://docs.semgrep.dev/api-reference/v1/findingsservice/list-code-supply-chain-or-ai-powered-detection-findings).

If you previously imported a v1 export with the development version that stored
each finding as an object, the first replay updates the existing SQLite record
to store the native finding as JSON text. Its local ID and source finding ID stay
the same, and its version increases once. Replaying the same evidence again
reports it as unchanged.

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

The CLI/CI and SARIF readers accept SAST only. Select SAST rules or a Code-only CI scan, since
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
