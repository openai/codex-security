# Import Semgrep findings

Import native Code CLI or CI JSON to retain severities and available snippets.
Self-contained Semgrep SARIF 2.1.0 is also supported. Either format can be gzipped.
For selected findings from the Semgrep Platform API, use the
[local SDK example](#import-selected-semgrep-platform-sast-findings-with-the-sdk).

## Quick start

For local import of selected existing Code findings, see [Existing Platform findings](#existing-platform-findings).

[Enable external imports](README.md#preview-a-report). From the scanned checkout root,
preview a saved SAST report using the repository's credential-free HTTP(S) URL
and a stable key for the organization, project and branch. If you need a report,
[capture one with Semgrep](#ci-artifacts).

For an existing report, set its path in the same shell.

```sh
semgrep_report=../reports/semgrep.json
```

Preview the selected report.

```sh
codex-security publish findings "$semgrep_report" --to local --repository . \
  --provider semgrep --source-repository-url https://github.com/example/project \
  --source-key example/project/main --dry-run --format json
```

## Import and verify

Check the declared source URL against the checkout's Git remote. With an empty
or wholly excluded report, the preview alone does not establish a repository match.
[Save or publish and verify](README.md#save-or-publish-and-verify) using the
same source URL and key. Cloud uses the `semgrep` provider.

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
Projected code locations retain the original spelling of a valid relative
`location.file_path`, including literal backslashes. The API row does not
identify the path convention. For a custom GitHub Enterprise host, supply the trusted
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

## Reference

### CI artifacts

Use a saved artifact from a Code-only `semgrep ci` job. Policy and baseline
determine which matches it contains. Exit 1 can indicate blocking findings
even when the report is valid. Check the job's product selection and exit status.

To create a local report, run Semgrep from the repository root with your
SAST rules. Write to a private directory outside the checkout. After a
successful scan, use that file in the preview above. [Semgrep CLI reference](https://docs.semgrep.dev/cli-reference)

```sh
semgrep_report=
report_dir=$(mktemp -d) &&
  semgrep scan --config /path/to/sast-rules.yaml --json-output "$report_dir/semgrep.json" . &&
  semgrep_report="$report_dir/semgrep.json"
```

### Evidence and identity

Native JSON retains the result, rule, CWE IDs, range, snippets and ignored
state when supplied. SARIF retains the selected rule and result, including
traces and fixes. SARIF `error` imports as high even if the original severity
was critical. Check Cloud exclusions for deeply nested traces.
[Semgrep output fields](https://docs.semgrep.dev/semgrep-appsec-platform/json-and-sarif)

The match ID uses JSON `extra.fingerprint` or SARIF `matchBasedId/v1`.
Reimporting the same fingerprint under the same source key and repository
updates its location. If the fingerprint is absent or says `requires login`,
the ID uses rule, literal path and range. Moving the match then creates a new
record. [Imported evidence and identity](schema-guide.md)

For CLI/CI JSON and SARIF, use SAST-only rules. Identifiable Supply Chain and Secrets results are
excluded, but SARIF can omit the product metadata. Scan errors or unsuccessful
SARIF invocations stop import. Direct artifact URIs and native `%SRCROOT%`
paths can supply locations. Indexed artifacts or unresolved bases remain in
raw evidence and require a fingerprint for identity. Use the original report
for run-wide inventories and timing.

SDK callers pass `sourceRepositoryUrl` to the native or SARIF normalizer.
When using `prepareNormalizedLocalImport` directly, pass the original SARIF
repository references in the third argument's `sourceRepositories`. Use
`{ url, platform: "github" }` for a verified custom GitHub host.

### Import selected Semgrep Platform SAST findings with the SDK

Request `issue_type=sast` and save the original project lookup and findings
pages as response text. Pass each findings page separately. The SDK checks
every row on pages that contain a selected ID for conflicting product evidence.
When a page contains only fields shared by several products, the original
request filter identifies the product.

To find existing Code findings in Codex, sign in to Guardian and ask for the
deployment, project and full ref you want to inspect. Guardian returns a
selection for review. For this SDK import, confirm the candidate findings in
the original Web API results and use the IDs from those records. The SDK also
accepts saved responses from an authorized operator. Fetching new responses
directly requires Web API read access.
[Guardian sign-in](https://docs.semgrep.dev/semgrep-guardian/quickstart) ·
[Query existing findings](https://semgrep.dev/products/product-updates/query-your-semgrep-findings-by-asking-guardian/) ·
[Findings Web API](https://docs.semgrep.dev/api-reference/v1/findingsservice/list-code-supply-chain-or-ai-powered-detection-findings)

Use the full ref from the findings, such as `refs/heads/main` or
`refs/tags/v1`. Supply the credential-free HTTP(S) repository URL you verified
for the checkout. The native `project.url` and any selected
`finding.repository.url` must match it exactly.

- An exact finding URL is sufficient when `repository.id` is absent, even if
  the display names differ. If several projects share the URL and ref, choose
  the finding IDs from the intended project.
- Any `repository.id` supplied must match `project.id`. When the finding has
  no URL, it must include both the matching project ID and a `repository.name`
  equal to the decoded, namespace-qualified path in the supplied URL, such as
  `example/project`.

[Enable external imports](README.md#preview-a-report). In a Node.js project
you control outside the scanned checkout, install `@openai/codex-security`
and save this script as `preview-semgrep.mjs`. Set the deployment, ref,
repository URL, source key and finding IDs for your selection. Pass the IDs as
positive decimal strings without leading zeros to preserve 64-bit IDs.

```js
import { readFile } from "node:fs/promises";
import {
  normalizeSelectedSemgrepPlatformFindings,
  prepareNormalizedLocalImport,
} from "@openai/codex-security";

const [checkout, projectFile, ...findingsFiles] = process.argv.slice(2);
const sourceRepositoryUrl = "https://github.com/example/project";
const selected = normalizeSelectedSemgrepPlatformFindings({
  deployment: "example",
  ref: "refs/heads/main",
  sourceRepositoryUrl,
  projectResponse: await readFile(projectFile, "utf8"),
  findingsResponses: await Promise.all(
    findingsFiles.map((file) => readFile(file, "utf8")),
  ),
  findingIds: ["123"],
});
const prepared = await prepareNormalizedLocalImport(
  selected,
  {
    provider: "semgrep",
    sourceKey: "example/project/platform/main",
    repository: checkout,
  },
  { sourceRepositories: [{ url: sourceRepositoryUrl }] },
);
console.log(JSON.stringify(prepared.preview, null, 2));
```

Run the script from your SDK project. Pass the checkout, project response and
each saved findings page as absolute paths.

```sh
node preview-semgrep.mjs /path/to/checkout /path/to/reports/semgrep-project.json \
  /path/to/reports/semgrep-findings-1.json
```

Review the repository, findings and exclusions. To save the selection, append
`await prepared.import()` to a copy of the script in your SDK project and run
that copy with the same inputs.
[Read back the local records](README.md#save-or-publish-and-verify) using the
checkout path from the preview.
Keep the same source key on replay. Each occurrence is identified by deployment,
project ID, SAST product, full ref and native finding ID.

The stored evidence includes the selected finding and the project's ID, name
and URL. Larger positive integer IDs are retained without rounding. Equivalent
numeric spellings (`2` and `2.0`) and key order do not change the stored record.
Preview excludes findings that lack both a native rule name and a message.
Only repository-relative files become locations. URI-like and directory-only
paths stay in the native evidence.
