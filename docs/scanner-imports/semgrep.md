# Import Semgrep findings

Use native Semgrep Code CLI or CI JSON to keep severity and available snippets.
You can also import self-contained Semgrep SARIF 2.1.0. Either format can be
gzipped. For selected SAST findings from the Platform API, use the
[local SDK example](#import-selected-semgrep-platform-sast-findings-with-the-sdk).

## Quick start

In Codex, [import selected Guardian findings](#import-selected-guardian-findings) with your existing Semgrep sign-in.
For a whole project and ref, use the [Web API collector](#collect-a-platform-project-and-branch).

[Enable external imports](README.md#preview-a-report). From the scanned checkout
root, choose a saved report or run Semgrep in the same shell.

**Saved report.** Set the path to your Code report. For a `semgrep ci`
artifact, check that the job scanned only Code. The policy and baseline
determine which matches the report contains. Exit 1 can mean the job found
blocking matches and produced a valid report.

```sh
semgrep_report=../reports/semgrep.json
```

**Run Semgrep.** Supply your SAST rules and write the JSON to a private
directory outside the checkout. [Semgrep CLI reference](https://docs.semgrep.dev/cli-reference)

```sh
semgrep_report=
report_dir=$(mktemp -d) &&
  semgrep scan --config /path/to/sast-rules.yaml --json-output "$report_dir/semgrep.json" . &&
  semgrep_report="$report_dir/semgrep.json"
```

**Preview the report.** Replace the example URL with the checkout's
credential-free HTTP(S) URL. Use a stable source key for the organization,
project and branch.

```sh
codex-security publish findings "$semgrep_report" --to local --repository . \
  --provider semgrep --source-repository-url https://github.com/example/project \
  --source-key example/project/main --dry-run --format json
```

Check the findings, exclusions and source URL. If the preview has no accepted
findings, verify the URL against the checkout's Git remote yourself. Keep the
same URL and key when you [save locally or publish to Cloud](README.md#save-or-publish-and-verify).

## Import selected Guardian findings

Enable [external imports](README.md#preview-a-report) and sign in to
[Semgrep Guardian for Codex](https://docs.semgrep.dev/semgrep-guardian/quickstart).
Ask Codex to import the selected Code or Supply Chain findings from Guardian
into the local workbench. Specify the deployment, repository and full Git ref.
Guardian handles authentication through its existing connection.

Codex calls `get_semgrep_sast_findings` or `get_semgrep_supply_chain_findings`
with that scope. If you already selected rows from that tool, Codex can reuse
the successful response. It saves the exact string IDs and original selected
rows from `structuredContent.findings`. Guardian returns only the repository
name, so confirm its SCM URL against the checkout before saving the capture.
A missing or ambiguous selected ID stops the import. Guardian defaults to 20
open or reviewing results and returns at most 1,000 per call.

For SDK callers, `guardianClient` below is your connected Guardian MCP client.
Pass the filters used for your selection, including states for any closed or
ignored findings. Save the capture in a private directory outside the checkout.

```js
import { writeFile } from "node:fs/promises";
import { collectSelectedSemgrepGuardianFindings } from "@openai/codex-security";

const capture = await collectSelectedSemgrepGuardianFindings(
  {
    request: {
      name: "get_semgrep_sast_findings",
      arguments: {
        deployment_name: "example",
        repository_name: "example/project",
        ref: "refs/heads/topic",
      },
    },
    findingIds: ["123"],
    sourceRepositoryUrl: "https://github.com/example/project",
  },
  { callTool: (request) => guardianClient.callTool(request) },
);
await writeFile("guardian.json", JSON.stringify(capture), {
  flag: "wx",
  mode: 0o600,
});
```

Preview before confirming the import. Use the same file and source key on replay.

```sh
codex-security publish findings /path/to/private/guardian.json --provider semgrep \
  --to local --repository /path/to/project --source-key example/project/topic --dry-run --format json
```

Guardian records retain the original MCP fields. The summary omits end lines,
CWEs, package versions and fix versions. Guardian and Web API records keep
separate identities even when their IDs look identical. To verify a pair,
identify the same occurrence independently by deployment, mapped project,
product, full ref, rule and location. Then compare the complete ID strings,
preserving every digit.

## Existing Platform findings

Use the SDK to select exact Web API IDs from **Semgrep Code (SAST)** when you
have original Web API responses. For this format, save the native
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

To preview a Cloud publication in the SDK, append this to the script that
created `selected`. Set `repository` to the verified URL of the destination.

```js
import {
  normalizeSemgrepPlatformFindings,
  prepareNormalizedExternalPublication,
} from "@openai/codex-security";

const repository = "https://github.com/example/project";
const findings = normalizeSemgrepPlatformFindings(
  selected,
  repository,
  "cloud",
);
const publication = await prepareNormalizedExternalPublication(findings, {
  provider: "semgrep",
  repository,
  sourceKey: "example/project/release/platform",
});
console.log(JSON.stringify(publication.preview, null, 2));
```

Review the destination, findings and exclusions. To publish the approved
selection, call `await publication.publish()` on the prepared object. Reuse
the same source key for subsequent imports.

## Collect a Platform project and branch

With a Web API token in `SEMGREP_APP_TOKEN`, collect all findings returned for a
project, exact ref and product. The collector looks up the project ID, requests
every page with server-side deduplication disabled, and stops on a failed or
overlapping page. Offset pagination does not provide a point-in-time snapshot.
For a multi-page result the collector also checks whether the first page's
membership has changed. Retry the collection if it reports a change.

On HTTP 429, the collector retries the same GET once if `Retry-After` specifies
a wait of 10 seconds or less, in whole seconds or as an HTTP date. Zero or a
past date triggers an immediate retry. Cancellation stops the wait. Failed requests report
the HTTP status and up to 64 KiB of the vendor response.

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

Native JSON retains the result, rule, CWE IDs, range, snippets and ignored
state when present. SARIF retains the selected rule and result, including
traces and fixes. SARIF `error` imports as high even if Semgrep assigned
critical severity. Check Cloud exclusions for deeply nested traces.
[Semgrep output fields](https://docs.semgrep.dev/semgrep-appsec-platform/json-and-sarif)

The match ID comes from JSON `extra.fingerprint` or SARIF `matchBasedId/v1`.
Under the same source key and repository, the fingerprint lets you update a
match when it moves. If the fingerprint is missing or says `requires login`,
the ID comes from the rule, literal path and range. Moving that match
creates a new record. [Imported evidence and identity](schema-guide.md)

For CLI/CI JSON and SARIF, use SAST-only rules. The reader excludes results
it recognizes as Supply Chain or Secrets, but SARIF can omit product metadata.
Scan errors or an unsuccessful SARIF invocation stop the import. Direct artifact URIs and native
`%SRCROOT%` paths can supply locations. Indexed artifacts and unresolved bases
stay in the raw evidence and need a fingerprint for identity. Keep the original
report for run-wide inventories and timing.

If you call the JSON or SARIF normalizer from the SDK, pass `sourceRepositoryUrl`.
When calling `prepareNormalizedLocalImport` directly, pass the original SARIF
repository references in the third argument's `sourceRepositories`. Use
`{ url, platform: "github" }` for a verified custom GitHub host.

## Import selected Semgrep Platform SAST findings with the SDK

**Collect the selection.** Request `issue_type=sast` and save the original
project lookup and each findings page as response text. On any page with a
selected ID, the SDK checks every row for conflicting product information.
When rows contain only fields shared across products, the request filter
establishes that the findings are SAST.

Use the IDs from the original Web API results for this SDK import. The SDK
accepts saved responses from an authorized operator. Fetching new Web API
responses requires read access. For selections made in Codex, use the
[Guardian workflow](#import-selected-guardian-findings).
[Findings Web API](https://docs.semgrep.dev/api-reference/v1/findingsservice/list-code-supply-chain-or-ai-powered-detection-findings)

**Check the project and ref.** Use the full ref from the findings, such as
`refs/heads/main` or `refs/tags/v1`. Verify the checkout's credential-free
HTTP(S) URL. The native `project.url` must match it exactly. Check the
repository fields on each selected finding.

- If a finding has a `repository.url`, it must match the verified URL exactly.
  That URL is enough when the ID is absent, even if display names differ.
  If several projects share the URL and ref, choose IDs from the intended project.
- If a finding supplies `repository.id`, it must match `project.id`. A finding
  without a URL also needs the matching ID and a `repository.name` equal to
  the decoded, namespace-qualified URL path, such as `example/project`.

**Preview the selection.** [Enable external imports](README.md#preview-a-report).
In a Node.js project you control outside the scanned checkout, install
`@openai/codex-security` and save this script as `preview-semgrep.mjs`.
Set the deployment, ref, repository URL, source key and finding IDs. Use
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

From your SDK project, pass the checkout, project response and each findings
page as absolute paths.

```sh
node preview-semgrep.mjs /path/to/checkout /path/to/reports/semgrep-project.json \
  /path/to/reports/semgrep-findings-1.json
```

Check the repository, findings and exclusions. To save the selection, append
`await prepared.import()` to a copy of the script and run the copy with the
same inputs. [Read back the local records](README.md#verify-the-import).

Each occurrence uses the deployment, project ID, SAST product, full ref and
native finding ID. Reuse the same source key for later imports. The stored
evidence includes the selected finding and the project's ID, name and URL.
The SDK preserves large positive IDs exactly. Key order and equivalent numeric
spellings (such as `2` and `2.0`) leave the stored record unchanged.

The preview excludes findings that lack both a native rule name and a message.
Only repository-relative files become locations. URI-like and directory-only
paths stay in the native evidence.
