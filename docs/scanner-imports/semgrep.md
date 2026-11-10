# Import Semgrep findings

Choose the route that matches your report or account. Each route uses a different
source of finding IDs.

| Starting point                                                   | What to collect                                                                                                                                                                                | Destination    |
| ---------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------- |
| [CLI or CI report](#quick-start)                                 | A Code-only JSON or self-contained SARIF 2.1.0 file, optionally gzipped. Native JSON keeps Semgrep severity and available snippets.                                                            | Local or Cloud |
| [Guardian in Codex](#import-selected-guardian-findings)          | Selected Code or Supply Chain findings through the connected Guardian account.                                                                                                                 | Local or Cloud |
| [Selected Web API IDs](#existing-platform-findings)              | Original project response and SAST findings pages for one full Git ref. Use the SDK to save a selection or [import it directly](#import-selected-semgrep-platform-sast-findings-with-the-sdk). | Local or Cloud |
| [Whole Platform project](#collect-a-platform-project-and-branch) | All findings for one project, full ref and product using a Web API token.                                                                                                                      | Local or Cloud |

## Quick start

From the scanned checkout root, choose a saved report or run Semgrep in the same shell.

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
`%SRCROOT%` paths can supply locations. The reader preserves the scanner's path
spelling, including backslashes in POSIX filenames and Windows paths.
Indexed artifacts and unresolved bases
stay in the raw evidence and need a fingerprint for identity. Keep the original
report for run-wide inventories, matching explanations and timing. Individual
findings keep their own match data.

If you call the JSON or SARIF normalizer from the SDK, pass `sourceRepositoryUrl`.
When calling `prepareNormalizedLocalImport` directly, pass the original SARIF
repository references in the third argument's `sourceRepositories`. Use
`{ url, platform: "github" }` for a verified custom GitHub host.

## Import selected Guardian findings

Sign in to
[Semgrep Guardian for Codex](https://docs.semgrep.dev/semgrep-guardian/quickstart).
Ask Codex to import the selected Code or Supply Chain findings from Guardian
into the local workbench or the matching Cloud repository. Specify the deployment, repository and full Git ref.
Guardian handles authentication through its existing connection.

Codex calls `get_semgrep_sast_findings` or `get_semgrep_supply_chain_findings`
with that scope. If you already selected rows from that tool, Codex can reuse
the successful response. It saves the exact string IDs and original selected
rows from `structuredContent.findings`. Guardian returns only the repository
name, so verify its SCM URL before saving the capture. The importer checks that URL against the checkout or the selected Cloud repository.
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

Preview the selected findings for the intended destination.

```sh
codex-security publish findings /path/to/private/guardian.json --provider semgrep \
  --to local --repository /path/to/project --source-key example/project/topic --dry-run --format json
```

For Cloud, replace `--to local --repository /path/to/project` with
`--to cloud --repository https://github.com/example/project`, using the URL
or Cloud ID of the repository you verified. After reviewing the destination,
findings and exclusions, repeat without `--dry-run` and confirm. Keep the
same capture and source key for a retry.

For normalized SDK imports, select the `semgrep` provider and keep each generated
Guardian ID with its original finding and collection scope. The repository URL
in each finding must agree with the report's mapping.

In the preview, check the rule and message in `evidence.title` and
`evidence.description`, the selected ref in `branch`, and the file and
starting line in `locations`. The verified SCM URL identifies the repository.
The original Guardian row is in `source_data.finding`. Guardian supplies
no end line, CWE IDs, package versions or fix versions in this summary. Guardian and Web API records keep
separate identities even when their IDs look identical. To verify a pair,
identify the same occurrence independently by deployment, mapped project,
product, full ref, rule and location. Then compare the complete ID strings,
preserving every digit.

## Existing Platform findings

Use these steps to select individual SAST findings by their Web API IDs.
With a read-authorized Web API token, save the native
[project response](https://docs.semgrep.dev/api-reference/v1/projectsservice/get-project-details)
and the [Findings API pages](https://docs.semgrep.dev/api-reference/v1/findingsservice/list-code-supply-chain-or-ai-powered-detection-findings)
for that deployment, project ID and fully qualified Git ref (for example,
`refs/heads/release` or `refs/tags/release`), using `issue_type=sast` and
`dedup=false`. Read through the pages until you have the requested IDs. Use a
project with an HTTP(S) repository URL.
Each selected finding must match the requested ref. When the finding includes
a repository URL or project ID, each must match the selected project. If the URL
is absent, the native project ID and full repository name must match the decoded
path of the project URL.

Pass the response text directly to the selector to preserve numeric IDs and
other numeric evidence exactly. Keep the responses and selection together in a
private directory outside the checkout. Run this example in that directory
with the SDK installed. Local preview compares the project URL with the
checkout's fetch URLs offline. If it cannot read the checkout's legacy remote
metadata, add a named fetch URL you have verified against that project.

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

From the directory that contains `selected.json`, preview the saved selection for the local checkout.

```sh
codex-security publish findings selected.json --to local --provider semgrep \
  --repository /path/to/project --source-key example/project/release/platform --dry-run --format json
```

For Cloud, preview the same file and source key against the connected repository.

```sh
codex-security publish findings selected.json --to cloud --provider semgrep \
  --repository https://github.com/example/project --source-key example/project/release/platform --dry-run --format json
```

Check the repository, finding IDs and exclusions for the destination you chose.
Cloud verifies the project's repository. After review, repeat the matching
command without `--dry-run` and confirm. [Verify the import](README.md#verify-the-import).

To preview the saved file with the SDK, run this in the same private directory.
After checking the destination and exclusions, call `await publication.publish()`
on the prepared object to confirm.

```js
import { prepareExternalPublication } from "@openai/codex-security";

const publication = await prepareExternalPublication("selected.json", {
  provider: "semgrep",
  repository: "https://github.com/example/project",
  sourceKey: "example/project/release/platform",
});
console.log(JSON.stringify(publication.preview, null, 2));
```

If you already have an in-memory selection, call
`normalizeSemgrepPlatformFindings(selected, repositoryUrl, "cloud")` and
pass the result to `prepareNormalizedExternalPublication()`.

## Import selected Semgrep Platform SAST findings with the SDK

Use the [project and SAST responses](#existing-platform-findings) described above.
On each page containing a selected ID, the SDK checks every row for conflicting
product information. Where rows contain only shared fields, the request's
`issue_type=sast` filter establishes the product.

**Check the project and ref.** Use the full ref from the findings. Verify the checkout's credential-free
HTTP(S) URL. The native `project.url` must match it exactly. Check the
repository fields on each selected finding.

- If a finding has a `repository.url`, it must match the verified URL exactly.
  That URL is enough when the ID is absent, even if display names differ.
  If several projects share the URL and ref, choose IDs from the intended project.
- If a finding supplies `repository.id`, it must match `project.id`. A finding
  without a URL also needs the matching ID and a `repository.name` equal to
  the decoded, namespace-qualified URL path, such as `example/project`.

**Preview the selection.**
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
  ref: "refs/heads/release",
  sourceRepositoryUrl,
  projectResponse: await readFile(projectFile, "utf8"),
  findingsResponses: await Promise.all(
    findingsFiles.map((file) => readFile(file, "utf8")),
  ),
  findingIds: ["101", "103"],
});
const prepared = await prepareNormalizedLocalImport(
  selected,
  {
    provider: "semgrep",
    sourceKey: "example/project/release/platform",
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
It verifies the selected project's repository even when every finding is excluded.
Only repository-relative files become locations. URI-like and directory-only
paths stay in the native evidence.

## Collect a Platform project and branch

With a Web API token in `SEMGREP_APP_TOKEN`, collect all findings returned for a
project, exact ref and product. The collector looks up the project ID, requests
every page with server-side deduplication disabled, and stops on a failed or
overlapping page. Offset pagination does not provide a point-in-time snapshot.
For a multi-page result the collector also checks whether the first page's
membership has changed. Retry the collection if it reports a change.

[Troubleshoot collection errors and rate limits](README.md#troubleshoot-semgrep-and-snyk-collection).

Run the following commands from a trusted working directory outside the project
checkout. Each collection gets a new owner-only file. A failed collection
leaves earlier exports available for replay.

```sh
report=$(mktemp ./semgrep-backlog.XXXXXX) &&
  codex-security import semgrep example/project --semgrep-deployment example \
    --semgrep-ref refs/heads/topic --semgrep-product sast --format json > "$report" &&
  codex-security publish findings "$report" --to local --repository /path/to/project \
    --provider semgrep --source-key example/project/topic --dry-run --format json
```

To preview this saved backlog in Cloud, keep its source key and choose the authorized repository.

```sh
codex-security publish findings "$report" --to cloud --provider semgrep \
  --repository https://github.com/example/project --source-key example/project/topic --dry-run --format json
```

Check the finding IDs and exclusions, then [confirm the import for the chosen
destination](README.md#save-or-publish-and-verify).

Use `--semgrep-product sca` for Supply Chain or `ai_sast` for AI-powered
detection. The default is `sast`. Use `--source-repository-url` on collection
when the project has no repository URL. The report records that mapping in
`sourceRepositoryUrl`, and stored finding evidence retains a null native project URL.
For SSH projects, the report stores the original address in `nativeProjectUrl` and the resolved HTTP(S) address in `project.url`.
It records any supplied mapping separately. Save the complete output from a successful
command. The importer checks the recorded finding count and repository/ref
claims. It retains each original finding as JSON text so large IDs survive replay. The reader also accepts saved v1 project exports with native object rows and decimal type witnesses.

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

When replaying v1 exports whose findings were stored as objects, the first
replay converts the stored finding to JSON text and increments its version.
Its local and source IDs stay the same.

## Replay saved Platform findings

Semgrep's native signed 64-bit finding IDs match across file and SDK imports.
For synthetic IDs above that range, repeat the original workflow and preserve
the ID's spelling and JSON type. A saved selection keeps its literal ref,
including older short refs. For a row without a URL but with a matching
project ID and ref, saved files also accept the complete percent-encoded
repository path. New selections require the decoded path.

**Repository mapping.** Local preview compares the project URL with the checkout's
named fetch URLs. For an IP address, use its canonical spelling, such as
`127.0.0.1` or `[::1]`. For an internationalized SSH hostname, use its ASCII
(Punycode) spelling. A verified custom host can be supplied in the
SDK's `sourceRepositories` option when selecting and preparing findings.
Use `platform: "github"` for GitHub Enterprise or `platform: "gitlab"` for a
self-managed GitLab instance. The latter allows the usual `.git` suffix.

**Native evidence.** Each selection keeps the native row as JSON text under
`source_data.semgrepPlatformFindingJson`, including locations that cannot be
mapped to the checkout. A valid relative `location.file_path` preserves its
spelling, including literal backslashes. Reordering JSON keys leaves stored
evidence unchanged. Use a separate source key for CLI scans.

**Normalized SDK records.** Keep each generated `source_finding_id` with its
native row and original deployment, project, ref and product. If you assign
your own opaque ID, retain that scope in a marked Platform batch. The SDK checks
the serialized native row when present. In legacy v1 `source_data.finding`,
repository fields, `ref` (even `null`), recognized `product` or `issue_type`,
and non-null `found_dependency` or `vulnerability_identifier` can establish
scope. Put unrelated metadata under a different key, such as
`source_data.ticket`, or submit it in a batch without a Platform marker.

**Cloud retries.** Cloud checks the original project's repository, including
for Supply Chain findings without a typed repository field. New approvals
retain the collection scope of caller-managed rows. Older approvals check
the repository and the scope retained in their evidence. Retry the original
input with the same account and destination. [Retry a Cloud submission](schema-guide.md#retry-a-cloud-submission).
