# Import Semgrep Code findings

Use native Semgrep Code CLI or CI JSON to keep severity and available snippets.
You can also import self-contained Semgrep SARIF 2.1.0. Either format can be
gzipped. For selected SAST findings from the Platform API, use the
[local SDK example](#import-selected-semgrep-platform-sast-findings-with-the-sdk).

## Quick start

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

Use SAST-only rules. The reader excludes results it can identify as Supply
Chain or Secrets, but SARIF can omit the product metadata. Scan errors or an
unsuccessful SARIF invocation stop the import. Direct artifact URIs and native
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

To select findings in Codex, sign in to Guardian and ask for the deployment,
project and full ref. Confirm the IDs in the original Web API results.
You can use saved responses from an authorized operator. Fetching new pages
requires Web API read access.
[Guardian sign-in](https://docs.semgrep.dev/semgrep-guardian/quickstart) ·
[Query existing findings](https://semgrep.dev/products/product-updates/query-your-semgrep-findings-by-asking-guardian/) ·
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
