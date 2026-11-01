# Import Semgrep Code findings

Import native Code CLI or CI JSON to retain severities and available snippets.
Self-contained Semgrep SARIF 2.1.0 is also supported. Either format can be gzipped.
For selected findings from the Semgrep Platform API, use the
[local SDK example](#import-selected-semgrep-platform-sast-findings-with-the-sdk).

## Quick start

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

Use SAST-only rules. Identifiable Supply Chain and Secrets results are
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
