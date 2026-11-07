# `@openai/codex-security`

Run Codex Security from TypeScript or the command line to find, validate, and fix
security vulnerabilities in your code. The package includes the Codex runtime,
security plugin, and TypeScript declarations. It uses ES modules.

- Scan repositories, selected paths, or Git changes. Deep scans repeat Standard
  scans of the selected scope and merge their findings after each batch.
- Validate findings, generate patches, and verify existing fixes.
- Draft security policies and retain threat models.
- Review saved findings, identify duplicates, classify severity, and suggest owners.
- Import GitHub code scanning alerts, export SARIF, JSON, or CSV, and publish
  findings to Linear or a findings service.
- Import saved scanner reports locally or publish them to Codex Security Cloud.
  See the [scanner import guides](https://github.com/openai/codex-security/blob/main/docs/scanner-imports/README.md) for supported vendors and formats.
- Automate scans across repositories and project components.

See the [CLI reference](docs/cli.md),
[findings guide](docs/findings-service.md), or
[online documentation](https://learn.chatgpt.com/docs/security) for setup and examples.

Before version `1.0.0`, minor releases may change the public API.

## Install

Supported runtimes:

- Node.js 22.13.0+ within 22.x, or Node.js 24.x or 26.x, on macOS, Linux, or Windows.
- Python 3.10+ for scans, policy generation, exports, scan history, and saved
  findings. Python 3.10 also needs `tomli`.

Compressed Codex session logs (`.jsonl.zst`) are readable on all supported Node.js
versions. The bundled streaming decoder reads concatenated frames and reports
truncated streams as collection errors.

### Install the CLI

Install the CLI globally:

```bash
npm install --global @openai/codex-security
cs --version
```

Continue with the [CLI walkthrough](#cli). You can use the full command
`codex-security` if `cs` names another tool on your PATH. If installation
fails with `EEXIST`, use `npx @openai/codex-security` in place of `cs`.

### Install the TypeScript SDK

Install the package locally in your TypeScript project:

```bash
npm install @openai/codex-security
```

## Authentication

Sign in with ChatGPT:

```bash
cs login
```

If you installed only the SDK locally, sign in from your project directory:

```bash
npx @openai/codex-security login
```

In the following CLI examples, replace `cs` with `npx @openai/codex-security`
when using a local SDK installation, including the API-key login example below.

For CI, set `OPENAI_API_KEY` or `CODEX_API_KEY` in the scan process's environment.
These keys apply to the current command without replacing your saved login.
To save an API key instead, pass it on stdin:

```bash
printenv OPENAI_API_KEY | cs login --with-api-key
```

SDK calls accept `auth: "auto" | "chatgpt" | "api-key"`. The default, `"auto"`,
prefers `OPENAI_API_KEY`, then `CODEX_API_KEY`, then stored credentials.
Use `"chatgpt"` to ignore environment API keys. The CLI uses the same `--auth`
values and prompts in an interactive terminal when both credential types are available.

Some cybersecurity requests and protected findings require
[Trusted Access for Cyber](https://chatgpt.com/cyber) approval. See the
[authentication reference](docs/cli.md#authentication) for providers, stored
credentials, and Cyber access program selection.

### Remote login with SSH forwarding

On a remote or headless machine, try `login --device-auth` if your workspace
allows it. Otherwise, open an SSH tunnel from your local machine:

```bash
ssh -L 1455:localhost:1455 user@remote-host
```

Run `cs login` in that SSH session, then open its sign-in
URL in your local browser. Keep SSH connected until login finishes.

### Amazon Bedrock

Bedrock scans use AWS credentials and model access. They do not require
`codex-security login` or an OpenAI API key. See the
[Bedrock guide](https://github.com/openai/codex-security/blob/main/docs/bedrock.md)
for setup, model selection, and verification.

## Run a scan from TypeScript

Scan a repository you own or have permission to assess:

```ts
import { CodexSecurity } from "@openai/codex-security";

const security = new CodexSecurity();

try {
  const result = await security.run("/path/to/repository");

  console.log(result.reportPath);
  console.log(result.findings.findings);

  if (result.hasFindingsAtOrAbove("high")) {
    process.exitCode = 1;
  }
} finally {
  await security.close();
}
```

Omitting `outputDir` saves results in the private Codex Security state directory.
To choose another location, use a new or empty directory outside the scanned
repository and its enclosing Git worktree. Existing output directories keep their
permissions; newly created directories are private to you by default.

### Read results

| Result                            | Contents                                                         |
| --------------------------------- | ---------------------------------------------------------------- |
| `findings.findings`               | Findings from this scan.                                         |
| `reportPath`                      | Path to the Markdown report.                                     |
| `review.excludedPaths`            | Additional paths the scan excluded.                              |
| `repositoryFindings`              | This scan's findings plus earlier open findings, when available. |
| `sarifPath`                       | SARIF export path, or `null`.                                    |
| `threatModel` / `threatModelPath` | Saved threat model and document path; either can be `null`.      |
| `cost`                            | Estimated model usage cost, or `null` when unavailable.          |

Read `result.manifest.scan.status` and `result.manifest.scan.scope` alongside
`result.review.excludedPaths` to see the outcome, the requested scope and any
additional exclusions. A completed scan can report zero findings within that scope.

If the run retained a draft or checkpoint, its `reviewState.deferred` lists
unfinished work and `reviewState.openQuestions` lists follow-up questions.
See [saved scan files](docs/cli.md#understand-scan-scope-and-follow-up-work)
for the current and legacy layouts. Reports and logs can include source code,
vulnerability details and credentials. Review them before sharing.

Saved-history excerpts use scanned Git objects without fetching missing data.
Working-tree diff scans omit excerpts, as do historical scans whose source or
scope cannot be established. Unambiguous older scans remain readable. An omitted
excerpt does not remove the finding.

The SDK does not set your process's exit status. Use `hasFindingsAtOrAbove()`
as in the example to enforce a severity threshold.

### Scan options and output

Pass scan settings as the second argument to `run()`. The following SDK snippets
assume an open `CodexSecurity` client named `security`; close it when finished.

```ts
const result = await security.run("/path/to/repository", {
  target: ["src", "tests"],
  knowledgeBasePaths: ["/path/to/architecture.md"],
  scanPrompt: "Focus on authentication and authorization.",
  outputDir: "/path/outside/repository/results",
  maxCostUsd: 5,
});
```

| Option                                      | Use                                                                            |
| ------------------------------------------- | ------------------------------------------------------------------------------ |
| `target`                                    | Whole repository (default), repository-relative paths, or a `DiffTarget`.      |
| `mode`                                      | `"standard"` (default) or `"deep"`. Deep scans support repositories and paths. |
| `knowledgeBasePaths`                        | Supporting text, PDF, DOCX files, or directories.                              |
| `scanPrompt` / `scanPromptFile`             | Additional scan instructions. Inline text takes precedence.                    |
| `validationPrompt` / `validationPromptFile` | Custom validation instructions for standard scans.                             |
| `postScanPrompt` / `postScanPromptFile`     | Follow-up instructions after the scan.                                         |
| `ownerSuggestions`                          | Write optional owner suggestions after a committed scan (default: `false`).    |
| `outputDir`                                 | Results directory; omit to use the state directory.                            |
| `archiveExisting`                           | Move previous results aside before reusing `outputDir`.                        |
| `maxCostUsd`                                | Stop at an estimated model cost; see [cost limits](#progress-and-cost).        |
| `signal`                                    | An `AbortSignal` to cancel the scan.                                           |

The exported `ScanOptions` type describes all options and callbacks. For full
CLI behavior, see [scan options and output](docs/cli.md#scan-options-and-output).

Set `ownerSuggestions: true` or run `codex-security scan --owner-suggestions`
to write `owner-suggestions.json` beside a completed committed Git scan. Project
files can set `scan.owner_suggestions: true`. The report uses the scan's finding
IDs and frozen revision; it does not change the sealed findings or assign users.
Owner failures leave the base scan completed and appear as
`result.ownerSuggestionsError`; successful reports set `result.ownerSuggestionsPath`.
The scan records optional owner hints within its existing session and budget.
Report finalization applies CODEOWNERS and validates Git evidence without another
model call, including when `maxCostUsd` is set. Missing hints abstain and invalid
hints produce per-finding errors. Working-tree and directory snapshots are
unsupported. Explicit owner-only analysis remains available through `suggestOwners`
and `suggest-owners`, sharing the same evidence validation and report code.

### Scan a diff

```ts
import { DiffTarget } from "@openai/codex-security";

const result = await security.run("/path/to/repository", {
  target: DiffTarget.refs({ base: "origin/main" }),
});
```

`DiffTarget.refs()` compares the base with `HEAD` unless you supply `head`.
The checkout must be clean, complete, and at that head revision.
Use `DiffTarget.workingTree()` for staged and unstaged changes relative to `HEAD`.
Diff targets require standard mode.

### Configure the client

Set model and native Codex settings on the client:

```ts
const security = new CodexSecurity({
  codexOverrides: {
    model_reasoning_effort: "high",
    analytics: { enabled: false },
  },
});
```

Constructor options are `codexOverrides`, `pythonPath`, and `pluginPath`.
The bundled runtime and plugin are used by default. `pythonPath` overrides the
`PYTHON` environment variable. To choose a model, set `codexOverrides.model`.
For a custom `pluginPath`, check [custom plugin compatibility](#custom-plugins).

With the built-in OpenAI provider, `security.run()` requests Daybreak Blue
when Codex advertises it for the selected model and credentials. To request
Standard or opt in to Red, pass `cyberAccessProgram: "standard"` or
`cyberAccessProgram: "daybreak_red"` in the scan options. See
[Cyber access programs](docs/cli.md#select-a-cyber-access-program) for defaults
and [Daybreak opt-in](docs/cli.md#daybreak-opt-in) for the native Codex toggle.

Deep Scan workers, including resumed workers, inherit per-scan provider,
authentication, environment, and executable settings with read-only permissions.

Scans use an isolated Codex configuration. See
[runtime configuration](docs/cli.md#runtime-configuration-and-worker-limits)
for supported overrides and defaults.

Windows defaults to `windows.sandbox = "elevated"` to enforce credential read
denials. Explicit `windows.sandbox` settings remain unchanged; Codex reports
policies unsupported by the selected backend.

### Load a project file

Load shared CLI and SDK settings explicitly:

```ts
import { CodexSecurity, loadProjectConfig } from "@openai/codex-security";

const { config, options } = await loadProjectConfig("codex-security.yaml");
const security = new CodexSecurity(config);

try {
  const result = await security.run("/path/to/repository", options);
  if (
    options.failureSeverity !== undefined &&
    result.hasFindingsAtOrAbove(options.failureSeverity)
  ) {
    process.exitCode = 1;
  }
} finally {
  await security.close();
}
```

`run()` does not discover project files. Paths inside a file resolve from that
file's directory; scope paths resolve from the repository. For a typed object,
use `resolveProjectConfig(input, directory?)`. Override loaded options with
`{ ...options, maxCostUsd: 5 }`.

Project files are trusted configuration and can select model endpoints or start
MCP servers. Keep CI scanner configuration outside the checkout being assessed.
See the [project configuration guide](https://github.com/openai/codex-security/blob/main/docs/project-configuration.md)
for the schema and precedence rules.

### Check inputs before scanning

```ts
const plan = await security.preflight("/path/to/repository", {
  target: ["src"],
  maxCostUsd: 5,
});
console.log(plan);
```

`preflight()` checks local inputs without starting Codex or using the network.
It does not verify credentials, model access, Python, or the plugin. The CLI
equivalent is `scan --dry-run`.

### Set investigation time

```ts
await security.run("/path/to/repository", { maxTimeMinutes: 15 });
```

`maxTimeMinutes` accepts positive fractional minutes. Standard scans use an
advisory allowance, unset by default; Deep scans retain their enforced discovery
limit. Scans may finish early and reporting may run longer. The CLI equivalent is
`scan --max-time 15`; project files use `scan.max_time_minutes`. See
[investigation time](docs/cli.md#set-investigation-time) for lifecycle and limit
semantics. `maxCostUsd` and `signal` keep their existing behavior.

### Configure deep scans

```ts
const result = await security.run("/path/to/repository", {
  mode: "deep",
  workers: 2,
  subagents: 0,
  stopAfterNoNew: 3,
  stopAfterConsecutiveErrors: 3,
  maxDiscoveryRuns: 10,
  maxTimeMinutes: 90,
});
```

`workers` controls concurrent Standard scans and `subagents` controls delegation
within each scan. Time and run limits apply to discovery. The coordinator merges
completed findings before the next batch starts. See
[deep scan settings](docs/cli.md#configure-deep-scans) for defaults and saved settings.
Deep discovery retains its enforced deadline, with a default and maximum of
5760 minutes. `maxTimeHours` remains a deprecated Deep-only alias in hours.

### Progress and cost

Use `onLifecycle` to observe the saved state of a top-level scan in your own
application:

```ts
await security.run(repository, {
  onLifecycle(scan) {
    console.log(scan.scanId, scan.status, scan.hasReportableFindings);
  },
});
```

For `runComponentScans()`, subscribe to `onScanEvent` and select events with
`type === "lifecycle"` to correlate each snapshot with its `componentId`. Deep
component scans also emit `deep-progress` events with independent review counts.

Group observations by `scanId`. A completed scan with
`hasReportableFindings: false` finished with zero reportable findings.
The field is `null` until that outcome is known. Saved scan history retains
the lifecycle snapshot after the originating process exits. The snapshot
includes the launch surface, package and plugin versions when available,
and whether the scan used a mock. Offline imports appear in history with
lifecycle mode `import`. Exclude imports and mock scans when counting executed
scans. For older records, saved recipes identify known imports, mock scans,
and the plugin version used at launch. Missing fields stay unknown.

If `run()` rejects before you receive a registration, record the error separately
from saved scan outcomes. The caller may have missed the registration receipt.

Use `onProgress` for scan progress and `onMeasurement` for observed token/cost
subtotals, coverage, and collection time. `onCost` and `onUsage` report complete
totals. `onUsageObservation` reports the native token measurement time
(`tokensUpdatedAt`) and account-wide allowance readings (`accountRateLimits`).
Each reading has its own `observedAt` timestamp and percentages used in each
reported window. An allowance can arrive before any token measurement. See
[telemetry and measurement](docs/telemetry.md) for operation receipts, collection
controls, replay, and reporting definitions.

Follow scans with `onWorkerEvent` and `onReconnect`. `onWorkerEvent` reports
persisted worker sessions discovered by the SDK's existing session tracker,
independently of model-emitted status markers:

```ts
await security.run(repository, {
  onWorkerEvent(event) {
    console.log(`Worker ${event.worker} observed`);
  },
});
```

The callback contains only `{ kind: "observed", worker: number }`. The scan-local
worker number matches `onActivity` and `onSessionEvent`; no prompts, raw thread
IDs, or session contents are exposed. Each session is reported once per run,
including nested workers and scan-associated validation or Deep Scan sessions.
On resume, already persisted workers can be reported again. Observation ends
with scan cost tracking, before `postScanPrompt`.

This works with the bundled Codex version. Persistence and polling can delay
notification, and missing notifications do not prove that delegation was skipped.
An observed session does not establish that a worker just started or that file
review has begun. The callback does not report failed spawn attempts, phase names,
or planned counts, and cannot act as a pre-dispatch gate. Use `maxCostUsd` or
`signal` for cancellation. Observer failures go to `onObserverError` without
stopping the scan.

`onWorkerStatus` reports **best-effort** phase dispatch counts from model-emitted
text markers. A missing dispatch status does not mean delegation was skipped.
For retired progress hooks, see [older progress integrations](#older-progress-integrations).

`onSessionEvent` receives saved events with thread IDs and worker numbers and can
contain source code or credentials. Deep scans additionally expose durable
independent-review counts through `onDeepProgress`: `completed`, `active`, and
`maximum`. The maximum is a configured cap, not a percentage denominator. The
optional `consolidating` flag reports when results are being combined or the
coordinator has finished.
`ScanOptions` lists all callbacks.

Costs estimate API-equivalent model usage, not your bill or ChatGPT subscription
allowance. Use `cost.estimatedUsdRange` for reporting. `maxCostUsd` uses the
short-context estimate; in-flight requests can exceed it. Post-scan prompts run
outside that limit. With a cost limit, completing the scan requires verifiable
usage for the scan and its workers. Matching earlier findings can also make model calls.
See [progress and cost](docs/cli.md#progress-and-cost) for accounting and budget callbacks.

### Validate an existing finding

`validate()` sends the finding to your configured model provider. The model's
review tools can read the checkout, with network access and web search disabled.
Validation uses source evidence and skips builds, tests and application execution.

```ts
import { writeFile } from "node:fs/promises";

const result = await security.validate({
  repositoryPath: "/path/to/repository",
  finding: {
    title: "Possible SQL injection",
    location: "src/query.ts:42",
  },
});
console.log(result.disposition, result.report);
await writeFile("/path/to/reports/assessment.md", result.report, "utf8");
```

Pass literal finding text or a JSON-serializable object. The assessment is
returned to the caller and has no scan history entry. The example saves
`result.report` in an existing directory. Use `outputDir` to select the
session directory. If you need runtime evidence, arrange a separate check.

The disposition is `reportable`, `suppressed`, `not_applicable`, or `deferred`.
`reportable` can rely on static analysis; `deferred` means there is insufficient
evidence. Failed or malformed responses reject the promise. `outputDir`, `auth`,
and `signal` are also supported.

To validate GitHub code scanning alerts, first import them with
`importGitHubCodeScanningAlerts()`. See the
[import guide](docs/cli.md#import-alerts-from-the-cli) for CLI and SDK examples.

For host-managed model execution, use `validateRecords()` or `validate --records`.
See [host-provided standalone validation](docs/validate-records.md).

### Generate and verify a patch

`patch()` runs the bundled remediation workflow non-interactively against a
workspace that the caller has intentionally made writable:

```ts
import { CodexSecurity } from "@openai/codex-security";

const security = new CodexSecurity();
try {
  const result = await security.patch({
    repositoryPath: "/path/to/disposable/workspace",
    finding: {
      title: "Possible SQL injection",
      summary: "User input reaches a raw SQL query.",
      locations: [{ path: "src/query.ts", startLine: 42 }],
    },
    onActivity(activity) {
      console.log(activity.description);
    },
    onCost(cost) {
      console.log(cost.estimatedUsd);
    },
  });

  switch (result.status) {
    case "verified":
    case "no_change":
      console.log(result.verificationReport);
      break;
    case "blocked":
    case "failed":
      console.error(result.reason);
      break;
  }
} finally {
  await security.close();
}
```

Pass literal finding text or a JSON-serializable object; strings are never read
as file paths. Sandboxed patch commands may edit only `repositoryPath` and run
without network access or web search. Patch workspaces are always treated as
untrusted Codex projects, so repository-local Codex configuration and MCP
servers are not loaded. Host-configured tools retain their host permissions.
The method does not create a commit, push, open a pull request, publish findings,
change remote finding state, or add a scan to history.
Callers remain responsible for reviewing and deriving the authoritative diff,
approval, commit creation, and delivery.

The discriminated result reports `verified`, `no_change`, `blocked`, or
`failed`, plus repository-relative `changedFiles`, `threadId`, and estimated
`cost` when model pricing and usage are available. Verified and no-change
results include `verificationReport`; blocked and failed results include
`reason`. Transport, authentication, cancellation, incomplete turns, and
malformed results reject the promise. Failed, blocked, or interrupted operations
can leave partial workspace changes for the caller to inspect or discard.

`changedFiles` is model-reported metadata, not the authoritative diff.
Patch-risk assessment is not included in this API.

Patch operations reuse constructor configuration and credentials. Pass `auth`,
`safetyIdentifier`, `model`, or `reasoningEffort` for per-call selection.
`onActivity`, `onSessionEvent`, `onCost`, `onReconnect`, `onAuthentication`,
`onWarning`, and `onObserverError` use the same observer contracts as scans.

## CLI

After [installing the CLI](#install-the-cli), sign in if needed:

```bash
cs login
```

From the repository you want to review, run:

```bash
cs scan .
```

Open the report at the path printed on completion. To inspect the latest
completed scan for this checkout, run `cs scans show`. To provide a project
policy for future scans, [draft and review a `SECURITY.md`](#generate-a-security-policy).

To narrow the scan scope or check the configuration before scanning:

```bash
cs scan . --path src --path tests
cs scan . --diff origin/main --json
cs scan . --dry-run
```

Use `--help` to find commands and `<command> --help` for options. Scans are
report-only by default. Add `--fail-on-severity high` to return exit code `1`
for high or critical findings; execution and required-output failures return `2`.
Scope exclusions and follow-up notes do not change a completed scan's exit code.

The [CLI reference](docs/cli.md) covers scan history, reruns, bulk and component
scans, custom validation, imports, patching, and integrations.

### Generate a security policy

Use `policy` to draft a new `SECURITY.md` or update an existing one. To select a
component:

```bash
cs policy . --path services/api
```

Existing files stay unchanged until you review and copy the draft to the
**Policy target** shown. Scans already use root and component policies; you can
keep them without generating new ones.

The SDK provides `generatePolicy()`, `preflightPolicy()`, and `previewPolicy()`. See
[policy generation](docs/cli.md#generate-a-security-policy) for SDK examples,
policy locations and reporting instructions, headless use, and saved artifacts.

### Exports and CI

Export a completed scan's findings to a SARIF file:

```bash
cs export /path/to/scan-results --output results.sarif
```

Replace `/path/to/scan-results` with the results directory printed by `scan`.
Export reads saved results, so you don't need to rerun the scan or sign in.

See [exports and CI](docs/cli.md#exports-and-ci) for source fingerprints, other
formats, threat models, and the `exportArtifact()` SDK method. For repository or
pull request scans in GitHub Actions, use the
[GitHub Action guide](https://github.com/openai/codex-security/blob/main/github-action/README.md).
Separate examples cover
[GitHub Actions with Bedrock](https://github.com/openai/codex-security/blob/main/examples/github-actions/README.md)
and [Azure Pipelines](https://github.com/openai/codex-security/blob/main/examples/azure-pipelines/README.md).

### Classify finding severity

Use `classify-severity` to assess saved findings with the built-in severity rubric
or an explicit custom rubric, without changing their original severity or evidence.
Each finding receives three independent reviews by default; the most common severity wins,
with the highest severity breaking ties among the top vote counts.
Use `--runs N` to request 1–10 reviews (default: 3). The SDK exposes `classifySeverity()`,
`classifyScanSeverity()`, and `classifyScanDirectorySeverity()`. See
[severity classification](docs/cli.md#classify-finding-severity) for selection,
checkpointing, and publication behavior.

For canonical records without a saved scan, use `classify-severity --records`
or `classifySeverityRecords()` with [host-provided execution](docs/classify-severity-records.md).

### Suggest finding owners

Use `suggest-owners` or the SDK's `suggestOwners()` to suggest contributors based
on CODEOWNERS, source, and Git history. Declared owners take priority over Git
contributors. Suggestions do not assign tickets. See
[owner suggestions](docs/cli.md#suggest-finding-owners) for input and output examples.

### Read existing Cloud findings

The Security plugin includes `$cloud-findings` for accounts where Codex Security
Cloud is available. Install the plugin through your configured Codex marketplace,
sign in to Codex with ChatGPT, and complete the Cloud connection interactively in
the intended account and workspace. Installation alone does not authenticate the
connection. Local scans do not require Cloud, and an API key used for scanning
does not replace the Cloud connection.

In Codex desktop or the interactive Codex CLI, ask:

> Use $cloud-findings to list findings for example/security-demo in my selected
> workspace. Inspect the highest-severity finding and its report, and show its
> recorded assignee, patch links, verification results, and latest scan status.
> Do not change anything.

After completing connection setup, the same host connection can be used by
`codex exec`:

```bash
codex exec --ephemeral --json -s read-only 'Use $codex-security:cloud-findings to read findings and the latest scan status for example/security-demo in my selected workspace. Inspect one finding and its report. If the workspace or repository is ambiguous, explain the required selection and stop. Do not change anything.'
```

Noninteractive execution needs an existing authenticated connection; it cannot
complete first-time sign-in. If authentication expires, the app is unavailable,
or workspace policy denies access, complete the reported setup action before
retrying. Those failures do not mean the repository has no findings.

Assignment, issue validation, patch checks, periodic fix checks, and finding
lifecycle status are separate records. Some finding sources do not provide all
of them. The read workflow reports missing data and incomplete evidence pages,
and does not describe failed or unfinished scans as clean.

### Publish findings to Cloud

Use `publish scan --to cloud` for completed Codex Security scans or a Codex
Security findings CSV. Preview either input offline with `--dry-run`. Uploads
require a file-backed ChatGPT login. [Cloud publication](docs/cli.md#publish-completed-scans)

For a report exported by a scanner, see [Import external findings](#import-external-findings).
For issue tracking, see [Linear publication](docs/cli.md#publish-completed-scans-to-linear).

### Import external findings

For a saved scanner report, call `prepareLocalExternalImport` for a checkout
or `prepareExternalPublication` for a connected Cloud repository. Review the
returned `preview`, then call `import()` to save locally or `publish()` to
upload. The [scanner import guides](https://github.com/openai/codex-security/blob/main/docs/scanner-imports/README.md)
list the supported report formats and destinations for each provider.

For normalized evidence, use `prepareNormalizedLocalImport(findings, options)`
or `prepareNormalizedExternalPublication(findings, options)` and review the
preview in the same way. Cloud file imports use `ExternalPublicationOptions`,
and normalized Cloud imports use `NormalizedExternalPublicationOptions`. Keep
Cloud receipts and saved requests when retrying an interrupted submission.

Use `listLocalExternalFindings({ repository })` to read saved scanner evidence.
It starts unassessed. Reimporting the same repository, provider, source key
and finding ID updates that record. Records omitted from the export remain stored.

A local SDK import with only excluded records returns the exclusions and zero
writes. The CLI exits 2 in that case. When Cloud preparation throws
`NoPublishableFindingsError`, inspect its `selection` for the read count,
exclusions and scanner diagnostics. A clean empty report needs no upload.

File imports forward repository references from the reader automatically. With
`prepareNormalizedLocalImport()`, supply additional known references in the
third argument's `sourceRepositories` when they are absent from
`evidence.details.repository.url`. For a known GitHub custom host, include
`platform: "github"`, for example `{ sourceRepositories: [{ url:
"https://git.example.test/example/project", platform: "github" }] }`. Named Wiz
reports carry this platform in their repository inventory. If you export only the
normalized finding rows to JSONL, supply that metadata separately; the original
finding evidence does not include the surrounding inventory.

#### Collect and normalize scanner evidence

To collect selected Sonar issues, pass their keys to `collectSonarIssues` in `options.issueKeys`.
Omit `issueKeys` to collect the project's open security issues. An empty list is rejected.
If you know the source repository, pass its Git URL in `options.sourceRepositoryUrl`
to check the Sonar binding before fetching issues.

For AWS Continuum code findings, use `readContinuumFindings(path, sourceRepositoryUrl)`
with a saved list or detail response, or `normalizeContinuumFindings(input, sourceRepositoryUrl)`
with parsed JSON. Verify the repository for the selected findings before passing its Git URL.
[Continuum import guide](https://github.com/openai/codex-security/blob/main/docs/scanner-imports/continuum.md)

For a saved Checkmarx One CLI JSON or CxSAST XML report, use
`readCheckmarxFindings(path, sourceRepositoryUrl, "local")` to inspect its evidence.
To prepare a local import, pass `provider: "checkmarx"` and the verified
`sourceRepositoryUrl` to `prepareLocalExternalImport`. Keep each batch of normalized
Checkmarx findings scoped to one scan and its repository.
[Checkmarx SAST import guide](https://github.com/openai/codex-security/blob/main/docs/scanner-imports/checkmarx.md)

Use `collectSelectedSemgrepGuardianFindings` with a connected Guardian MCP client to
[capture selected Code or Supply Chain findings](https://github.com/openai/codex-security/blob/main/docs/scanner-imports/semgrep.md#import-selected-guardian-findings) using the user's Guardian sign-in.
Use `normalizeSelectedSemgrepPlatformFindings` for selected SAST findings from saved
Semgrep Web API responses. See the [Semgrep SDK example](https://github.com/openai/codex-security/blob/main/docs/scanner-imports/semgrep.md#import-selected-semgrep-platform-sast-findings-with-the-sdk).
Use `selectSemgrepPlatformFindings` to [save a selection for the local CLI](https://github.com/openai/codex-security/blob/main/docs/scanner-imports/semgrep.md#existing-platform-findings).
Use `collectSemgrepPlatformFindings` to [collect one project at an explicit ref](https://github.com/openai/codex-security/blob/main/docs/scanner-imports/semgrep.md#collect-a-platform-project-and-branch) for a single product (default `sast`).

Use `collectSnykIssues` to [collect existing Open Source or Code issues](https://github.com/openai/codex-security/blob/main/docs/scanner-imports/snyk.md#existing-issues-from-snyk) for local import or Cloud publication.
For a private repository with a verified SCM, pass its URL and `platform: "gitlab"` or `"github"` in `sourceRepositories` to match standard SSH clone URLs.

To inspect dependency vulnerabilities in a saved Trivy schema-v2 repository or filesystem
report, call `readTrivyFindings` with the JSON or gzip path. Use `normalizeTrivyFindings`
for an already parsed report. Supply the scanned directory relative to the checkout
(`.` for the whole checkout) unless the report's remote target and Git metadata establish it.

```ts
import { readTrivyFindings } from "@openai/codex-security";

const { findings, excluded, report } = await readTrivyFindings(
  "trivy.json.gz",
  "local",
  ".",
);
```

## Findings storage and deduplication

Saved-scan deduplication uses local SQLite directly:

```bash
cs dedupe --scan SCAN_ID --json
```

The [findings guide](docs/findings-service.md) covers local storage, embedding
credentials, deduplication, backups, and independently operated HTTP endpoints.
For an older service deployment, see [migration guidance](docs/findings-service.md#local-service-removal).
For records stored in your own system, see
[SDK records deduplication](docs/dedupe-records.md).

## Containerized bulk scans

Use the scanner image and Compose files to scan a list of repositories with
persistent results and authentication. See
[containerized bulk scans](docs/cli.md#containerized-bulk-scans) for setup, or the
[workflow runner](https://github.com/openai/codex-security/blob/main/docker/README.md#workflow-runner)
for individual CLI stages in containers.

## Local security model

Codex Security runs with your operating-system permissions. Scan subprocesses
can inherit your environment, so start them with only the credentials they need.
Local tools running under the same account are trusted.

The scan profile allows reads across the local filesystem and writes to workspace
roots. Execution approvals are reviewed automatically and may grant extra
permissions for an operation. Set `codexOverrides.approval_policy: "never"`
(or CLI `--codex "approval_policy='never'"`) to deny permission requests.
If you select a Codex profile, its explicit `approval_policy` takes precedence
over the root setting.
Host and network restrictions still apply.

Repository contents, model output, and imported artifacts do not authorize
access to other targets, disclosure of credentials, or writes outside approved
paths. Keep state and scan artifacts private and outside the repository.

## Compatibility

### Package and plugin versions

When reporting a problem, run `codex-security info --json` with the installation
that produced it. For a local SDK installation, run
`npx @openai/codex-security info --json` in that project. Include `cliVersion`,
`sdkVersion`, `bundledPluginVersion`, `codexVersion` and `codexSdkVersion`. If
you supplied a separate plugin or Codex executable, include its version too.

For package provenance, compare the registry's `gitHead` and `dist.integrity`
with the release tag and tarball. If a package omits `gitHead`, use the commit
in its [verified release attestation](https://github.com/openai/codex-security/blob/main/.github/workflows/node-github-release.yml).

### Custom plugins

New and resumed Deep Scans require a plugin with `directDeepScanEngine: 1`,
`workerProviderSnapshot: 4`, and isolated worker configuration support. Older
custom plugins fail before scan execution; update the plugin or omit `pluginPath`
to use the bundled version. Reading saved reports does not require these
execution capabilities.

Use the current shell or Windows launcher for runtime-root routing. The SDK does
not adapt the older `node ./mcp/server.mjs` MCP entrypoint.

Custom plugins must support the current workbench protocol for scan comparison
and archival. The SDK does not adapt older payloads or archive scan directories
on behalf of older workbench implementations.

### Older progress integrations

The helper-derived `kind: "preflight"` event, `config_preflight.py` helper, and
custom capability registries are retired. This includes the `preflightChecks`
progress-tool input and workbench `--preflight-issues-json` /
`--preflight-issues-json-stdin` arguments. Scans use available runtime tools and
parent fallback without a capability registry. Saved preflight history remains
readable. Local `preflight()` input checks, authentication, sandbox enforcement,
and Deep worker configuration still apply.

### Error types

`LocalPluginBootstrapError` identifies local plugin setup failures and extends
`PluginBootstrapError`, so existing catches keep working. Knowledge-base
preparation errors use `ConfigurationError`; wrapped diagnostics remain in `cause`.

## Documentation and security

- [Online SDK guide](https://learn.chatgpt.com/docs/security/sdk)
- [CLI reference](docs/cli.md)
- [Findings guide](docs/findings-service.md)
- [GitHub issues](https://github.com/openai/codex-security/issues) for bugs and feature requests
- [Security policy](https://github.com/openai/codex-security/blob/main/SECURITY.md) for private vulnerability reporting
