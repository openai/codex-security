# `@openai/codex-security`

Run Codex Security from TypeScript or the command line to find, validate, and fix
security vulnerabilities in your code. The package includes the Codex runtime,
security plugin, and TypeScript declarations. It uses ES modules.

- Scan repositories, selected paths, or Git changes. Deep scans run parallel
  discovery workers on repositories and selected paths.
- Validate findings, generate patches, and verify existing fixes.
- Draft security policies and retain threat models.
- Review saved findings, identify duplicates, classify severity, and suggest owners.
- Import GitHub code scanning alerts, export SARIF, JSON, or CSV, and publish
  findings to Linear or a findings service.
- Import [Snyk Open Source findings](https://github.com/openai/codex-security/blob/main/docs/scanner-imports/snyk.md) from
  official plugin JSON or native CLI JSON locally or into Cloud; Open Source
  SARIF is also supported. License findings and other Snyk products are excluded.
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

Reading compressed Codex session logs (`.jsonl.zst`) requires Node.js 22.15.0+
within 22.x, or Node.js 24.x or 26.x. On Node.js 22.13–22.14, compressed sessions
are unavailable when reading saved activity or attaching scan logs to feedback, and
scans whose original session is compressed cannot resume. Plain `.jsonl` logs
work on all supported runtimes.

### Install the CLI

Install the CLI globally:

```bash
npm install --global @openai/codex-security
cs --version
```

`cs` is a short alias for `codex-security`; both commands run the same CLI.
The installation creates both commands in npm's global executable directory,
which must be on your `PATH`. If `cs` already resolves to another tool, use
`codex-security` instead. If npm stops with an `EEXIST` error for `cs`, use
`npx @openai/codex-security` without a global installation.

Continue with the [CLI walkthrough](#cli). To run without a global installation,
replace `cs` in the CLI examples with `npx @openai/codex-security`.

### Install the TypeScript SDK

Install the package locally in your TypeScript project:

```bash
npm install @openai/codex-security
```

### Package and plugin versions

For bug reports, run `npx @openai/codex-security info --json` in the project
where the SDK is installed, or `codex-security info --json` for a global install.
Include the npm version (`cliVersion` and `sdkVersion`), bundled plugin manifest
version (`bundledPluginVersion`), and Codex runtime and SDK pins (`codexVersion`
and `codexSdkVersion`). If you used a marketplace plugin, a plugin supplied by
path, or a custom Codex executable, include its version separately.

For example, `npm view @openai/codex-security@0.1.5 gitHead dist.integrity`
shows the registry's source commit and tarball digest. Compare `gitHead` with
the commit for tag `npm-v0.1.5`. `npm pack @openai/codex-security@0.1.5` downloads
the archive, including `package/_bundled_plugin/.codex-plugin/plugin.json`.

The [release workflow](https://github.com/openai/codex-security/blob/main/.github/workflows/node-github-release.yml)
verifies the signed attestation that binds the tarball to the tagged commit.
For `0.1.0` and `0.1.1`, npm omits `gitHead`. Use the commit from the verified attestation.

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

## Read existing Cloud findings

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
| `review`                          | Additional excluded paths. This is not file coverage.            |
| `repositoryFindings`              | This scan's findings plus earlier open findings, when available. |
| `sarifPath`                       | SARIF export path, or `null`.                                    |
| `threatModel` / `threatModelPath` | Saved threat model and document path; either can be `null`.      |
| `cost`                            | Estimated model usage cost, or `null` when unavailable.          |

Review the requested paths and exclusions alongside the execution outcome.
`reviewState.deferred` records unfinished requested work, while
`reviewState.openQuestions` records optional follow-up separately.

Review the scan status and scope alongside findings. A report with no findings does not establish
that the repository is secure. Reports and logs can contain source code,
vulnerability details, and credentials; review them before sharing.

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

To enable Daybreak on Codex 0.163.0 or later, set `codexOverrides.daybreak: true`.
The toggle defaults off; an explicit `false` keeps it off. The setting reaches
Deep Scan discovery and reducer workers, including resumed workers. Scans use
isolated configuration, so a desktop toggle or personal Codex configuration does
not configure an SDK scan. See [Daybreak opt-in](docs/cli.md#daybreak-opt-in) for
CLI, project-file, and direct plugin configuration.

Deep Scan discovery, reducer, and resumed workers inherit per-scan provider,
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

`workers` controls concurrent discovery workers; `subagents` controls delegation
within each worker. Time and run limits apply to discovery. After discovery
stops, the scan combines and returns completed findings. See
[deep scan settings](docs/cli.md#configure-deep-scans) for defaults and saved settings.
Deep discovery retains its enforced deadline, with a default and maximum of
5760 minutes. `maxTimeHours` remains a deprecated Deep-only alias in hours.

### Progress and cost

Use `onProgress` for scan progress and `onCost` for cost updates.
Use `onUsageObservation` for the last reported token measurement time
(`tokensUpdatedAt`) and account-wide allowance readings (`accountRateLimits`).
Each reading includes its own `observedAt` timestamp and the percentage used in
each reported window. A limit-only update can arrive before any token measurement.

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
outside that limit. Matching earlier findings can also make model calls.
See [progress and cost](docs/cli.md#progress-and-cost) for accounting and budget callbacks.

### Validate an existing finding

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

Pass finding text or a JSON-serializable object, not a file path. Standalone
validation uses source evidence in a read-only, offline session. It does not build
the target, execute application code, run tests or PoCs, or add a scan to history.
The validator returns the assessment without writing report files. The example
saves `result.report` in an existing directory. `outputDir` selects the session
directory, not a report destination. Callers that previously read reports from it
must save `result.report` instead.
Callers needing runtime proof must arrange a separate reproduction step. Standard,
Deep, and diff scan validation keep their existing workflows.

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
const security = new CodexSecurity();
try {
  const result = await security.patch({
    repositoryPath: "/path/to/disposable/workspace",
    finding: {
      title: "Possible SQL injection",
      summary: "User input reaches a raw SQL query.",
      locations: [{ path: "src/query.ts", startLine: 42 }],
    },
    signal,
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

From your repository, optionally [draft a `SECURITY.md`](#generate-a-security-policy)
that explains what counts as a security issue in your project:

```bash
cs policy .
```

The draft is saved outside your repository. Review the diff and notes, edit the
draft, then copy only `SECURITY.md` to the **Policy target** shown. Skip this step
to keep your current policy or scan without one.

Then scan the repository:

```bash
cs scan .
```

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

### Publish findings to Cloud

`publish scan --to cloud` uploads selected findings to Codex Security Cloud.
It requires ChatGPT credentials; inference API keys and AWS credentials do not
grant Cloud access. See [Cloud publication](docs/cli.md#publish-findings-to-cloud)
for setup and review steps, or [Linear publication](docs/cli.md#publish-completed-scans-to-linear)
for issue creation.

External vendor imports are opt-in. Set `CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS=1`
to enable `publish findings`, `findings imported`, `import github-advisories`, and
the SDK's external publication, local import/readback, and advisory acquisition
APIs. They are disabled otherwise; CLI commands are hidden from help and schemas.
SDK callers can supply the flag through the existing per-call
`dependencies.environment`. Pure normalizers and file readers remain available.
This does not affect scan publishing or the existing GitHub alert collector.

The SDK also exposes `prepareExternalPublication(file, options)` for supported
vendor exports and `prepareNormalizedExternalPublication(findings, options)` for
normalized external evidence from any provider in the Cloud import contract.
The normalized API accepts `NormalizedExternalPublicationOptions`; file readers
use `ExternalPublicationOptions` for their supported formats. Both resolve the Cloud repository and return a
`preview` plus a separate `publish()` operation. Inspect the preview before
calling `publish()`. Imported evidence remains not assessed by Codex, and saved
requests and receipts support retries after interruption.

Prefer each provider's supported native JSON for local and Cloud imports. Keep
the same acquisition format for repeat imports: SARIF and CSV are compatibility
options where supported, and changing formats can change record identities or
replace richer evidence with less detail. See the
[import guide](docs/cli.md#import-vendor-findings-locally) for format selection.

For Amazon Inspector Code Security, use `--provider inspector` with a complete
ListFindings JSON export and `--source-repository-url`. When the export identifies
the repository by an ARN and name, pass `--inspector-project-arn ARN` with the ARN
you verified for that Git URL in the SCM integration. See the
[Inspector guide](https://github.com/openai/codex-security/blob/main/docs/scanner-imports/inspector.md).

For Black Duck SCA, use `--provider blackduck` with a BOM-6 vulnerable-components
export for one project version. Map that version to its source repository with
`--source-repository-url`. See the
[Black Duck guide](https://github.com/openai/codex-security/blob/main/docs/scanner-imports/blackduck.md).

For Veracode Static Analysis policy findings, use `--provider veracode` with
every Findings API page from one application. Set `--source-repository-url`
to the source repository mapped to that application. See the
[Veracode guide](https://github.com/openai/codex-security/blob/main/docs/scanner-imports/veracode.md).

For OpenGrep, use `--provider opengrep` with native JSON or gzip and an explicit
`--source-repository-url`. Local and Cloud imports retain unassessed OpenGrep
evidence through the existing Semgrep source-provider contract. See the
[OpenGrep guide](https://github.com/openai/codex-security/blob/main/docs/scanner-imports/opengrep.md) for preview commands,
coverage diagnostics, stable source identities, and local SDK assessment.

For Wiz, prefer supported native JSON acquired through an authorized MCP or API
connection. The [CSV compatibility reader](docs/cli.md#import-wiz-findings) covers
repository package vulnerabilities (SCA) only; it does not add SAST, CSPM or
complete code-to-cloud coverage. Both formats support gzip. The acquisition path
still needs validation with an authorized Wiz tenant.

For GitHub code scanning and GHSA advisories, save complete JSON from
`import github` or `import github-advisories`, respectively. **GHSA import
does not establish an installed dependency or applicability to the repository.**
For Dependabot, save the native REST alert records from one repository using the
[Dependabot export guide](https://github.com/openai/codex-security/blob/main/docs/scanner-imports/github-dependabot.md).
The GitHub file reader accepts all three families. Secret-scanning alerts and
writeback to GitHub are outside its scope.

Use `publish findings FILE --to local --repository PATH --provider wiz
--source-key KEY` to store the same vendor evidence in the local workbench SQLite
database. Preview with `--dry-run --format json`, then confirm interactively or
use `--yes`. Read it with `findings imported [REPOSITORY] --format json`; the
repository defaults to the current directory. No Cloud login or model call is
needed. Use `--provider snyk` for native CLI JSON, a Snyk plugin SCA bundle or
Open Source SARIF. Prefer JSON, and keep one format and stable source key per scan
target; switching formats creates separate source identities. See
[local imports](docs/cli.md#import-vendor-findings-locally).

Use `--provider endor` with native Endor Finding JSON; existing endorctl SARIF is
accepted as a lossy compatibility format. See
[Endor imports](docs/cli.md#import-endor-labs-findings).

For saved GitHub code-scanning alerts, GHSA advisories, or Dependabot alerts, use
`--provider github` with a separate stable source key for each finding family.
See [local imports](docs/cli.md#import-vendor-findings-locally).

The SDK's `prepareLocalExternalImport(file, options)` returns a `preview` and a
separate `import()` operation. `prepareNormalizedLocalImport(findings,
options)` accepts already normalized evidence, and
`listLocalExternalFindings({ repository })` reads the stored records. Imports
remain unassessed source evidence, separate from native scan findings. Repeated
imports update the same repository/provider/source-key/source-ID record; omitted
records remain stored, and unknown evidence fields are not inferred.

File imports forward repository references from the reader automatically. Direct
normalized callers should provide additional known references in the third
argument's `sourceRepositories` when they are absent from
`evidence.details.repository.url`. For a known GitHub custom host, include
`platform: "github"`, for example `{ sourceRepositories: [{ url:
"https://git.example.test/example/project", platform: "github" }] }`. Named Wiz
reports carry this platform in their repository inventory. If you export only the
normalized finding rows to JSONL, supply that metadata separately; the original
finding evidence does not include the surrounding inventory.

See [Semgrep Code imports](https://github.com/openai/codex-security/blob/main/docs/scanner-imports/semgrep.md) for native CLI/CI JSON, SARIF compatibility, and local or Cloud imports. The SDK also supports selected Platform SAST finding IDs from scoped Web API responses through `normalizeSelectedSemgrepPlatformFindings`. To save a selection for the local CLI, use `selectSemgrepPlatformFindings`.

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
(or CLI `--codex 'approval_policy="never"'`) to deny permission requests.
If you select a Codex profile, its explicit `approval_policy` takes precedence
over the root setting.
Host and network restrictions still apply.

Repository contents, model output, and imported artifacts do not authorize
access to other targets, disclosure of credentials, or writes outside approved
paths. Keep state and scan artifacts private and outside the repository.

## Compatibility

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
