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
- Automate scans across repositories and project components.

See the [CLI reference](docs/cli.md),
[findings service guide](docs/findings-service.md), or
[online documentation](https://learn.chatgpt.com/docs/security) for setup and examples.

Before version `1.0.0`, minor releases may change the public API.

## Install

```bash
npm install @openai/codex-security
npx @openai/codex-security --version
```

Supported runtimes:

- Node.js 22.13.0+ within 22.x, or Node.js 24.x or 26.x, on macOS, Linux, or Windows.
- Python 3.10+ for scans, policy generation, exports, scan history, and saved
  findings. Python 3.10 also needs `tomli`.

## Authentication

Sign in with ChatGPT:

```bash
npx @openai/codex-security login
```

For CI, set `OPENAI_API_KEY` or `CODEX_API_KEY` in the scan process's environment.
These keys apply to the current command without replacing your saved login.
To save an API key instead, pass it on stdin:

```bash
printenv OPENAI_API_KEY | npx @openai/codex-security login --with-api-key
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

Run `npx @openai/codex-security login` in that SSH session, then open its sign-in
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
repository and its enclosing Git worktree. On macOS and Linux, an existing output
directory must be private to you (`chmod 700`).

### Read results

| Result                            | Contents                                                         |
| --------------------------------- | ---------------------------------------------------------------- |
| `findings.findings`               | Findings from this scan.                                         |
| `reportPath`                      | Path to the Markdown report.                                     |
| `coverage`                        | What the scan assessed and any coverage gaps.                    |
| `repositoryFindings`              | This scan's findings plus earlier open findings, when available. |
| `sarifPath`                       | SARIF export path, or `null`.                                    |
| `threatModel` / `threatModelPath` | Saved threat model and document path; either can be `null`.      |
| `cost`                            | Estimated model usage cost, or `null` when unavailable.          |

Review coverage alongside findings. A report with no findings does not establish
that the repository is secure. Reports and logs can contain source code,
vulnerability details, and credentials; review them before sharing.

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
| `outputDir`                                 | Results directory; omit to use the state directory.                            |
| `archiveExisting`                           | Move previous results aside before reusing `outputDir`.                        |
| `maxCostUsd`                                | Stop at an estimated model cost; see [cost limits](#progress-and-cost).        |
| `signal`                                    | An `AbortSignal` to cancel the scan.                                           |

The exported `ScanOptions` type describes all options and callbacks. For full
CLI behavior, see [scan options and output](docs/cli.md#scan-options-and-output).

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

Deep Scans with non-default provider selection or custom provider definitions
require a plugin that supports per-scan worker provider snapshots. Older custom plugins
fail before starting model work with an upgrade message; update the plugin or
omit `pluginPath` to use the bundled version. Older custom plugins remain usable
for standard scans and Deep Scans that inherit native provider configuration or
explicitly select the built-in OpenAI provider without custom provider definitions
when their workers forward that selection or native configuration selects the
same effective provider for both the parent and workers. Otherwise, the scan
stops before model work with the plugin upgrade message.
When no provider is selected, discovery, reducer, and resumed workers inherit the
same native configuration as the parent.

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

### Configure deep scans

```ts
const result = await security.run("/path/to/repository", {
  mode: "deep",
  workers: 2,
  subagents: 0,
  stopAfterNoNew: 3,
  stopAfterConsecutiveErrors: 3,
  maxDiscoveryRuns: 10,
  maxTimeHours: 1.5,
});
```

`workers` controls concurrent discovery workers; `subagents` controls delegation
within each worker. Time and run limits apply to discovery. After discovery
stops, the scan combines and returns completed findings. See
[deep scan settings](docs/cli.md#configure-deep-scans) for defaults and saved settings.

### Progress and cost

Use `onProgress` for scan progress and `onCost` for cost updates.

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

`onWorkerStatus` remains available for tool-derived preflight status and
**best-effort** phase dispatch counts from model-emitted text markers. A missing
dispatch status does not mean delegation was skipped. `onSessionEvent` receives
saved events with thread IDs and worker numbers and can contain source code or
credentials. Deep scans additionally expose durable independent-review counts
through `onDeepProgress`: `completed`, `active`, and `maximum`. The maximum is a
configured cap, not a percentage denominator. `ScanOptions` lists all callbacks.

Costs estimate API-equivalent model usage, not your bill or ChatGPT subscription
allowance. Use `cost.estimatedUsdRange` for reporting. `maxCostUsd` uses the
short-context estimate; in-flight requests can exceed it. Post-scan prompts run
outside that limit. Matching earlier findings can also make model calls.
See [progress and cost](docs/cli.md#progress-and-cost) for accounting and budget callbacks.

### Validate an existing finding

```ts
const result = await security.validate({
  repositoryPath: "/path/to/repository",
  finding: {
    title: "Possible SQL injection",
    location: "src/query.ts:42",
  },
});
console.log(result.disposition, result.report);
```

Pass finding text or a JSON-serializable object, not a file path. Validation uses
the client's settings and credentials without changing repository files or
adding a scan to history.

The disposition is `reportable`, `suppressed`, `not_applicable`, or `deferred`.
`reportable` can rely on static analysis; `deferred` means there is insufficient
evidence. Failed or malformed responses reject the promise. `outputDir`, `auth`,
and `signal` are also supported.

To validate GitHub code scanning alerts, first import them with
`importGitHubCodeScanningAlerts()`. See the
[import guide](docs/cli.md#import-alerts-from-the-cli) for CLI and SDK examples.

## CLI

```bash
npx @openai/codex-security scan .
npx @openai/codex-security scan . --path src --path tests
npx @openai/codex-security scan . --diff origin/main --json
npx @openai/codex-security scan . --dry-run
```

Use `--help` to find commands and `<command> --help` for options. Scans are
report-only by default. Add `--fail-on-severity high` to return exit code `1`
for high or critical findings; incomplete scans and execution failures return `2`.

The [CLI reference](docs/cli.md) covers scan history, reruns, bulk and component
scans, custom validation, imports, patching, and integrations.

### Generate a security policy

```bash
npx @openai/codex-security policy .
npx @openai/codex-security policy . --path services/api
```

`policy` drafts `SECURITY.md` outside the checkout. Review the draft before
installing it; it guides future scans. The SDK provides `generatePolicy()`,
`preflightPolicy()`, and `previewPolicy()`. See
[policy generation](docs/cli.md#generate-a-security-policy) for SDK examples,
headless use, artifacts, and review requirements.

### Exports and CI

Export saved findings or a threat model without starting another analysis:

```bash
npx @openai/codex-security export --scan SCAN_ID --export-format sarif --output results.sarif
npx @openai/codex-security export --scan SCAN_ID --artifact threat-model --output threatmodel.md
```

The SDK provides `exportArtifact()` for the same offline operations. See
[exports and CI](docs/cli.md#exports-and-ci) for details. For repository or pull
request scans in GitHub Actions, use the
[GitHub Action guide](https://github.com/openai/codex-security/blob/main/github-action/README.md).
Separate examples cover
[GitHub Actions with Bedrock](https://github.com/openai/codex-security/blob/main/examples/github-actions/README.md)
and [Azure Pipelines](https://github.com/openai/codex-security/blob/main/examples/azure-pipelines/README.md).

### Classify finding severity

Use `classify-severity` with your own rubric to assess saved findings without
changing their original severity or evidence. The SDK exposes `classifySeverity()`,
`classifyScanSeverity()`, and `classifyScanDirectorySeverity()`. See
[severity classification](docs/cli.md#classify-finding-severity) for selection,
checkpointing, and publication behavior.

### Suggest finding owners

Use `suggest-owners` or the SDK's `suggestOwners()` to suggest contributors based
on source and Git history. Suggestions do not assign tickets. See
[owner suggestions](docs/cli.md#suggest-finding-owners) for input and output examples.

### Publish findings to Cloud

`publish scan --to cloud` uploads selected findings to Codex Security Cloud.
It requires ChatGPT credentials; inference API keys and AWS credentials do not
grant Cloud access. See [Cloud publication](docs/cli.md#publish-findings-to-cloud)
for setup and review steps, or [Linear publication](docs/cli.md#publish-completed-scans-to-linear)
for issue creation.

## Findings service (preview)

The findings service stores findings and duplicate groups in SQLite and provides
a read-only dashboard. It has no built-in authentication; keep it on loopback or
behind an authenticated TLS proxy. Imports send complete finding JSON to the
configured embeddings endpoint.

See the [findings service guide](docs/findings-service.md) for its HTTP API,
Docker setup, publishing, and deduplication. For records stored in your own
system, see [SDK records deduplication](docs/dedupe-records.md).

### Running without Docker

```bash
npx @openai/codex-security serve --port 3000
```

Open `http://127.0.0.1:3000/dashboard`. Startup and listing need no API key;
imports that generate embeddings need `OPENAI_API_KEY` or `CODEX_API_KEY`.
A ChatGPT login is not an embedding API credential. See
[local service setup](docs/findings-service.md#run-without-docker) for storage settings.

### Upgrades and backups

Stop the service and back up its entire state directory before upgrading.
Keep the state volume when replacing a container. See
[backup and restore instructions](docs/findings-service.md#storage-upgrades-and-backups).

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
Host and network restrictions still apply.

Repository contents, model output, and imported artifacts do not authorize
access to other targets, disclosure of credentials, or writes outside approved
paths. Keep state and scan artifacts private and outside the repository.

## Documentation and security

- [Online SDK guide](https://learn.chatgpt.com/docs/security/sdk)
- [CLI reference](docs/cli.md)
- [Findings service guide](docs/findings-service.md)
- [GitHub issues](https://github.com/openai/codex-security/issues) for bugs and feature requests
- [Security policy](https://github.com/openai/codex-security/blob/main/SECURITY.md) for private vulnerability reporting
