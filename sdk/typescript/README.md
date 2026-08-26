# `@openai/codex-security`

TypeScript SDK and CLI for Codex Security. The ESM-only package includes
TypeScript declarations and the Codex runtime.

Before version `1.0.0`, minor releases may change the public API.

## Install

```bash
npm install @openai/codex-security
npx @openai/codex-security --version
```

Supports macOS, Linux, and Windows with Node.js 22.13.0+ (22.x), 24.x, or 26.x.
Scans, exports, scan history, and saved findings also need Python 3.10+
(and `tomli` on Python 3.10). Select an interpreter with `--python` on `scan`,
`bulk-scan`, or `export`, `pythonPath` in the SDK, or the `PYTHON` environment
variable.

## Run a scan from TypeScript

Sign in with `npx @openai/codex-security login` or set `OPENAI_API_KEY` or
`CODEX_API_KEY`. Then create a client and scan a repository you own or have
permission to assess:

```ts
import { CodexSecurity } from "@openai/codex-security";

const security = new CodexSecurity();

try {
  const result = await security.run("/path/to/repository", {
    outputDir: "/path/outside/repository/results",
  });

  console.log(result.reportPath);
  console.log(result.findings.findings.length);
} finally {
  await security.close();
}
```

The SDK supports repository, path, committed-diff, and working-tree targets.
`result.findings` contains the current scan's findings; `repositoryFindings`
also includes open findings from earlier scans when available. Matching earlier
findings can make one additional model call, even with a scan cost limit.

Keep results outside the repository and restrict access: reports can contain
source code, vulnerability details, and reproduction steps.

### Validate an existing finding

Use `security.validate()` to assess one finding:

```ts
const security = new CodexSecurity();
try {
  const result = await security.validate({
    repositoryPath: "/path/to/repository",
    finding: {
      title: "Possible SQL injection",
      location: "src/query.ts:42",
    },
    outputDir: "/path/outside/repository/validation",
  });
  console.log(result.disposition);
  console.log(result.report);
} finally {
  await security.close();
}
```

`finding` is literal text or a JSON-serializable object, not a file path.
Validation uses the client's settings and authentication, leaves repository
files unchanged, and does not add a scan to history.

Results contain a `disposition` (`reportable`, `suppressed`, `not_applicable`,
or `deferred`), Markdown `report`, `threadId`, and evidence `outputDir`.
`reportable` can rely on static analysis; `deferred` means insufficient
evidence. Failed, incomplete, or malformed responses reject the promise.

`outputDir` must be empty and outside the Git worktree; it defaults to
`validations/` under the state directory. Pass `auth` to select credentials
or `signal` to cancel.

### Import GitHub code scanning alerts

Import GitHub code scanning alerts, including third-party SARIF uploads, then
validate them against the corresponding local checkout:

```ts
import {
  CodexSecurity,
  importGitHubCodeScanningAlerts,
} from "@openai/codex-security";

const findings = await importGitHubCodeScanningAlerts({
  repository: "example/repository",
  alertNumbers: [12, 18], // Omit to list all open alerts on the default branch.
  githubToken: process.env["GH_TOKEN"],
});

const security = new CodexSecurity();
try {
  for (const finding of findings) {
    const result = await security.validate({
      repositoryPath: "/path/to/repository",
      finding,
    });
    console.log(finding.url, result.disposition, result.outputDir);
  }
} finally {
  await security.close();
}
```

Each result contains `source`, `repository`, `number`, `url`, and the full
upstream `alert`. Import is read-only and does not start Codex or check out code.

Without `alertNumbers`, `state` defaults to `"open"`; it also accepts `"closed"`,
`"dismissed"`, `"fixed"`, and `"all"`. Exact alert numbers ignore state and
cannot be combined with a nondefault `state`. Use `ref` for another branch or
pull-request reference.

Authentication uses `githubToken` or `gh auth token`, including GitHub CLI token
environment variables. `githubHost` defaults to `GH_HOST` or `github.com`.
The token needs read access to code scanning alerts; access failures reject
the import. Pass `signal` to cancel.

### SDK configuration and scan options

Pass runtime configuration to the `CodexSecurity` constructor:

| Option           | Description                                                                 |
| ---------------- | --------------------------------------------------------------------------- |
| `pluginPath`     | Use a Codex Security plugin directory or ZIP instead of the bundled plugin. |
| `pythonPath`     | Select the Python interpreter before consulting `PYTHON`.                   |
| `codexOverrides` | Deep-merge supported settings into the isolated Codex configuration.        |

Pass scan configuration to `security.run(repository, options)` or
`security.preflight(repository, options)`:

| Option                  | Description                                                                                |
| ----------------------- | ------------------------------------------------------------------------------------------ |
| `auth`                  | Select `"auto"`, `"chatgpt"`, or `"api-key"`.                                              |
| `safetyIdentifier`      | Stable hashed end-user ID for this scan's model requests; requires API-key authentication. |
| `target`                | Select a repository, repository-relative paths, committed diff, or working-tree diff.      |
| `mode`                  | Select `"standard"` or `"deep"`; deep mode supports repositories and paths.                |
| `knowledgeBasePaths`    | Add architecture documents, security policies, threat models, or directories.              |
| `outputDir`             | Choose an artifact directory outside the enclosing Git worktree.                           |
| `archiveExisting`       | Archive results already in `outputDir` before starting a scan.                             |
| `maxCostUsd`            | Stop after the estimated model cost exceeds a positive USD amount.                         |
| `maxTimeHours`          | Limit deep-scan discovery to a positive number of hours, up to 96.                         |
| `failureSeverity`       | Record a finding-severity policy in the saved scan recipe.                                 |
| `parentScanId`          | Link a rerun to an existing parent scan.                                                   |
| `expectedPluginVersion` | Require the original plugin version when replaying a scan.                                 |
| `signal`                | Cancel a scan with an `AbortSignal`.                                                       |

Use `onWorkerStatus` and `onReconnect` to follow a scan, or `onSessionEvent`
for saved events with thread IDs and worker numbers. `ScanOptions` lists all
callbacks. Preflight checks local inputs without starting Codex, authenticating,
resolving Python, inspecting the plugin, or running lifecycle callbacks.

## Authentication

For local use, sign in with ChatGPT:

```bash
npx @openai/codex-security login
npx @openai/codex-security scan .
```

On a remote or headless machine, use device authentication:

```bash
npx @openai/codex-security login --device-auth
```

For CI, set `OPENAI_API_KEY` or `CODEX_API_KEY`. To store an API key instead,
pass it on stdin:

```bash
printenv OPENAI_API_KEY | npx @openai/codex-security login --with-api-key
```

Environment API keys apply to the current scan and are not stored. Only
`login --with-api-key` saves a key. For a Codex access token, use
`login --with-access-token` with the token on stdin; access-token environment
variables are not scan API keys.

To use another inference provider, set its API key and select its provider:

```bash
export OPENROUTER_API_KEY="<your-openrouter-api-key>"
npx @openai/codex-security scan . --provider openrouter --model anthropic/claude-sonnet-4.5

export FIREWORKS_API_KEY="<your-fireworks-api-key>"
npx @openai/codex-security scan . --provider fireworks --model accounts/fireworks/models/qwen3-235b-a22b

export AWS_BEARER_TOKEN_BEDROCK="<your-bedrock-api-key>"
export AWS_REGION="us-east-2"
npx @openai/codex-security scan . --provider amazon-bedrock --model openai.gpt-5.6-luna
```

Bedrock also accepts standard AWS access keys, profiles, web identity,
container credentials, and the default AWS credential chain. Set `AWS_REGION`
and select a Bedrock model with `--model`. OpenAI Bedrock models such as
`openai.gpt-5.6-luna` support `--max-cost`.

On Windows, set the API key in PowerShell:

```powershell
$env:OPENAI_API_KEY = "<your-api-key>"
npx @openai/codex-security scan C:\code\repository
```

Login, logout, and scans share a private credential home at
`$CODEX_SECURITY_STATE_DIR/codex-home`, or
`$CODEX_HOME/state/plugins/codex-security/codex-home`. Codex uses its configured
file or keyring backend and honors managed-device policies. An existing
file-based Codex sign-in is imported if this home has no credentials. Logout
disables that import until you log in again.

If ChatGPT credentials cannot be refreshed, run `login status`. Retry if the
sign-in recently changed; otherwise run `logout`, then `login`.

When both ChatGPT and an environment API key are available, interactive scans
ask which to use for that scan. CI, JSON output, dry runs, and other
noninteractive scans prefer the API key. Select explicitly with `--auth`:

```bash
npx @openai/codex-security scan . --auth chatgpt
npx @openai/codex-security scan . --auth api-key
```

`--auth chatgpt` ignores environment API keys. `--auth api-key` requires
`OPENAI_API_KEY` or `CODEX_API_KEY`. The default is `--auth auto`; unset both
variables to default to ChatGPT. The SDK uses the same `auth` option on `run`
and `preflight`. Codex may still need ChatGPT credentials to load
workspace-managed policies when using an API key.

Some cybersecurity requests and protected findings require approval through
Trusted Access for Cyber. To apply or check your access, visit
[chatgpt.com/cyber](https://chatgpt.com/cyber).

## CLI

```bash
npx @openai/codex-security scan .
npx @openai/codex-security scan /path/to/repository --path src --path tests
npx @openai/codex-security scan /path/to/repository --diff origin/main --json
npx @openai/codex-security scan /path/to/repository --output-dir /path/outside/repository/results
npx @openai/codex-security scan /path/to/repository --dry-run
```

Run `scan --help` for all options, `--version` for the installed version, or
`info --json` for package, plugin, runtime, and model details. `--dry-run`
checks local inputs and reports effective settings without starting Codex or
contacting the network. It does not verify authentication, model access,
the plugin, or Python.

### Scan options and output

`--path` scopes a scan to one or more paths, `--diff` scans committed changes,
and `--working-tree` scans staged and unstaged changes. Deep scans support
repository and path targets.

Working-tree snapshots include files from untracked nested Git repositories.
Initialized submodules must be clean and checked out at the commit recorded by
the parent repository.

Repeat `--knowledge-base PATH` to include files or directories containing
Markdown, text, PDF, or Word (`.docx`) documents. Directories are searched
recursively; bulk scans share the documents with every repository.

Use an empty output directory outside the scanned directory and its enclosing
Git worktree. On macOS/Linux, an existing directory must be private to the
current user (`chmod 700`). Use `--archive-existing` to move previous results
to `<output-dir>.previous-<timestamp>-<id>` before scanning, or add `--dry-run`
to preview the move. SARIF, when produced, is at
`<scan-dir>/exports/results.sarif`.

Scans are report-only by default. `--fail-on-severity high` exits with code `1`
when a completed scan finds high or critical issues. Incomplete scans still
write available results to stdout and a coverage warning to stderr, then exit
with code `2`.

### Attribute scans to end users

For an application that serves multiple users, pass the originating user's
stable hashed ID on each scan:

```ts
await security.run("/path/to/repository", {
  auth: "api-key",
  safetyIdentifier: hashedUserId,
});
```

```bash
codex-security scan /path/to/repository --auth api-key --safety-identifier hashed-user-id
```

The ID must be 1 to 64 characters, nonblank, and free of NUL. Do not use an
email address or other personal data. It applies to the scan, workers,
retries, and follow-up work without changing shared configuration. Supply it
again for reruns.

This requires native `--safety-identifier` support and a plugin that forwards
it to workers. The bundled runtime does not yet support it; select a compatible
build with `CODEX_CLI_PATH`. The SDK validates the format but does not check
runtime or plugin compatibility, so older versions may omit the identifier.

### Scan project components

`scan --path` runs one scan across the selected paths. Use `scan-components`
to run a separate standard scan for each component of one local project:

```bash
npx @openai/codex-security scan-components /path/to/project \
  --component apps/api --component apps/web --component packages/shared \
  --workers 4 --output-dir /path/outside/project/results
```

Use `--auto` instead of `--component` to let Codex propose the split. To review
or edit it first, save a plan, then run that plan into a new output directory:

```bash
npx @openai/codex-security scan-components /path/to/project \
  --auto --plan-only --output-dir /path/outside/project/plan
npx @openai/codex-security scan-components /path/to/project \
  --components-file /path/outside/project/plan/components.json \
  --output-dir /path/outside/project/results
```

A component can contain several repository-relative paths:

```json
{
  "components": [
    { "name": "API", "paths": ["apps/api", "packages/auth"] },
    { "name": "Web", "paths": ["apps/web"] }
  ]
}
```

Automatic planning follows Git ignore rules and puts omitted files in an
`Other files` component. Each proposed path must contain an inventoried file.
Planning does not change source files.

Each component saves artifacts under `component-N/`. The combined
`findings.json` merges high-confidence root-cause matches, retaining the highest
severity and original IDs; uncertain matches stay separate. `summary.json`
records coverage and matching status, and `report.md` links to component
reports. Export and publish from the individual scan folders, not the combined
summary.

The output directory must be empty and outside the project. Failed components
do not stop others. Failures, incomplete coverage, or failed matching exit with
code `2`. To retry failed or incomplete components, pass
`retry-components.json` to `--components-file` with a new output directory.

`--max-cost` applies per component, excluding planning and matching.
`--model` and `--effort` also apply to matching; `--auth` applies throughout.
Knowledge-base and prompt-file options work as for bulk scans.

From TypeScript, use `runComponentScans({ repository, outputDir, components })`.
Use `auto: true` for planning, `planOnly: true` to save the plan without scans,
and `scanOptions.auth` to select credentials.

### Configure deep scans

For `scan --mode deep`, `--workers` limits concurrent discovery workers,
`--subagents` controls each worker's subagents, `--stop-after-no-new` stops after
that many runs find no new issues, `--max-discovery-runs` limits total runs, and
`--max-time-hours` limits discovery duration. These options are also available
on SDK scans:

```ts
await security.run("/path/to/repository", {
  mode: "deep",
  workers: 2,
  subagents: 0,
  stopAfterNoNew: 3,
  maxDiscoveryRuns: 10,
  maxTimeHours: 1.5,
});
```

Defaults in `$CODEX_HOME/codex-security/config.toml`
(`~/.codex/codex-security/config.toml` by default) are:

```toml
[deep_scan]
workers = 4
subagents = 3
stop_after_no_new = 4
stop_after_consecutive_errors = 3
max_discovery_runs = 40
max_time_hours = 96
```

Explicit CLI and SDK options override these values. Set
`stop_after_consecutive_errors` in the file; `--codex` does not configure this
section. Worker and run counts must be positive integers; `subagents` can be
zero. The legacy `workers = "auto"` resolves to four. Unknown keys are rejected.

`max_time_hours` accepts positive values up to 96, including fractional hours.
At the deadline, discovery stops and completed findings are reduced and returned.

`scan --workers` controls discovery workers within one deep scan;
`bulk-scan --workers` controls how many repositories are scanned concurrently.

### Runtime configuration and worker limits

Scans use an isolated Codex configuration, not your user or repository Codex
configuration. The defaults are:

```toml
approval_policy = "on-request"
approvals_reviewer = "auto_review"
cli_auth_credentials_store = "auto"
model = "gpt-5.6-sol"
model_reasoning_effort = "xhigh"
model_reasoning_summary = "detailed"
show_raw_agent_reasoning = true

[features]
plugins = true
goals = true

[features.multi_agent_v2]
enabled = true
max_concurrent_threads_per_session = 9

[windows]
sandbox = "unelevated"
```

Use `--model` to choose a model and `--effort minimal|low|medium|high|xhigh|max`
for reasoning effort. Repeat `--codex KEY=VALUE` for other TOML settings:

```bash
npx @openai/codex-security scan . \
  --model gpt-5.6-terra \
  --effort high \
  --codex features.multi_agent_v2.max_concurrent_threads_per_session=4
```

The thread limit includes the parent agent, so `9` allows up to eight delegated
workers. It is separate from deep-scan and bulk-scan worker counts.

Quote string values as TOML, for example
`--codex 'model_reasoning_effort="high"'`. Do not pass both `--model` and
`--codex 'model="..."'`, or both `--effort` and
`--codex 'model_reasoning_effort="..."'`: conflicting or repeated keys are
rejected.

Choose a plugin with `--plugin-path`; overrides of `plugins`, `marketplaces`,
or `features.plugins`, including in profiles, are rejected. Multi-agent v2 must
stay enabled; `agents.max_threads` and
`features.multi_agent_v2.enabled=false` are rejected.
`validate` and `patch` accept `--effort` and only the `model` and
`model_reasoning_effort` `--codex` keys; they do not accept general scan
runtime overrides.

These overrides cannot replace the scanner-owned approval reviewer or
filesystem profile. Use `--codex 'approval_policy="never"'` to deny approval
requests instead of reviewing them automatically. See
[Local security model](#local-security-model).

### Environment variables

| Variable                                                                    | Effect                                                                                        |
| --------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------- |
| `OPENAI_API_KEY`, `CODEX_API_KEY`                                           | Scan authentication; `OPENAI_API_KEY` wins when both are present.                             |
| `CODEX_SECURITY_LINEAR_TEAM`, `CODEX_SECURITY_LINEAR_PROJECT`               | Default Linear team and project for completed-scan publication.                               |
| `CODEX_SECURITY_LINEAR_API_KEY`                                             | Patch Linear issues or publish directly with a personal API key.                              |
| `CODEX_SECURITY_LOG_LEVEL`                                                  | CLI-only; set to `debug` for verbose diagnostics.                                             |
| `LOG_LEVEL`                                                                 | CLI-only fallback when `CODEX_SECURITY_LOG_LEVEL` is unset.                                   |
| `CODEX_SECURITY_STATE_DIR`                                                  | Override the private scan-history, workbench, and default artifact directory.                 |
| `CODEX_HOME`                                                                | Set the ambient Codex home for file-backed sign-in and default state; defaults to `~/.codex`. |
| `CODEX_CLI_PATH`                                                            | Use another Codex executable for authentication, plugin setup, scans, and nested workers.     |
| `PYTHON`                                                                    | Select a Python interpreter when `--python` or SDK `pythonPath` is not set.                   |
| `GH_HOST`                                                                   | Select a GitHub Enterprise host during interactive `bulk-scan` discovery.                     |
| `CODEX_SECURITY_NO_UPDATE_NOTICE`, `NO_UPDATE_NOTIFIER`                     | Disable interactive update notices when either variable is defined.                           |
| `CODEX_SECURITY_NPM_REGISTRY`, `npm_config_registry`, `NPM_CONFIG_REGISTRY` | Select the update-check registry, in the listed precedence order.                             |
| `CI`                                                                        | Disable interactive update notices in automated environments.                                 |
| `NO_COLOR`, `TERM`                                                          | Disable colored scan-history output when `NO_COLOR` is defined or `TERM=dumb`.                |

Custom Codex executables need thread source attribution for `exec` and
`app-server` (Codex 0.149.1+). On Windows, use a native `.exe` or `.com`;
command shims such as `codex.cmd` fall back to the bundled executable.

Interpreter discovery uses `--python` or `pythonPath` first, then `PYTHON`,
the managed Codex runtime, and finally `python3` or `python` from `PATH` (`py`
is also supported on Windows).
`CODEX_SECURITY_STATE_DIR` takes precedence over `CODEX_HOME`; keep both
state and result paths outside the scanned repository.

### Progress and cost

Interactive scans show a full-screen progress view. CI, redirected output,
and `--headless` use plain status lines. Progress and diagnostics go to stderr;
results go to stdout. Add `--verbose` for diagnostics, and review logs for
sensitive information before sharing them.

Each scan records its model, tokens, and estimated cost in its JSON result,
scan history, and bulk-scan receipt. Estimates use
[standard API token prices](https://developers.openai.com/api/docs/models/compare),
including cached input and cache writes; fees and surcharges are not included.

`--max-cost USD` stops a scan and its workers when estimated cost exceeds the
limit. In-flight requests can finish above it. A deep scan that has finished
discovery returns a sealed partial report without further model requests,
listing unvalidated candidates as follow-up work. Incomplete coverage exits
with code `2`. For bulk scans, the limit applies per repository attempt.

### Bulk scans

Sign in with `gh auth login`, then run `npx @openai/codex-security bulk-scan`
to select GitHub repositories pushed in the last 90 days, excluding forks and
archived repositories. Private checkouts reuse the GitHub CLI sign-in.
The command prompts for an output directory and saves the selection to
`repositories.csv` there. `--output-dir` is only valid with a CSV input.

To use an existing repository list or run in CI, pass a CSV with required `id`,
`repository`, and `revision` columns. Revisions must be full commit hashes;
optional `scope`, `mode`, and `prompt` columns customize individual scans:

```csv
id,repository,revision,scope,mode,prompt
service,https://github.com/acme/service.git,0123456789abcdef0123456789abcdef01234567,src,standard,Focus on authentication and authorization.
```

```bash
npx @openai/codex-security bulk-scan repositories.csv \
  --output-dir /path/outside/repositories/security-scans --workers 4
```

Use `--scan-prompt-file PATH` to add instructions to a scan or every bulk scan.
Bulk scans append each repository's CSV `prompt` after the shared instructions.
Use `--post-scan-prompt-file PATH` to run a follow-up in the same authenticated
session after each scan, including incomplete or failed scans. Canceled scans
and scans stopped at their configured cost limit do not start another turn.

`--workers` defaults to `4` concurrent repositories. `--max-attempts` defaults
to `1` attempt per pending repository per invocation. Rerun the same command
to resume. Use `bulk-scan --help` for all options.

### Custom validation

Replace the final validation step of a standard or diff scan with a prompt
file. Source review still runs; discovery workers do not receive this prompt.

```bash
npx @openai/codex-security scan . --validation-prompt-file validation.md
```

The SDK accepts the same text as `validationPrompt`:

```ts
const result = await security.run(repository, {
  validationPrompt:
    "Run scripts/validate.sh, test each candidate through the local API, and stop the test environment when finished.",
});
```

Include setup, allowed targets, required evidence, and cleanup in the prompt;
there are no separate setup or teardown hooks. Reference credentials through
environment variables. Deep scans reject this option; scans with no candidates
skip the custom turn.

The SDK supplies the candidate IDs and requires a `CustomValidationResult`:

```json
{
  "status": "complete",
  "reason": null,
  "validations": [
    {
      "candidateId": "candidate-1",
      "validation": {
        "disposition": "reportable",
        "method": "integration test",
        "confidence": "high",
        "confidence_rationale": "The test reproduced the reported behavior.",
        "rubric": "Check the protected operation.",
        "evidence": ["The unauthorized request succeeded."],
        "counterevidence_or_proof_gap": "",
        "remaining_uncertainty": "",
        "artifact_paths": []
      },
      "severity": null,
      "impact": null
    }
  ]
}
```

Return one result per candidate with disposition `reportable`, `suppressed`,
`not_applicable`, or `deferred`. Set `severity` or `impact` to
`{ "level": "medium", "rationale": "..." }` to revise an assessment, or `null`
to retain it. Identity and source locations stay unchanged.

Candidates and results are saved under `artifacts/custom-validation/`,
including suppressed and deferred candidates. Deferred candidates, setup
failures, and incomplete or invalid output leave coverage incomplete. An
incompatible plugin also stops the scan; there is no fallback to default
validation. Supply `--validation-prompt-file` again when rerunning the scan.

### Publish findings to Cloud

Choose completed scans from your local history:

```bash
npx @openai/codex-security publish scan --to cloud --dry-run --json
```

Press Space to select scans, then Enter to submit. Nothing is preselected.

For scripts, repeat `--scan` with saved scan IDs or unique ID prefixes (at
least eight characters):

```bash
npx @openai/codex-security publish scan \
  --scan SCAN_ID_A --scan SCAN_ID_B \
  --to cloud --dry-run --json
```

Use `scans list --json` to find IDs, or `--scan latest` for the current
repository's latest completed scan. Sealed artifacts must still be available
locally.

`--dry-run` checks inputs and prints findings without uploading or logging in.
Live uploads require file-stored ChatGPT credentials. Set this in your Codex
`config.toml`, then sign in with ChatGPT again:

```toml
cli_auth_credentials_store = "file"
```

Cloud publication rejects automatic and keyring storage, even if an
`auth.json` file exists: the file may be stale or belong to another account.

To publish findings from a CSV instead of a completed scan, pass the CSV
created by `codex-security export --export-format csv`:

```bash
npx @openai/codex-security publish scan --to cloud \
  --csv /path/outside/repository/findings.csv
```

The [findings CSV template](https://github.com/openai/codex-security/blob/main/examples/findings.csv)
contains the required export columns. Deep-scan exports may also include
`candidate_id`. Validate a CSV with `--dry-run --json`. `--csv` only supports
Cloud and cannot be combined with scan IDs or directories.

For artifacts outside local history, pass a directory or repeat
`--scan-dir PATH`. Each directory must contain one completed, sealed scan;
bulk-run directories and `results.jsonl` are not accepted. Do not mix directory
inputs with `--scan`.

For multiple distinct scans, output contains:

- `results`: receipts or dry-run previews, each with its `scanId` and `scanDir`.
- `failed`: errors with `scanDir` and, for saved selections, `scanId`.
- `notAttempted`: saved scan IDs, or paths for directory inputs, that the command
  did not reach before cancellation.

One scan returns its result directly. Scans upload sequentially; a failure does
not stop later scans, but makes the command exit with code `2`. Cancellation
stops new requests and returns partial results with code `130` (Ctrl-C) or
`143` (SIGTERM), unless every publication was already confirmed.

Receipts contain Cloud finding IDs in request order, not local finding IDs.
Save the command output: Cloud receipts are not stored in scan history.
Uploads are never retried automatically. A missing or invalid receipt does
not prove failure; check Cloud before retrying, and never resend a scan with
a confirmed receipt.

### Publish completed scans to Linear

Publish findings from one completed scan to a Linear team:

```bash
npx @openai/codex-security publish scan --scan SCAN_ID \
  --to linear \
  --linear-team TEAM_ID
```

Use a scan ID, unique prefix, `latest`, or a scan directory (positional or
`--scan-dir PATH`). Omit the selector to choose interactively. The completed
scan must exist in local history.

Add `--linear-project PROJECT_ID` (`--project` is an alias) to place issues in
a project. Destination flags override `CODEX_SECURITY_LINEAR_TEAM` and
`CODEX_SECURITY_LINEAR_PROJECT`. `--dry-run` previews issue titles without
contacting Linear; `--json` returns structured results.

By default, publication uses your existing Codex configuration and connected
Linear app, not the isolated scan home. Sign in to Codex and connect Linear
first. To use the Linear API directly instead, set a personal API key:

```bash
export CODEX_SECURITY_LINEAR_API_KEY=YOUR_LINEAR_PERSONAL_API_KEY
npx @openai/codex-security publish scan /path/to/completed-scan \
  --to linear \
  --linear-team TEAM_ID
```

Direct API publication leaves issues unassigned unless you pass
`--linear-assignee` with a user ID or email. `--linear-api-key KEY` overrides
the environment variable, but exposes the key in shell history and process
listings. Keys are omitted from saved results and artifacts; error messages
are returned unchanged.

Check scan integrity and recorded publications before publishing:

```bash
npx @openai/codex-security publish check /path/to/completed-scan \
  --to linear --linear-team TEAM_ID --json
```

`publish check` is read-only. With an API key it also checks authentication,
team, project, and assignee access; connected-app access is `not-checked`.
Issue-creation permission is always `not-tested`.

Each finding creates an issue titled `[Codex Security][HIGH] Finding title`
with source locations, code, evidence, and remediation. Choose a destination
authorized to receive those details. Successful issue IDs are saved in local
history, separately from sealed scan artifacts.

Publishing again creates duplicate issues by default. `--skip-existing` skips
recorded successes for the same occurrence, team, and project; results separate
`created` and `skipped` issues. It does not search or verify remote issues.
Combine it with `--dry-run` to preview the remaining findings.

An interrupted or indeterminate publication may have created issues that local
history does not record. Inspect the retained handoff, evidence, and Linear
destination before retrying. The CLI cannot recover unrecorded remote issues;
`--skip-existing` cannot prevent those duplicates or concurrent publications.

You can also publish a scan from TypeScript:

```ts
import { publishScan } from "@openai/codex-security";

const publication = await publishScan("/path/to/completed-scan", {
  destination: "linear",
  teamId: "TEAM_ID",
});

console.log(publication.scanId);
console.log(publication.created.length);
```

Options include `projectId`, `skipExisting`, `linearApiKey` for direct API
publication, and `assigneeId` (user ID or email). `checkScanPublication` accepts
the same destination options for a read-only check.

### Scan history and reruns

Commands default to the current repository. Scan selectors accept a full ID
or unique prefix of at least eight characters.

| Command                                               | Purpose                                                                                                      |
| ----------------------------------------------------- | ------------------------------------------------------------------------------------------------------------ |
| `scans list [REPOSITORY]`                             | List scans; use `--scan-root DIR` to filter by artifact root.                                                |
| `scans show [SCAN_ID]`                                | Show a scan, defaulting to the latest completed one. Add `--show-linked-findings` for earlier finding links. |
| `scans logs [SCAN_ID]`                                | Show session events, defaulting to the latest scan, including active scans.                                  |
| `scans rerun [SCAN_ID]`                               | Repeat a scan against the current checkout, defaulting to the latest completed scan.                         |
| `scans match BEFORE AFTER`                            | Link findings with the same root cause.                                                                      |
| `scans match --all`                                   | Match completed scans across worktrees and clones of the repository.                                         |
| `scans compare [BEFORE] [AFTER]`                      | Compare selected scans, defaulting to the latest two completed scans.                                        |
| `findings list [REPOSITORY]`                          | List open findings. `findings` is an alias.                                                                  |
| `findings false-positive OCCURRENCE_ID --reason TEXT` | Mark a false positive; later scans dismiss matches only while the reason still applies.                      |

Matching requires sealed artifacts and reuses saved matches unless `--force`
is passed. Comparisons report new, persisting, reopened, resolved, or unknown
findings. A missing finding is not resolved if the later scan is incomplete
or excludes its original scope. With one ID, `scans compare` compares it to
the latest completed scan.

History is stored in `$CODEX_SECURITY_STATE_DIR/workbench.sqlite3`, or
`$CODEX_HOME/state/plugins/codex-security/workbench.sqlite3`. Keep the state
directory writable and outside the scanned repository. Scan configurations
do not store credentials, but session logs and live details can contain them.
During a scan, press `d` for details, then `a` for all sources, `m` for the main
scan, or `1` through `9` for a worker.

### Exports and CI

`export` creates CSV, JSON, or SARIF from a completed, sealed scan without
starting Codex or loading credentials. It defaults to the current repository's
latest completed scan. Use `--output -` for stdout, or `--source-root PATH`
with SARIF to add source-line fingerprints. Run `export --help` for all options.

JSON preserves the sealed findings document. CSV marks findings as open and
omits local triage state. CSV cannot go to stdout when JSON output is requested.

For CI, save output outside the checkout and set a severity threshold:

```bash
SCAN_ROOT="$(mktemp -d)"
npx @openai/codex-security scan . \
  --diff origin/main \
  --output-dir "$SCAN_ROOT/results" \
  --json \
  --fail-on-severity high > "$SCAN_ROOT/findings.json"
```

Scan exit codes are `0` for a completed report-only scan or passing policy,
`1` for a policy violation, `2` for invalid input, incomplete coverage, or a
runtime/export error, `130` for interruption, and `143` for termination.
JSON scans do not use interactive controls. `validate`, `login`, and `logout`
reject `--json`.

`install-hook` scans staged and unstaged changes before each commit, blocking
high-severity findings or failed scans. It respects `core.hooksPath` and leaves
existing hooks alone. Use `--fail-on-severity` to change the threshold.

### Import alerts from the CLI

`import github OWNER/REPO` reads open code scanning alerts on the default
branch. Repeat `--github-alert NUMBER` for exact alerts, use
`--github-state open|closed|dismissed|fixed|all` to filter lists, or
`--github-ref REF` to select a reference. See the
[SDK import options](#import-github-code-scanning-alerts) for authentication.

```bash
# Import all open alerts, or a selected subset, as complete JSON.
npx @openai/codex-security import github example/repository --format json \
  > /path/outside/repository/github-alerts.json
npx @openai/codex-security import github example/repository \
  --github-alert 12 --github-alert 18 --format json
# Run from the corresponding local repository; imported contents are data.
npx @openai/codex-security validate /path/outside/repository/github-alerts.json
```

Import is read-only and returns an alert array (`[]` when empty). `--json`
aliases `--format json`. Avoid output filters or token limits when saving
validation inputs. The SDK loop returns a separate disposition for each alert.

### Validate and patch findings

`validate` assesses a candidate; `patch` fixes and verifies it. Both accept
files or literal text and operate on the current directory. For `patch`, a
saved finding or occurrence ID instead selects its original repository.

```bash
npx @openai/codex-security validate "Possible SQL injection" --effort high
npx @openai/codex-security patch OCCURRENCE_ID
npx @openai/codex-security patch --scan SCAN_ID --severity high --json
npx @openai/codex-security patch --scan SCAN_ID --severity high --create-pr
```

`--scan latest` selects the latest scan of the current repository. Saved-finding
patch commands support `--json`; literal-text and file patch commands do not.
Override the model with `--codex 'model="gpt-5.6-sol"'` or reasoning effort with
`--effort high`. Each finding gets a separate saved Codex desktop task.

Use `scan --patch` to patch after a complete scan. `--patch-severity` defaults
to `low`; `high` selects high and critical findings. The interactive finding
browser also lets you select findings and add patch instructions.
Patch results contain a `patches` entry per finding with status `verified`,
`no_change`, `blocked`, or `failed`. Verified and already-fixed findings no
longer fail `--fail-on-severity`.

`--create-pr` commits verified patch files and uses `gh` to open a draft PR.
If publication fails, run the printed `patch --resume-pr BRANCH` command from
the same repository. It reuses the saved commit without rerunning Codex and
refuses to publish if the branch changed.

For Linear, repeat `--linear-issue ISSUE` (ID or URL), or use
`--linear-project "PROJECT"` with an optional native `--linear-filter` JSON
filter. Completed and canceled issues are excluded unless the filter sets
`state`. Authenticate with `CODEX_SECURITY_LINEAR_API_KEY`, `LINEAR_API_KEY`,
or `LINEAR_ACCESS_TOKEN` for OAuth. `--linear-api-key KEY` overrides them;
prefer environment variables to keep keys out of shell history. Intake is
read-only, includes issue comments, and does not pass Linear credentials to
the patch subprocess. Issue URLs must match the selected workspace.

### Verify fixes

`verify-fix` checks a fix in a read-only sandbox. Pass a finding description,
saved finding ID, `--scan SCAN_ID`, `--linear-issue ISSUE`, or
`--linear-project "PROJECT"`. Linear credentials and filters work as for
`patch`; explicitly filter for completed issues when checking a finished
backlog.

Results are `fixed`, `still_vulnerable`, or `inconclusive`, with evidence.
Use `--json` for structured output. Exit code `0` means all findings are fixed,
`1` means at least one remains vulnerable, and `2` means verification was
inconclusive or could not finish.

### Command discovery and integrations

The CLI uses [Incur](https://github.com/wevm/incur). Use `--llms` for the
command manifest, `scan --schema --format json` for a command schema, and
`completions bash|zsh|fish` for shell completions. Scan output supports
`--format toon|json|yaml|jsonl` and `--full-output`.

`skills add` syncs agent skills; `mcp add` registers the CLI as an MCP server.
MCP exposes only the read-only `info` command because the transport cannot
cancel active scans. Other commands remain CLI-only.

## Containerized bulk scans

Create `repositories.csv` as described under [Bulk scans](#bulk-scans).
With a published container image, run from the Codex Security repository root:

```bash
mkdir -p results state
chmod 700 results state
export CODEX_SECURITY_USER="$(id -u):$(id -g)"
export CODEX_SECURITY_IMAGE=ghcr.io/openai/codex-security:latest
docker compose pull codex-security
docker compose run --rm codex-security login --device-auth
docker compose run --rm codex-security
```

Results go to `results/`; the device login stays in `state/`. For unattended
scans, set `OPENAI_API_KEY` or `CODEX_API_KEY`. Private GitHub checkouts use
`GH_TOKEN` or `GITHUB_TOKEN`; GitHub Enterprise uses `CODEX_SECURITY_GIT_HOST`.
The container requires CSV input and does not support interactive discovery.

Compose accepts `CODEX_SECURITY_IMAGE`, `CODEX_SECURITY_USER`,
`CODEX_SECURITY_SECCOMP`, `CODEX_SECURITY_CSV`, `CODEX_SECURITY_RESULTS`, and
`CODEX_SECURITY_STATE` for the image, user, seccomp profile, and mounts.

On Ubuntu hosts that restrict unprivileged user namespaces, an administrator
can install the optional AppArmor profile:

```bash
sudo install -m 0644 docker/codex-security.apparmor /etc/apparmor.d/codex-security-container
sudo apparmor_parser -r -W /etc/apparmor.d/codex-security-container
docker compose -f compose.yaml -f compose.apparmor.yaml run --rm codex-security
```

The override keeps the nonroot user, dropped capabilities,
no-new-privileges, and seccomp policy. Other Docker hosts do not need it.

## Local security model

Codex Security runs with your operating-system permissions. Scan only
repositories you trust and are authorized to assess. Local tools and scans
under the same account are not separate security principals.

The `codex_security_scan` filesystem profile allows reads across the local
filesystem and writes to workspace roots and the scan state directory.
Execution approvals are reviewed automatically and may grant additional
permissions for a specific operation.
Set `--codex 'approval_policy="never"'`, directly or in a selected profile, to
deny approval requests. Other overrides cannot replace the reviewer or
filesystem profile. Saved scans retain their approval policy; older scans
remain deny-all on rerun. Host and network restrictions still apply.

Scan and workbench subprocesses can inherit your environment, including
unrelated API tokens and cloud credentials. Start a scan with only the
credentials it needs.

Repository contents, model output, and imported artifacts do not authorize
access to other targets, disclosure of credentials, or writes outside approved
paths. See the security policy below for the full threat model.

## Documentation and security

- [CLI quickstart](https://developers.openai.com/codex/security/cli)
- [TypeScript SDK guide](https://developers.openai.com/codex/security/sdk)
- [GitHub issues](https://github.com/openai/codex-security/issues) for bugs and
  feature requests
- [Security policy](https://github.com/openai/codex-security/blob/main/SECURITY.md)
  for private vulnerability reporting and safe operation
