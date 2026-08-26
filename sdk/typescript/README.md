# `@openai/codex-security`

Open-source TypeScript SDK and CLI for running Codex Security scans. The
ESM-only package includes TypeScript declarations, the `codex-security`
executable, and the matching Codex runtime.

> [!NOTE]
> This package follows semantic versioning. Its public API may change between
> minor versions before `1.0.0`.

## Install

```bash
npm install @openai/codex-security
npx @openai/codex-security --version
```

The package supports macOS, Linux, and Windows and requires Node.js 22.13.0 or
later in the 22.x release line, Node.js 24.x, or Node.js 26.x. Scans, bulk
scans, exports, scan history, and saved findings also require Python 3.10 or
later. Python 3.10 also requires `tomli`. Use `--python` with `scan`,
`bulk-scan`, or `export`; use `pythonPath` with the SDK. Set `PYTHON` to select
an interpreter for any Python-backed command.

When a newer version is available, the CLI shows the update command for your
installation method. Set `CODEX_SECURITY_NO_UPDATE_NOTICE=1` to hide the
notice. Notices are also disabled in CI and when stderr is not a terminal.

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
Use `security.preflight()` to validate local inputs, `onWorkerStatus` and
`onReconnect` to observe long-running scans, and an `AbortSignal` to cancel a
scan.

For separate standard scans under one project, the SDK also exports
`runComponentScans({ repository, outputDir, components })`. Each component has
a `name` and `paths` array. Use `auto: true` instead of `components` for
model-assisted planning, and `planOnly: true` to save the plan without scanning.

Successful results include open repository findings in `repositoryFindings`,
when available; `findings` remains the current scan. Matching earlier findings
can make one additional model call, including with a scan cost limit.

Results can contain source excerpts, vulnerability details, and reproduction
steps. Keep result directories and saved reports outside the repository and
limit access to authorized reviewers.

### Validate an existing finding

Use `security.validate()` to assess one finding without running a repository
scan or invoking the Codex Security CLI:

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

`finding` accepts literal text or a JSON-serializable object, never a file
path. Read files explicitly. Validation uses the CLI's validation skill and
the client's settings and authentication. It leaves repository files unchanged
and does not add a scan to scan history.

The result contains `disposition` (`reportable`, `suppressed`, `not_applicable`,
or `deferred`), a Markdown `report`, `threadId`, and `outputDir` for evidence.
The report explains root cause, exploitability, evidence, and proof gaps.
`reportable` can rely on static analysis; `deferred` means insufficient evidence.

`outputDir` must be empty and outside the enclosing Git worktree. It defaults
to the Codex Security state directory's `validations/` folder. Pass `auth` to
select authentication or `signal` to cancel. Failed, incomplete, or malformed
responses reject the promise.

### Import GitHub code scanning alerts

Use `importGitHubCodeScanningAlerts()` to read GitHub code scanning findings,
including third-party SARIF uploads, before independent validation:

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
upstream `alert`, including rule/help text, locations, commit/ref, and dismissal
context. Import does not start Codex, register a scan, or change GitHub state.
Validate against the intended local checkout; import does not check out code.

Without `alertNumbers`, `state` defaults to `"open"`; `"closed"`, `"dismissed"`,
`"fixed"`, and `"all"` are also accepted. Exact alert numbers ignore state and
cannot be combined with a nondefault `state`. `ref` selects another branch or
pull-request reference and preserves that reference's alert instance.

Authentication reuses `gh auth token` (including GitHub CLI token environment
variables) unless `githubToken` is supplied. `githubHost` defaults to `GH_HOST`
or `github.com`; `signal` cancels requests. The token needs read access to code
scanning alerts. Access failures reject the import.

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

Progress and lifecycle callbacks are `onAuthentication`, `onCost`,
`onOutputArchived`, `onOutputDirReady`, `onScanStarted`,
`onTrustedAccessStatus`, `onReconnect`, `onSessionEvent`, `onWorkerStatus`,
`onWarning`, and `onObserverError`. `onSessionEvent` receives saved scan and
worker events with their thread IDs and worker numbers. Preflight does not start
the runtime, authenticate, resolve Python, inspect the plugin, or run those
scan-lifecycle callbacks.

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

Environment API keys are supplied directly to the current scan and are never
saved to the Codex credential home or system keyring. Only an explicit
`login --with-api-key` stores an API key.

To pass a Codex access token explicitly, use
`login --with-access-token` and provide the token on stdin. An access token
environment variable is not automatically used as a scan API key.

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

On Windows, set the API key in PowerShell:

```powershell
$env:OPENAI_API_KEY = "<your-api-key>"
npx @openai/codex-security scan C:\code\repository
```

Codex Security keeps its sign-in in a private, stable Codex home at
`$CODEX_SECURITY_STATE_DIR/codex-home`, or at
`$CODEX_HOME/state/plugins/codex-security/codex-home` when no state directory is
configured. On managed Windows devices, inherited access for `SYSTEM` and local
`Administrators` is preserved while protecting the home against future changes
to its parents. Other users and broad groups are rejected, and PowerShell
Constrained Language Mode is supported. Login,
status, logout, and scans use the same home. Codex manages
credentials using its configured file or system-keyring backend and honors
managed-device policies. An existing file-based Codex sign-in is imported only
when the dedicated home does not already contain stored credentials. Logging
out prevents later scans from automatically reimporting that ambient sign-in
until you explicitly log in again.

Scan runtime preparation locks this home even if the process pauses; exiting or
crashing releases the lock. A compatibility heartbeat prevents released
heartbeat-only clients from replacing an active newer owner's lock, but those
clients can still replace a paused newer owner's lock. Finish operations using
older versions before upgrading. Keep `.codex-security-scan.sqlite3` between
operations and never remove it while an operation is running. PID reuse can make
older PID-only locks look live and block recovery. Stop all operations using
this home before manually removing an old `.codex-security-scan.lock` directory.

If a scan says the stored ChatGPT sign-in could not be refreshed, check it with
`npx @openai/codex-security login status` and retry if it recently changed.
Otherwise replace it with `npx @openai/codex-security logout`, then
`npx @openai/codex-security login`. Codex Security does not automatically clear
the sign-in or change managed login restrictions.

An environment API key takes precedence for model authentication by default,
but Codex may still need a valid ChatGPT sign-in to load workspace-managed
policies.
When both a stored ChatGPT sign-in and an environment API key are available, an
interactive scan asks which credential to use. JSON output, dry runs, CI, and
other noninteractive scans never prompt and retain automatic API-key
precedence. Select the credential source explicitly with `--auth`:

```bash
npx @openai/codex-security scan . --auth chatgpt
npx @openai/codex-security scan . --auth api-key
```

`--auth chatgpt` uses the stored sign-in and ignores `OPENAI_API_KEY` and
`CODEX_API_KEY`. `--auth api-key` requires one of those environment variables.
Omit `--auth`, or pass `--auth auto`, to preserve automatic API-key precedence
for existing CI and unattended scans. The SDK accepts the same selection as
`security.run(repository, { auth: "chatgpt" })` and
`security.preflight(repository, { auth: "chatgpt" })`.

To make the stored ChatGPT sign-in the automatic default instead, unset any
configured API-key variables:

```bash
unset OPENAI_API_KEY CODEX_API_KEY
```

The interactive choice applies only to the current scan and is not persisted.

When an environment key is configured, ChatGPT login and
`codex-security login status` identify the effective scan credential source
without printing its value, including when no stored sign-in exists.

Some cybersecurity requests and protected findings require approval through
Trusted Access for Cyber. To apply or check your access, visit
[chatgpt.com/cyber](https://chatgpt.com/cyber).

## CLI

```bash
npx @openai/codex-security scan
npx @openai/codex-security scan /path/to/repository
npx @openai/codex-security scan /path/to/repository --headless
npx @openai/codex-security scan /path/to/repository --patch
npx @openai/codex-security scan /path/to/repository --patch --patch-severity high --json
npx @openai/codex-security scan /path/to/repository --patch --patch-severity high --create-pr
npx @openai/codex-security scan /path/to/repository --model gpt-5.6-terra
npx @openai/codex-security scan /path/to/repository --model gpt-5.6-terra --effort high
npx @openai/codex-security scan /path/to/repository --path src --path tests
npx @openai/codex-security scan-components /path/to/repository --component apps/api --component apps/web --output-dir /path/outside/repository/results
npx @openai/codex-security scan-components /path/to/repository --auto --output-dir /path/outside/repository/results
npx @openai/codex-security scan /path/to/repository --knowledge-base /path/to/threat-models --knowledge-base /path/to/architecture.pdf
npx @openai/codex-security scan /path/to/repository --scan-prompt-file scan.md --post-scan-prompt-file follow-up.md
npx @openai/codex-security scan /path/to/repository --diff origin/main --json
npx @openai/codex-security scan /path/to/repository --output-dir /path/outside/repository/results
npx @openai/codex-security scan /path/to/repository --output-dir /path/outside/repository/results --archive-existing
npx @openai/codex-security scan /path/to/repository --verbose
npx @openai/codex-security scan /path/to/repository --dry-run
npx @openai/codex-security scan /path/to/repository --fail-on-severity high
npx @openai/codex-security scan /path/to/repository --max-cost 5
npx @openai/codex-security scan /path/to/repository --mode deep --workers 2 --subagents 0 --stop-after-no-new 3 --max-discovery-runs 10 --max-time-hours 1.5
npx @openai/codex-security install-hook
npx @openai/codex-security bulk-scan
npx @openai/codex-security bulk-scan --model gpt-5.6-terra --effort high
npx @openai/codex-security bulk-scan --workers 4 --mode deep --max-attempts 3 --max-cost 25
npx @openai/codex-security bulk-scan repositories.csv --output-dir /path/outside/repositories/security-scans --workers 4 --knowledge-base /path/to/threat-models --knowledge-base /path/to/architecture.pdf
npx @openai/codex-security bulk-scan repositories.csv --output-dir /path/outside/repositories/security-scans --scan-prompt-file scan.md --post-scan-prompt-file follow-up.md
npx @openai/codex-security scans list /path/to/repository
npx @openai/codex-security scans list --scan-root /path/outside/repository/results
npx @openai/codex-security scans show
npx @openai/codex-security scans show SCAN_ID
npx @openai/codex-security scans logs
npx @openai/codex-security scans logs SCAN_ID
npx @openai/codex-security scans rerun
npx @openai/codex-security scans rerun SCAN_ID
npx @openai/codex-security scans match PREVIOUS_SCAN_ID CURRENT_SCAN_ID
npx @openai/codex-security scans match --all
npx @openai/codex-security scans compare
npx @openai/codex-security scans compare PREVIOUS_SCAN_ID
npx @openai/codex-security scans compare PREVIOUS_SCAN_ID CURRENT_SCAN_ID
npx @openai/codex-security findings
npx @openai/codex-security findings list /path/to/repository
npx @openai/codex-security findings false-positive OCCURRENCE_ID --reason "The route already checks permissions"
npx @openai/codex-security export
npx @openai/codex-security export /path/outside/repository/results --export-format sarif --output /path/outside/repository/results.sarif
npx @openai/codex-security export /path/outside/repository/results --export-format csv --output /path/outside/repository/findings.csv
npx @openai/codex-security export /path/outside/repository/results --export-format json --output /path/outside/repository/findings.json
npx @openai/codex-security publish scan /path/outside/repository/results --to linear --linear-team TEAM_ID
npx @openai/codex-security publish scan --to linear --linear-team TEAM_ID
npx @openai/codex-security publish scan --to cloud --csv /path/outside/repository/findings.csv
npx @openai/codex-security validate /path/outside/repository/findings.json "Possible SQL injection in src/query.ts:42"
npx @openai/codex-security validate "Possible SQL injection" --effort high
npx @openai/codex-security import github example/repository --format json
npx @openai/codex-security verify-fix --linear-issue SEC-123 --json
npx @openai/codex-security verify-fix --linear-project "Security backlog" --linear-filter '{"state":{"type":{"eq":"completed"}}}' --json
npx @openai/codex-security verify-fix --scan SCAN_ID --severity high --json
npx @openai/codex-security patch /path/outside/repository/findings.json "Missing authorization check in src/routes.ts:18"
npx @openai/codex-security patch "Missing authorization check" --effort high
npx @openai/codex-security patch OCCURRENCE_ID
npx @openai/codex-security patch --scan SCAN_ID --severity high --json
npx @openai/codex-security patch --scan SCAN_ID --severity high --create-pr
npx @openai/codex-security patch --resume-pr codex-security/patch-SCAN_ID
npx @openai/codex-security patch --scan latest --severity medium
npx @openai/codex-security patch --linear-issue SEC-123 --linear-issue SEC-124
npx @openai/codex-security patch --linear-project "Security backlog" --linear-filter '{"labels":{"name":{"eq":"security"}}}'
```

Run `npx @openai/codex-security --version` for the installed CLI version or
`npx @openai/codex-security info --json` for the package, bundled plugin, Codex runtime,
default model, reasoning effort, and first-scan command. A scan with `--dry-run`
also reports its effective model and reasoning effort, including `--codex`
overrides, without starting Codex or contacting the network.

`install-hook` scans staged and unstaged changes before each commit. It respects
`core.hooksPath`, does not replace an existing hook, and blocks high-severity
findings or failed scans. Set `--fail-on-severity` to change the threshold.

`--path` scopes a scan to one or more paths, `--diff` scans committed changes,
and `--working-tree` scans staged and unstaged changes. Deep scans support
repository and path targets. The output directory must be outside the scanned
directory and any enclosing Git worktree. When SARIF is produced, it is written
to
`<scan-dir>/exports/results.sarif`.

Working-tree snapshots include files from untracked nested Git repositories.
Initialized submodules must be clean and checked out at the commit recorded by
the parent repository.

Repeat `--knowledge-base PATH` for multiple files or directories; `bulk-scan`
shares them with every repository. Directories are searched recursively for
Markdown, text, PDF, and Word (`.docx`) files.

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

The ID must contain 1–64 characters and cannot be blank or contain NUL.
Do not use an email address or other personal data. The ID is passed to Codex
for the scan, nested workers, retries, and follow-up work. It is not saved in
shared configuration or the scan recipe. Supply it again for a later rerun.
Concurrent SDK clients can use different IDs without changing `process.env`.

This requires a Codex runtime with native `--safety-identifier` support and a
plugin that forwards it to workers. The current bundled runtime does not yet
support this option. Use `CODEX_CLI_PATH` to select a compatible build.
The SDK does not check runtime or plugin compatibility; older versions may
omit the identifier. Omitting the option leaves ordinary scans unchanged.
Preflight checks the ID's format; authentication is checked when the scan starts.

### Scan project components

`scan --path` runs one scan across the selected paths. Use `scan-components`
to run a separate standard scan for each component of one local project:

```bash
npx @openai/codex-security scan-components /path/to/project \
  --component apps/api --component apps/web --component packages/shared \
  --workers 4 --output-dir /path/outside/project/results
```

Use `--auth chatgpt` or `--auth api-key` to select credentials for planning,
component scans, and matching. The default is `--auth auto`, as with `scan`.
The SDK accepts the same choice through `scanOptions.auth`.

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

Automatic planning uses a local file inventory. In Git repositories it follows
Git's ignore rules. Each automatic path must cover at least one inventoried file.
Explicit `--component` and `--components-file` selections keep their existing behavior.
Inventoried files omitted by the model are added to an
`Other files` component. No source files are changed during planning.

In an interactive terminal, one dashboard shows all components and their scan
progress. Use the arrow keys to select a component, Enter to view its activity,
and Esc to return. Other scans continue while you inspect one. Finding counts
are preliminary until cross-component matching finishes. Use `--headless` for
plain status lines; CI and redirected output use those automatically.
Failed or incomplete components are also saved in `retry-components.json`.
Pass that file to `--components-file` with a new output directory to retry them.

Each component keeps its normal scan artifacts under `component-N/`.
The combined `findings.json` uses the same root-cause matcher as `scans match`.
It merges high-confidence matches even when their titles, locations, or
fingerprints differ. Each group keeps its highest-severity finding and all
original scan and occurrence IDs. Match reasons and uncertain pairs are saved;
uncertain findings stay separate. `summary.json` records scan coverage and
whether matching finished. `report.md` links to the component reports.
These combined files are a project summary, not a new sealed scan. Use the
individual scan folders with `export` and `publish`.

The output directory must be empty and outside the project. Failed components
do not stop the others. The command saves the available results and exits with
code `2` if a component fails, coverage is incomplete, or cross-component
matching fails. `--max-cost` applies to each component scan, not planning,
cross-component matching, or the whole project. `--model` and `--effort` also
apply to matching. `--knowledge-base`,
`--scan-prompt-file`, and `--post-scan-prompt-file` work as they do for bulk scans.

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

Set defaults in `~/.codex/codex-security/config.toml`, or under `$CODEX_HOME`
when it is configured. Explicit CLI and SDK settings override these defaults:

```toml
[deep_scan]
workers = 2
subagents = 0
stop_after_no_new = 3
max_discovery_runs = 10
max_time_hours = 1.5
```

The discovery deadline defaults to 96 hours. The configured value may be any
positive number, including fractional hours, up to 96. At the deadline,
in-flight discovery stops and completed findings are reduced and returned.
The 97-hour outer tool-call timeout reserves approximately one hour for final
reduction and result delivery, including at the 96-hour maximum.

`scan --workers` controls discovery workers within one deep scan;
`bulk-scan --workers` controls how many repositories are scanned concurrently.

On macOS/Linux, an existing output directory must be private to the current
user (`chmod 700`).

If the output directory already contains results, add `--archive-existing`.
The CLI moves them to `<output-dir>.previous-<timestamp>-<id>` and starts the
scan in a new, empty directory at the original path. Add `--dry-run` to see
the destination without moving files.

Scans are report-only by default. Use `--fail-on-severity` in CI to exit 1 when
a completed scan contains a finding at or above the selected severity.
Incomplete coverage and CLI/runtime errors exit 2 so they cannot be mistaken
for a passing policy. Incomplete scans still write the available human or JSON
result to stdout and a coverage warning to stderr, including in report-only
mode.

Use `--patch` to fix and verify confirmed findings after a complete scan.
`--patch-severity high` selects high and critical findings; the default is low
and above. After showing the findings summary, interactive scans with findings
ask whether to open a color-coded finding browser with complete finding details
and a separate patch-instructions panel. Use the arrow keys to
browse, `Tab` to inspect details, `Space` to select individual findings, `i` to
edit instructions for the focused finding, `1`–`4` to select by severity, and
`r` to optionally create a draft GitHub pull request after patching. Press
`Enter` to patch or `q` to keep the checkout unchanged. Each selected finding
runs in its own saved Codex desktop task. Add `--create-pr` to `scan --patch` or a
saved-finding `patch` command to commit only verified patch files and open a
draft pull request with `gh`. If the push or pull request fails, run the printed
`patch --resume-pr BRANCH` command from the same repository. It uses the saved
commit without running Codex again and refuses to publish if the branch changed.
JSON scan results include `patchSeverity`. Scan and
saved-finding results include one `patches` entry per selected finding with
status `verified`, `no_change`, `blocked`, or `failed`, plus `pullRequest` when
one is created. When `--fail-on-severity` is also set, verified and already-fixed
findings no longer fail the policy.

Scans use `gpt-5.6-sol` with extra-high reasoning effort by default. OpenAI is
the implied provider. Use `--model gpt-5.6-terra` to switch models and
`--effort minimal|low|medium|high|xhigh|max` to set reasoning effort. Repeat
`--codex KEY=VALUE` for other Codex settings; existing
`--codex 'model_reasoning_effort="high"'` overrides remain supported.

### Runtime configuration and worker limits

The standalone CLI and SDK do not load an unrelated user or repository Codex
configuration. Each scan starts with a private runtime and these Codex
defaults:

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

Use `--model` and `--effort` for model selection. Repeat
`--codex KEY=VALUE` to deep-merge other TOML values into this isolated
configuration:

```bash
npx @openai/codex-security scan . \
  --model gpt-5.6-terra \
  --effort high \
  --codex features.multi_agent_v2.max_concurrent_threads_per_session=4
```

The session thread limit includes the parent agent: the default of `9`
provides up to eight delegated worker slots. This limit is separate from
`bulk-scan --workers`, which controls how many repositories run concurrently.
A configured limit is a maximum, not evidence that every worker started.

Quote string values as TOML, for example
`--codex 'model_reasoning_effort="high"'`. Do not pass both `--model` and
`--codex 'model="..."'`, or both `--effort` and
`--codex 'model_reasoning_effort="..."'`: conflicting or repeated keys are
rejected.

Plugin and marketplace loading belong to Codex Security. Overrides of
`plugins`, `marketplaces`, or `features.plugins`, including profile-specific
plugin overrides, are rejected; choose `--plugin-path` instead. Native
multi-agent v2 must remain enabled. The legacy `agents.max_threads` setting
and `features.multi_agent_v2.enabled=false` are incompatible and rejected.
`validate` and `patch` accept `--effort` and only the `model` and
`model_reasoning_effort` `--codex` keys; they do not accept general scan
runtime overrides.

These overrides cannot replace the scanner-owned approval reviewer or
filesystem profile. Use `--codex 'approval_policy="never"'` to deny approval
requests instead of reviewing them automatically. See
[Local security model](#local-security-model).

### Deep-scan engine configuration

Deep scans read `$CODEX_HOME/codex-security/config.toml`, defaulting to
`~/.codex/codex-security/config.toml`:

```toml
[deep_scan]
workers = 4
subagents = 3
stop_after_no_new = 4
stop_after_consecutive_errors = 3
max_discovery_runs = 40
max_time_hours = 96
```

The default is four discovery workers; the legacy `workers = "auto"` setting
also resolves to four. Set `workers` to a positive integer to choose an explicit
count. `subagents` must be a nonnegative integer;
`stop_after_no_new`, `stop_after_consecutive_errors`, and `max_discovery_runs`
must be positive integers. `max_time_hours` must be a positive finite number no
greater than 96; fractional hours are supported. Unknown `[deep_scan]` keys are
rejected.

These settings are separate from Codex's
`features.multi_agent_v2.max_concurrent_threads_per_session` and
`bulk-scan --workers`. Standalone CLI and SDK scans create an isolated
`CODEX_HOME`, import the ambient `[deep_scan]` configuration, and apply explicit
CLI or SDK options on top. Set `stop_after_consecutive_errors` in the
configuration file. Use `--codex` to adjust the Codex session thread limit, not
to set `[deep_scan]` values.

### Environment variables

The CLI and SDK recognize the following user-configurable environment:

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

Custom Codex executables must support thread source attribution for both `exec`
and `app-server` requests (Codex 0.149.1 or later).

On Windows, `CODEX_CLI_PATH` must name a native `.exe` or `.com`. Command
shims such as `codex.cmd` automatically use the bundled Codex executable
instead.

Interpreter discovery uses `--python` or `pythonPath` first, then `PYTHON`,
the managed Codex runtime, and finally `python3` or `python` from `PATH` (`py`
is also supported on Windows).
`CODEX_SECURITY_STATE_DIR` takes precedence over `CODEX_HOME`; keep both
state and result paths outside the scanned repository.

The repository's Docker Compose workflow additionally recognizes
`CODEX_SECURITY_IMAGE`, `CODEX_SECURITY_USER`, `CODEX_SECURITY_SECCOMP`,
`CODEX_SECURITY_CSV`, `CODEX_SECURITY_RESULTS`, and `CODEX_SECURITY_STATE` for
its image, runtime user, seccomp profile, input, results, and state mounts.
Provide `GH_TOKEN` or `GITHUB_TOKEN` for private GitHub checkouts and
`CODEX_SECURITY_GIT_HOST` for a GitHub Enterprise host in the container.
These container settings are distinct from standalone CLI flags and
interactive discovery's `GH_HOST`.

Variables such as `CODEX_SECURITY_SCAN_ID`, `CODEX_SECURITY_SCAN_DIR`,
`CODEX_SECURITY_PLUGIN_ROOT`, `CODEX_SECURITY_CONFIG_PATH`, and
`CODEX_SECURITY_TARGET_PATHS_FILE` are generated by an active scan. They are
internal runtime data, not supported user configuration.

Use `--provider openrouter` to send inference through OpenRouter. Set
`OPENROUTER_API_KEY` and specify a supported model with `--model`.

Use `--provider fireworks` to send inference through Fireworks AI. Set
`FIREWORKS_API_KEY` and specify a supported model with `--model`.

Use `--provider amazon-bedrock` to send inference through Amazon Bedrock. Set
`AWS_REGION` and authenticate with `AWS_BEARER_TOKEN_BEDROCK`, standard AWS
access keys, an AWS profile, web identity, container credentials, or the
default AWS credential chain. Specify a supported Bedrock model with `--model`;
OpenAI Bedrock models such as `openai.gpt-5.6-luna` support `--max-cost`.

Scan progress identifies the requested paths and reports actual ranking,
file-review, validation, and attack-path phases as they become available.
Interactive terminals show a full-screen view; CI, redirected output, and
`--headless` use plain timestamped progress lines.
Completion summarizes findings, severity, coverage, elapsed time, available
token and worker counts, estimated cost, the results directory, and the next
useful command.
Progress and summaries use stderr; structured scan results remain on stdout.

Add `--verbose` or set `CODEX_SECURITY_LOG_LEVEL=debug` to print
lifecycle, authentication, progress, and cost diagnostics to stderr.
`LOG_LEVEL=debug` is used only when `CODEX_SECURITY_LOG_LEVEL` is unset.
Structured JSON results remain on stdout. Review sensitive verbose logs before
sharing them. The normal activity feed hides credentials.

Each scan records its model, tokens, and estimated cost in its JSON result,
scan history, and bulk-scan receipt. Estimates use
[standard API token prices](https://developers.openai.com/api/docs/models/compare),
including cached input and cache writes; fees and surcharges are not included.

Use `--max-cost USD` to stop a scan, including its delegated workers, when its
running cost exceeds the limit. If a Deep Scan has already finished discovery,
it returns a sealed partial report with any completed findings and lists
unvalidated candidates as follow-up work. Requests already in progress can
finish above the limit; preparing the partial report makes no additional model
requests. Incomplete coverage retains its existing exit code.
For `bulk-scan`, the limit applies separately to each repository attempt.

Run `npx @openai/codex-security scan --help` or `npx @openai/codex-security bulk-scan --help`
for the complete CLI references.

Sign in with `gh auth login`, then run `npx @openai/codex-security bulk-scan` to discover
GitHub repositories pushed in the last 90 days. Archived
repositories and forks are excluded. Search the repository list, select the
repositories to scan, and confirm before scanning.
Private checkouts reuse your GitHub CLI sign-in without changing your global Git
configuration. The selected repositories are saved to
`<output-dir>/repositories.csv` for review or resumption.

Interactive discovery accepts the same `--workers`, `--mode`, `--max-attempts`,
`--model`, `--effort`, `--plugin-path`, `--python`, and `--codex` settings as
CSV-driven scans. It prompts for the output directory; `--output-dir` is only
valid when a repository CSV is supplied.

To use an existing repository list or run in CI, pass a CSV with required `id`,
`repository`, and `revision` columns. Revisions must be full commit hashes;
optional `scope`, `mode`, and `prompt` columns customize individual scans:

```csv
id,repository,revision,scope,mode,prompt
service,https://github.com/acme/service.git,0123456789abcdef0123456789abcdef01234567,src,standard,Focus on authentication and authorization.
```

Use `--scan-prompt-file PATH` to add instructions to a scan or every bulk scan.
Bulk scans append each repository's CSV `prompt` after the shared instructions.
Use `--post-scan-prompt-file PATH` to run a follow-up in the same authenticated
session after each scan, including incomplete or failed scans. Canceled scans
and scans stopped at their configured cost limit do not start another turn.

`--workers` sets the number of concurrent repository scans and defaults to
`4`. `--max-attempts` sets how many times each pending repository can run per
invocation and defaults to `1`. Results remain under `--output-dir`; rerun the
same command to resume.

### Publish findings to Cloud

Choose completed scans from your local history:

```bash
npx @openai/codex-security publish scan --to cloud --dry-run --json
```

The picker shows each scan's repository, finding count, age, and scan ID.
Press <kbd>Space</kbd> to select or deselect scans, then press
<kbd>Enter</kbd> to submit. At least one scan is required, and no scans are
selected automatically.

For scripts, repeat `--scan` with saved scan IDs or unique ID prefixes (at
least eight characters):

```bash
npx @openai/codex-security publish scan \
  --scan SCAN_ID_A --scan SCAN_ID_B \
  --to cloud --dry-run --json
```

Use `scans list --json` to find IDs for the current repository. `--scan latest`
selects its latest completed scan. The CLI resolves IDs through saved history,
processes each selected scan once, and checks that its sealed artifacts match
the selected ID. Picker selections use the order shown; repeated `--scan`
selections use argument order. The artifacts must still be available locally.

`--dry-run` validates the scans and prints their findings without uploading or
requiring a login. Remove `--dry-run` to upload. Live uploads require ChatGPT
credentials explicitly stored in a file. Set this in your Codex `config.toml`,
then sign in with ChatGPT again:

```toml
cli_auth_credentials_store = "file"
```

Automatic and keyring credential storage are not accepted for Cloud
publication, even when an `auth.json` file exists, because that file may be
stale and belong to a different account. The CLI sends one scan at a time,
with each scan's findings and metadata in a separate request.

To publish findings from a CSV instead of a completed scan, pass the CSV
created by `codex-security export --export-format csv`:

```bash
npx @openai/codex-security publish scan --to cloud \
  --csv /path/outside/repository/findings.csv
```

The repository includes a header-only
[findings CSV template](https://github.com/openai/codex-security/blob/main/examples/findings.csv)
that you can copy and fill in before publishing.

The CSV must have the export columns `occurrence_id`, `finding_id`, `title`,
`summary`, `severity`, `confidence`, `status`, `close_reason`, `note`,
`remediation`, `path`, `start_line`, and `end_line`. Deep-scan exports may also
include `candidate_id`. Use `--dry-run --json` to validate the CSV and inspect
the normalized findings locally without a login or network request.

`--csv` is only supported with `--to cloud` and cannot be combined with a scan
directory, `--scan-dir`, or `--scan`.

For artifacts outside local history, use repeated `--scan-dir PATH` instead.
A single positional directory is still accepted and can be combined with
`--scan-dir`. Do not combine directory inputs with `--scan`. Each directory
must contain one completed, sealed scan; bulk-run directories and
`results.jsonl` files are not accepted. Relative paths start at the current
directory, and `~/...` starts at your home directory. Each resolved directory
is processed once.

For multiple distinct scans, output contains:

- `results`: receipts or dry-run previews, each with its `scanId` and `scanDir`.
- `failed`: errors with `scanDir` and, for saved selections, `scanId`.
- `notAttempted`: saved scan IDs, or paths for directory inputs, that the command
  did not reach before cancellation.

For one distinct scan, the CLI returns the scan result directly,
without the batch fields above.

The CLI continues after a failed scan and exits with code `2` if any scan
fails. Ctrl-C or SIGTERM stops new requests and returns the results collected
so far. When cancellation stops work before every requested publication is
confirmed, the exit code is `130` for Ctrl-C and `143` for SIGTERM. If the
single response or final batch response has already confirmed the complete
publication, the command exits with code `0`. Cloud publication receipts
appear in command output; the CLI does not save them to scan history.

A successful receipt contains one opaque Cloud finding ID for each submitted
finding, in request order. These are not local finding IDs. The CLI verifies
the authenticated response status, count, and ID uniqueness, but cannot map
opaque server IDs back to individual local findings independently.

The CLI never retries an upload automatically. An upload with a missing or
invalid receipt may already have been accepted. Check whether Cloud accepted
that scan before retrying it. Do not resend scans with confirmed receipts.

### Custom validation

Use a prompt file to replace the final validation step in a standard or diff
scan. The ordinary source review still runs. The supplied text goes directly
into a separate validation turn and is not sent to discovery workers.
The SDK adapts the bundled discovery workflow without changing the plugin.
An incompatible plugin workflow stops the scan instead of using default validation.

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

Describe setup, allowed test targets, expected evidence, and cleanup in the
prompt. Refer to credentials through environment variables; do not put secrets
in the prompt or validation output. There are no separate setup or teardown
hooks. Deep scans reject this option. Empty candidate sets skip the custom turn.

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

Each candidate needs exactly one result. The disposition is `reportable`,
`suppressed`, `not_applicable`, or `deferred`. Optional assessment changes use
`{ "level": "medium", "rationale": "..." }` in `severity` or `impact`; use
`null` to retain the original assessment. Finding identity and source locations
do not change. Deferred candidates make coverage partial. Suppressed and
deferred candidates remain in the saved validation artifacts.

The scan directory contains `artifacts/custom-validation/candidates.json` and
`results.json`. Setup failure, incomplete output, or invalid output leaves the
scan incomplete. There is no automatic fallback to default validation. When
rerunning a saved custom-validation scan, supply
`scans rerun SCAN_ID --validation-prompt-file validation.md` again.

### Publish completed scans to Linear

Publish every finding from a completed standard, deep, or scoped scan to one
Linear team:

```bash
npx @openai/codex-security publish scan --scan SCAN_ID \
  --to linear \
  --linear-team TEAM_ID
```

Linear accepts one scan. Use a saved scan ID, a unique ID prefix, or `latest`.
For external artifacts, a positional directory or `--scan-dir PATH` is also
accepted.

Add `--linear-project PROJECT_ID` to place the issues in a Linear project.
The existing `--project` flag remains an alias. Without a project, issues are
created directly in the selected team.

To choose from all completed scans saved in your local scan history, omit the
scan selector. The selector highlights each repository and shows its finding
count, relative run time, and abbreviated scan ID:

```bash
npx @openai/codex-security publish scan \
  --to linear \
  --linear-team TEAM_ID
```

Destination flags take precedence over `CODEX_SECURITY_LINEAR_TEAM` and the
optional `CODEX_SECURITY_LINEAR_PROJECT`. Use `--dry-run` to preview the issue
titles without creating them, or `--json` to return structured publication
results.
Interactive publication shows a full-screen activity view with live Codex
output and issue-creation progress. Other terminals receive plain progress on
stderr, so `--json` output remains machine-readable.

By default, publishing starts Codex with your existing Codex configuration and
connected Linear app. Sign in to Codex and connect Linear before publishing in
this mode. No separate Linear API token is required, and publication does not
use the isolated Codex home created for security scans.

To publish directly through the Linear API without starting Codex, configure a
Linear personal API key:

```bash
export CODEX_SECURITY_LINEAR_API_KEY=YOUR_LINEAR_PERSONAL_API_KEY
npx @openai/codex-security publish scan /path/to/completed-scan \
  --to linear \
  --linear-team TEAM_ID
```

Direct API publication leaves issues unassigned by default. Pass
`--linear-assignee teammate@example.com` or `--linear-assignee USER_ID` to
assign the issues to a Linear user by email address or user ID.
`--linear-assignee` requires direct API publication.

You can also pass `--linear-api-key KEY`, which takes precedence over
`CODEX_SECURITY_LINEAR_API_KEY`. Prefer the environment variable to avoid
exposing your API key in shell history and process listings. API keys are not
added to successful publication results, scan history, or sealed scan artifacts.
Error messages are preserved as returned. `--dry-run` never contacts Linear in
either mode.

Use `publish check` to verify that the completed scan and its findings match
local history, and to see which findings already have recorded Linear issues:

```bash
npx @openai/codex-security publish check /path/to/completed-scan \
  --to linear --linear-team TEAM_ID --json
```

The check does not create issues, migrate scan history, or change sealed scan
artifacts. With a Linear API key, it also makes read-only authentication, team,
optional project, and assignee checks. Without a key, connected-app access is
reported as `not-checked`. Issue-creation permission is always `not-tested`;
successful read access does not prove write permission.

Each finding creates a separate new issue titled
`[Codex Security][HIGH] Finding title`. The issue includes the scan ID,
repository, scanned scope, source locations and code snippets, severity,
confidence, vulnerability classification, summary, and remediation guidance.
Verified immutable Git revisions include source links. Findings are published
concurrently in batches of up to 20. Successful issue identifiers are linked
to their findings in the local scan-history database, and structured results
are read back from that database rather than generated by Codex. The completed
scan must already exist in the local scan history. By default, running
publication again creates another set of issues for the same scan. Add
`--skip-existing` to skip findings with a recorded issue for the exact scan
occurrence, team, and optional project. Combine it with `--dry-run` to preview
only the remaining findings. Results distinguish newly `created` issues from
previously recorded `skipped` issues.

This option uses local publication history; it does not search, update, or
verify the continued existence of remote issues. Recover any retained handoff
from an interrupted or uncertain publication before retrying. Concurrent
publishers and remote creations that were never recorded can still create
duplicates.

Issue descriptions contain source code and vulnerability details. Select a
Linear destination authorized to receive that information. Publication receipts
are stored separately from the sealed scan artifacts.

Before recording a connected-app publication, Codex Security verifies the exact
mutation arguments and reconciles every recognized issue identifier and
non-empty URL in the connector result with its durable handoff. If those claims
conflict, or a completed mutation cannot be verified, publication exits with an
indeterminate recovery error. The private handoff, connector-event evidence,
and partial receipts remain in local state; independently verified sibling
issues may already be recorded in scan history.

Do not immediately rerun an indeterminate publication. Inspect the retained
evidence and the selected Linear destination, reconcile every issue that may
already have been created, and retry only after confirming that no unrecorded
issue would be duplicated. Publication does not perform a fresh remote readback
or recover unrecorded remote creations. The opt-in `--skip-existing` behavior
only skips issues already recorded in local history.

You can also publish a scan from TypeScript:

```ts
import { publishScan } from "@openai/codex-security";

const publication = await publishScan("/path/to/completed-scan", {
  destination: "linear",
  teamId: "TEAM_ID",
  onProgress: (progress) => {
    if (progress.type === "handoff_recorded") {
      console.error("Saved mutation result", progress.recorded);
    } else if (progress.type === "issue_completed") {
      console.error(
        `Processed ${progress.completed} of ${progress.total} findings.`,
      );
    }
  },
});

console.log(publication.scanId);
console.log(publication.created.length);
```

Add `projectId: "PROJECT_ID"` to the options to publish into a specific Linear
project instead of directly to the team. Pass `skipExisting: true` to skip
recorded successes, or import `checkScanPublication` and call it with the same
destination options for a read-only preflight.

Pass `linearApiKey` to publish directly through the Linear API. Omit
`assigneeId` to leave issues unassigned, or supply a Linear user ID or email
address to select an assignee:

```ts
const directPublication = await publishScan("/path/to/completed-scan", {
  destination: "linear",
  teamId: "TEAM_ID",
  linearApiKey: process.env["CODEX_SECURITY_LINEAR_API_KEY"],
  assigneeId: "teammate@example.com",
});
```

### Scan history and reruns

`scans` or `scans list` lists scans for the current repository. Pass a repository
path to inspect another checkout, or `--scan-root DIR` to list scans whose
artifacts are under a particular root. `scans show` opens the latest completed
scan for the current repository. Pass `SCAN_ID` to inspect another scan. Scan
details include the configuration, results, coverage, and artifact locations. Add
`--show-linked-findings` to include finding links from previous scans.

`scans logs` shows session events from the latest scan, including an active scan.
Pass `SCAN_ID` to select another scan. During a scan, press `d` for live details.
Filter with `a` for all sources, `m` for the main scan, or `1`–`9` for a worker.
Logs and live details can contain source code and credentials.

Every scan history command accepts a full scan ID or a unique prefix of at
least eight characters.

Scan history uses `$CODEX_SECURITY_STATE_DIR/workbench.sqlite3` when
`CODEX_SECURITY_STATE_DIR` is set. Otherwise, it uses
`$CODEX_HOME/state/plugins/codex-security/workbench.sqlite3`; `CODEX_HOME`
defaults to `~/.codex`. Scan credentials are never stored in the scan
configuration. Recorded failure summaries and bulk-scan receipts omit messages
that contain recognizable credentials.

The scan sandbox permits writes to the selected state directory so SQLite can
maintain its database and journal files. If the host itself cannot write to the
default directory, select a writable directory outside the scanned repository:

```bash
export CODEX_SECURITY_STATE_DIR=/path/to/writable/codex-security-state
```

`findings` or `findings list` lists open findings for the current repository.
Use `findings false-positive OCCURRENCE_ID --reason TEXT` to mark a finding as a
false positive and explain why. Later scans dismiss a matching finding only when
the same reason still applies.

`scans rerun` repeats the latest completed scan against the current checkout.
Pass `SCAN_ID` to rerun another scan.

`scans match BEFORE_SCAN_ID AFTER_SCAN_ID` links findings with the same root
cause; `scans match --all` matches all completed scans of the current repository,
including other worktrees and clones. Saved matches appear in `scans show` and
are reused unless `--force` is passed. Scans without sealed artifacts are skipped.

`scans compare` compares the two latest completed scans. Pass one scan ID to
compare it with the latest completed scan, or two IDs to select both scans. It
matches findings by root cause, reuses saved matches, and reports findings as
new, persisting, reopened, resolved, or unknown. Missing findings are not
treated as resolved when the later scan is incomplete or does not cover their
original scope.

The CLI uses [Incur](https://github.com/wevm/incur) for agent-friendly discovery
and structured output. Inspect the command manifest with `--llms`, inspect a
command schema with `scan --schema --format json`, register the CLI as an MCP
server with `mcp add`, sync agent skills with `skills add`, or generate shell
completions with `completions bash|zsh|fish`. Scan results support
`--format toon|json|yaml|jsonl` and `--full-output`.
Use `info --json` for SDK and bundled-plugin metadata. MCP exposes only this
read-only metadata command; scans, bulk repository scans,
authentication, imports, exports, validation, and patching remain CLI-only because the
MCP transport cannot cancel active scans.

For CI, save machine-readable output outside the checked-out repository and
apply a severity policy. Incomplete coverage and runtime errors still exit
nonzero:

```bash
SCAN_ROOT="$(mktemp -d)"
npx @openai/codex-security scan . \
  --diff origin/main \
  --output-dir "$SCAN_ROOT/results" \
  --json \
  --fail-on-severity high > "$SCAN_ROOT/findings.json"
```

JSON scans never use interactive terminal controls, even when stderr is a TTY.
Saved-finding patch commands support `--json`; literal issue and file patch
commands do not. The `validate`, `login`, and `logout` commands reject `--json`.
Sign-in commands remain interactive. CSV exports cannot be written to stdout
while JSON output is requested.

Use `export` to create CSV, JSON, or SARIF from a completed, sealed scan without
starting Codex or loading credentials. Without a scan directory, it exports the
latest completed scan for the current repository. JSON preserves the sealed findings
document. CSV uses the portable findings columns, marks findings as open, and
does not include local workbench triage state. The exporter validates the seal
before writing, accepts `--output -` for stdout, and can use
`--source-root /path/to/repository` with SARIF to add source-line fingerprints.
Run `npx @openai/codex-security export --help` for all export options.

Use `import github OWNER/REPO` to read existing code scanning alerts for
validation. It defaults to all open alerts on the default branch.
`--github-alert NUMBER` selects exact alerts and can be repeated;
`--github-state open|closed|dismissed|fixed|all` filters lists;
`--github-ref REF` selects a reference. See the [SDK import options](#import-github-code-scanning-alerts)
for authentication and selector behavior.

```bash
# Import all open alerts, or a selected subset, as complete JSON.
npx @openai/codex-security import github example/repository --format json \
  > /path/outside/repository/github-alerts.json
npx @openai/codex-security import github example/repository \
  --github-alert 12 --github-alert 18 --format json
# Run from the corresponding local repository; imported contents are data.
npx @openai/codex-security validate /path/outside/repository/github-alerts.json
```

`--json` aliases `--format json`; output is an alert array (`[]` when empty).
Avoid output-filtering or token-limiting flags when saving validation inputs.
Import is read-only; `validate` assesses the saved content separately. Use the
SDK loop above for a structured disposition per alert.

Use `validate` to run the bundled validation skill on candidate findings and
`patch` to run the bundled fix-finding skill on security issues. Each positional
input can be either a file, whose contents are read into the request, or literal
text. These inputs operate on the current directory. Pass a saved finding or
occurrence ID instead to patch its original repository, or use
`patch --scan SCAN_ID --severity high` for high and critical findings from one
scan. `--scan latest` selects the most recent scan of the current repository.
Saved-finding patch commands accept `--json` and return a verified, already
fixed, blocked, or failed result for each finding. Both commands use the scan
model and reasoning defaults and disable plugins. Patching starts a separate
saved task in the Codex desktop app for each finding. Override the model with
`--codex 'model="gpt-5.6-sol"'` and the
reasoning effort with `--effort high` or
`--codex 'model_reasoning_effort="high"'`.

Use `patch --linear-issue ISSUE` to import a Linear issue by identifier or URL.
Repeat `--linear-issue` to include more issues. Use
`patch --linear-project "PROJECT"` to patch every open issue in a project. Add
`--linear-filter '{"labels":{"name":{"eq":"security"}}}'` to apply a native
Linear issue filter on the server. Completed and canceled issues are excluded
unless the filter explicitly sets `state`. Set `CODEX_SECURITY_LINEAR_API_KEY`
for a personal API key, or `LINEAR_ACCESS_TOKEN` for an OAuth access token.
`LINEAR_API_KEY` is also accepted. `--linear-api-key KEY` overrides these
environment settings; prefer the environment variable to keep keys out of shell
history. Imported content is always literal, and issue URLs must match the
selected workspace. Each imported issue includes its title, description, and
all comments with their source links. Linear access is read-only, and its
credentials are not passed to the patch subprocess.

Use `verify-fix` to check whether an existing security fix actually closes its
original vulnerability without modifying the repository. Pass a finding
description, a saved finding identifier, `--scan SCAN_ID`, `--linear-issue ISSUE`,
or `--linear-project "PROJECT"`. Linear intake uses the same credentials and
`--linear-filter` options as `patch`; explicitly filter for completed issues when
verifying a finished backlog. Verification runs the bundled `verify-fix` skill
in a read-only Codex sandbox and reports `fixed`, `still_vulnerable`, or
`inconclusive` with supporting evidence for every finding. Use `--json` for
structured output. Exit code `0` means every finding is fixed, `1` means at
least one finding remains vulnerable, and `2` means a result is inconclusive or
verification could not complete.

Interactive verification shows the same live agent-activity dashboard used by
scans and Linear publication. Reasoning, repository commands, and progress are
written to stderr; redirected output and CI receive plain progress lines, and
JSON results on stdout remain machine-readable.

Exit codes are `0` for a completed report-only scan or a passing policy, `1`
for a completed policy violation, `2` for invalid input, incomplete coverage, or
a runtime/export error, `130` for interruption, and `143` for termination.

Use `--dry-run` or `await security.preflight(...)` to validate the repository,
target, mode, output location, and Codex overrides without initializing the
runtime or loading credentials. Dry runs do not inspect the plugin or probe its
Python interpreter. The preflight result includes the selected authentication
method and, for an environment API key, its variable name. Authentication and
model access remain unverified until a real scan starts.

Scan progress identifies the selected credential source before Codex starts.
Terminals and noninteractive CI logs also show how to retry with
`--auth chatgpt` when an environment API key overrides the stored sign-in.
Progress remains on stderr so JSON output stays machine readable. Network
failures and rate limits remain retryable; definitive authentication and model
authorization failures stop immediately.

## Containerized bulk scans

Create `repositories.csv` with one full, immutable Git commit per repository:

```csv
id,repository,revision
payments,https://github.com/example/payments.git,0123456789abcdef0123456789abcdef01234567
```

Once the approved image has been published, prepare private results and
authentication directories, sign in, and run the Docker Compose configuration
from the root of the Codex Security repository:

```bash
mkdir -p results state
chmod 700 results state
export CODEX_SECURITY_USER="$(id -u):$(id -g)"
export CODEX_SECURITY_IMAGE=ghcr.io/openai/codex-security:latest
docker compose pull codex-security
docker compose run --rm codex-security login --device-auth
docker compose run --rm codex-security
```

Reports and resumable scan results are written to `results/`; the reusable
device login remains in `state/`. For unattended scans, set `OPENAI_API_KEY`
or `CODEX_API_KEY` instead. Set `GH_TOKEN` or `GITHUB_TOKEN` for private
GitHub repositories.

The container accepts the repository CSV before or after bulk-scan options.
Interactive repository discovery remains disabled, including when global CLI
options appear before `bulk-scan`.

On Ubuntu hosts that restrict unprivileged user namespaces, an administrator
can install the optional, narrowly scoped AppArmor profile once:

```bash
sudo install -m 0644 docker/codex-security.apparmor /etc/apparmor.d/codex-security-container
sudo apparmor_parser -r -W /etc/apparmor.d/codex-security-container
docker compose -f compose.yaml -f compose.apparmor.yaml run --rm codex-security
```

The override preserves the nonroot user, dropped capabilities,
no-new-privileges, and hardened seccomp policy. Other Docker hosts do not need
the profile or override.

## Local security model

Codex Security runs with your local operating-system permissions. Scan only
repositories you trust and either own or are authorized to assess. Your
repository, Git installation, configured tools, and other scans under the
same account are not separate security principals.

Every scan uses the `codex_security_scan` filesystem profile and
automatically reviewed execution approvals. Its baseline profile allows reads
of the local filesystem and writes to workspace roots and the selected scan
state directory. Approval requests are reviewed without an interactive prompt;
approved requests can grant additional permissions for a specific operation.
Use `--codex 'approval_policy="never"'` or a selected profile with that policy
to deny all requests instead. Other `approval_policy`, `approvals_reviewer`,
`sandbox_mode`, or permission overrides cannot replace the reviewer or baseline
filesystem profile. Saved scans retain their effective approval policy; older
saved scans remain deny-all when rerun. Independently enforced host and network
restrictions still apply.

Scan and workbench subprocesses can inherit your environment, including
unrelated API tokens and cloud credentials. Start a scan with only the
credentials it needs.

The scanner must stay within the target and output paths you authorize and
must not disclose private data beyond the operation you requested. Its results
must accurately report the scan mode, reviewed files, and exclusions. Consult
the security policy for the full threat model and private reporting process.

## Documentation and security

- [CLI quickstart](https://developers.openai.com/codex/security/cli)
- [TypeScript SDK guide](https://developers.openai.com/codex/security/sdk)
- [GitHub issues](https://github.com/openai/codex-security/issues) for bugs and
  feature requests
- [Security policy](https://github.com/openai/codex-security/blob/main/SECURITY.md)
  for private vulnerability reporting and safe operation
