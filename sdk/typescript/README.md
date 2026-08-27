# `@openai/codex-security`

Run Codex Security scans from TypeScript or the command line. This ESM-only
package includes TypeScript declarations and the Codex runtime.

Before version `1.0.0`, minor releases may change the public API.

## Install

```bash
npm install @openai/codex-security
npx @openai/codex-security --version
```

Use Node.js 22.13.0+ (22.x), 24.x, or 26.x on macOS, Linux, or Windows.
Scans, exports, scan history, and saved findings also need Python 3.10+
(plus `tomli` on Python 3.10).

## Run a scan from TypeScript

Sign in with `npx @openai/codex-security login` or set `OPENAI_API_KEY` or
`CODEX_API_KEY`, then scan a repository you own or have permission to assess:

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

`result.findings` contains this scan's findings; `repositoryFindings` also
includes earlier open findings when available. Matching earlier findings can
make one extra model call, even with a cost limit.

Keep results outside the repository and restrict access: reports can contain
source code, vulnerability details, and reproduction steps.

### Validate an existing finding

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

Pass literal text or a JSON-serializable object as `finding`, not a file path.
Validation uses the client's settings and credentials without changing
repository files or adding a scan to history.

Results include `disposition` (`reportable`, `suppressed`, `not_applicable`,
or `deferred`), a Markdown `report`, `threadId`, and evidence `outputDir`.
`reportable` may rely on static analysis; `deferred` means insufficient evidence.
Failed, incomplete, or malformed responses reject the promise.

`outputDir` must be empty and outside the Git worktree; it defaults to
`validations/` under the state directory. Pass `auth` to select credentials
or `signal` to cancel.

### Import GitHub code scanning alerts

Import alerts, including third-party SARIF uploads, and validate them against
the matching local checkout:

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

Without `alertNumbers`, `state` filters alerts and defaults to `"open"`.
It also accepts `"closed"`, `"dismissed"`, `"fixed"`, and `"all"`. Exact alert
numbers ignore state and reject a nondefault `state`. Use `ref` for another
branch or pull-request reference.

Supply `githubToken` or use your `gh auth token` credentials, including GitHub
CLI token environment variables. `githubHost` defaults to `GH_HOST` or
`github.com`. The token needs read access to code scanning alerts; access
failures reject the import. Pass `signal` to cancel.

### SDK configuration and scan options

Constructor options:

| Option           | Description                                                             |
| ---------------- | ----------------------------------------------------------------------- |
| `pluginPath`     | Plugin directory or ZIP; defaults to the bundled plugin.                |
| `pythonPath`     | Python interpreter; overrides `PYTHON`.                                 |
| `codexOverrides` | Supported settings to deep-merge into the isolated Codex configuration. |

Options for `security.run(repository, options)` and
`security.preflight(repository, options)`:

| Option                  | Description                                                                    |
| ----------------------- | ------------------------------------------------------------------------------ |
| `auth`                  | Credential source: `"auto"`, `"chatgpt"`, or `"api-key"`.                      |
| `safetyIdentifier`      | Stable hashed end-user ID for model requests; requires API-key authentication. |
| `target`                | Repository, repository-relative paths, committed diff, or working-tree diff.   |
| `mode`                  | `"standard"` or `"deep"`; deep mode supports repositories and paths.           |
| `knowledgeBasePaths`    | Architecture documents, security policies, threat models, or directories.      |
| `outputDir`             | Artifact directory outside the enclosing Git worktree.                         |
| `archiveExisting`       | Archive existing results in `outputDir` before scanning.                       |
| `maxCostUsd`            | Stop when estimated model cost exceeds this positive USD amount.               |
| `maxTimeHours`          | Deep-scan discovery limit in hours: greater than zero, up to 96.               |
| `failureSeverity`       | Finding-severity policy to record in the saved scan recipe.                    |
| `parentScanId`          | Parent scan ID for a rerun.                                                    |
| `expectedPluginVersion` | Required original plugin version when replaying a scan.                        |
| `signal`                | `AbortSignal` to cancel a scan.                                                |

Follow scans with `onWorkerStatus` and `onReconnect`. `onSessionEvent` receives
saved events with thread IDs and worker numbers; `ScanOptions` lists all callbacks.

`preflight` and CLI `--dry-run` check local inputs without starting Codex or
using the network. They don't authenticate, verify model access, resolve Python,
inspect the plugin, or run scan-lifecycle callbacks. Dry runs print effective settings.

## Authentication

Sign in with ChatGPT:

```bash
npx @openai/codex-security login
npx @openai/codex-security scan .
```

Use device authentication on remote or headless machines:

```bash
npx @openai/codex-security login --device-auth
```

For CI, set `OPENAI_API_KEY` or `CODEX_API_KEY`. To save a key, pass it on stdin:

```bash
printenv OPENAI_API_KEY | npx @openai/codex-security login --with-api-key
```

Environment API keys apply to the current scan; only `login --with-api-key`
saves them. Pass Codex access tokens on stdin to `login --with-access-token`.
Access-token environment variables are not scan API keys.

For other inference providers:

```bash
export OPENROUTER_API_KEY="<your-openrouter-api-key>"
npx @openai/codex-security scan . --provider openrouter --model anthropic/claude-sonnet-4.5

export FIREWORKS_API_KEY="<your-fireworks-api-key>"
npx @openai/codex-security scan . --provider fireworks --model accounts/fireworks/models/qwen3-235b-a22b

export AWS_BEARER_TOKEN_BEDROCK="<your-bedrock-api-key>"
export AWS_REGION="us-east-2"
npx @openai/codex-security scan . --provider amazon-bedrock --model openai.gpt-5.6-luna
```

Bedrock also accepts AWS access keys, profiles, web identity, container
credentials, and the default AWS credential chain. Set `AWS_REGION` and choose
a Bedrock model with `--model`; OpenAI models such as `openai.gpt-5.6-luna`
support `--max-cost`.

On Windows, set the API key in PowerShell:

```powershell
$env:OPENAI_API_KEY = "<your-api-key>"
npx @openai/codex-security scan C:\code\repository
```

Login, logout, and scans share a private credential home:
`$CODEX_SECURITY_STATE_DIR/codex-home`, or
`$CODEX_HOME/state/plugins/codex-security/codex-home`. Codex uses the configured
file or keyring storage and managed-device policies. If this home has no
credentials, it imports an existing file-based Codex sign-in. Logout disables
imports until you log in again.

Finish operations using older versions before upgrading. Runtime preparation
holds the credential-home lock through pauses; exit or crash releases it.
Compatibility heartbeats protect active locks from older heartbeat-only
clients, but those clients can replace a paused client's lock.

Keep `.codex-security-scan.sqlite3` between operations; never remove it during
an operation. PID reuse can make old PID-only locks appear active and block
recovery. Stop all operations using this home before removing an old
`.codex-security-scan.lock` directory manually.

If ChatGPT credentials cannot be refreshed, run `login status`. Retry if the
sign-in recently changed; otherwise run `logout`, then `login`.

Interactive scans ask whether to use ChatGPT or an environment API key when
both are available. The choice applies to that scan. Noninteractive scans,
including CI, JSON output, and dry runs, prefer the API key. Choose with `--auth`:

```bash
npx @openai/codex-security scan . --auth chatgpt
npx @openai/codex-security scan . --auth api-key
```

`--auth chatgpt` ignores environment API keys. `--auth api-key` requires
`OPENAI_API_KEY` or `CODEX_API_KEY`. The default is `--auth auto`; unset both
variables to default to ChatGPT. The SDK uses the same `auth` option on `run`
and `preflight`. Codex may still need ChatGPT credentials to load
workspace-managed policies when using an API key.

Some cybersecurity requests and protected findings require Trusted Access for
Cyber approval. Apply or check your access at
[chatgpt.com/cyber](https://chatgpt.com/cyber).

## CLI

```bash
npx @openai/codex-security scan .
npx @openai/codex-security scan /path/to/repository --path src --path tests
npx @openai/codex-security scan /path/to/repository --diff origin/main --json
npx @openai/codex-security scan /path/to/repository --output-dir /path/outside/repository/results
npx @openai/codex-security scan /path/to/repository --dry-run
```

Use `scan --help` for options, `--version` for the installed version, and
`info --json` for package, plugin, runtime, and model details. `--dry-run`
runs local preflight checks.

### Scan options and output

`--path` scopes a scan to one or more paths, `--diff` scans committed changes,
and `--working-tree` scans staged and unstaged changes. Deep scans support
repository and path targets.

Working-tree snapshots include files from untracked nested Git repositories.
Initialized submodules must be clean and checked out at the commit recorded by
the parent repository.

Repeat `--knowledge-base PATH` for Markdown, text, PDF, or Word (`.docx`) files.
Directories are searched recursively. Bulk scans share these documents with
every repository.

Use an empty output directory outside the scanned directory and enclosing Git
worktree. On macOS/Linux, existing directories must be private to you
(`chmod 700`). `--archive-existing` moves previous results to
`<output-dir>.previous-<timestamp>-<id>`; add `--dry-run` to preview the move.
SARIF output, when produced, is at `<scan-dir>/exports/results.sarif`.

Scans are report-only by default. Set `--fail-on-severity high` to exit with
`1` if a completed scan finds high or critical issues. Incomplete scans exit
with `2`, writing available results to stdout and a coverage warning to stderr.

### Attribute scans to end users

When scanning on behalf of users, pass each user's stable hashed ID:

```ts
await security.run("/path/to/repository", {
  auth: "api-key",
  safetyIdentifier: hashedUserId,
});
```

```bash
codex-security scan /path/to/repository --auth api-key --safety-identifier hashed-user-id
```

Use a nonblank ID of 1 to 64 characters without NUL or personal data such as
email addresses. It applies to the scan, workers, retries, and follow-up work
without changing shared configuration. Supply it again for reruns.

The runtime needs native `--safety-identifier` support, and the plugin must
forward it to workers. The bundled runtime doesn't support it yet; choose a
compatible build with `CODEX_CLI_PATH`. The SDK checks the ID's format, not
runtime or plugin compatibility. Older versions may omit the ID.

### Scan project components

`scan --path` runs one scan across selected paths. To scan each local project
component separately in standard mode, use `scan-components`:

```bash
npx @openai/codex-security scan-components /path/to/project \
  --component apps/api --component apps/web --component packages/shared \
  --workers 4 --output-dir /path/outside/project/results
```

Use `--auto` instead of `--component` for a proposed split. Save a plan to
review or edit, then run it with a new output directory:

```bash
npx @openai/codex-security scan-components /path/to/project \
  --auto --plan-only --output-dir /path/outside/project/plan
npx @openai/codex-security scan-components /path/to/project \
  --components-file /path/outside/project/plan/components.json \
  --output-dir /path/outside/project/results
```

Components use repository-relative paths:

```json
{
  "components": [
    { "name": "API", "paths": ["apps/api", "packages/auth"] },
    { "name": "Web", "paths": ["apps/web"] }
  ]
}
```

Automatic planning respects Git ignore rules and groups omitted files under
`Other files`. Each proposed path must contain an inventoried file. Planning
leaves source files unchanged.

Each component saves artifacts under `component-N/`. Combined `findings.json`
merges high-confidence root-cause matches, keeping the highest severity and
original IDs. Uncertain matches stay separate. `summary.json` records coverage
and matching status; `report.md` links to component reports. Export and publish
from the individual scan folders, not the combined summary.

Use an empty output directory outside the project. Failed components don't
stop others, but failures, incomplete coverage, or failed matching exit with
`2`. Retry failed or incomplete components with
`--components-file retry-components.json` and a new output directory.

`--max-cost` applies per component, excluding planning and matching.
`--model` and `--effort` also apply to matching; `--auth` applies throughout.
Use `--knowledge-base`, `--scan-prompt-file`, and `--post-scan-prompt-file` as for
bulk scans.

From TypeScript, use `runComponentScans({ repository, outputDir, components })`.
Use `auto: true` for planning, `planOnly: true` to save the plan without scans,
and `scanOptions.auth` to select credentials.

### Configure deep scans

For `scan --mode deep`, `--workers` sets discovery concurrency and `--subagents`
sets subagents per worker. `--stop-after-no-new` stops after that many runs
without new issues. `--max-discovery-runs` and `--max-time-hours` cap discovery
runs and duration. SDK equivalents:

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

Set defaults in `$CODEX_HOME/codex-security/config.toml`:

```toml
[deep_scan]
workers = 4
subagents = 3
stop_after_no_new = 4
stop_after_consecutive_errors = 3
max_discovery_runs = 40
max_time_hours = 96
```

CLI and SDK options override these defaults. Set `stop_after_consecutive_errors`
in the file; `--codex` cannot configure this section. Worker and run counts must
be positive integers; `subagents` can be zero. Legacy `workers = "auto"` means
four workers. Unknown keys are rejected.

`max_time_hours` accepts positive values up to 96, including fractional hours.
At the deadline, discovery stops; the scan combines and returns completed findings.

`scan --workers` controls discovery workers within one deep scan;
`bulk-scan --workers` controls how many repositories are scanned concurrently.

### Runtime configuration and worker limits

Scans use these isolated Codex defaults instead of your user or repository
configuration:

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

The thread limit of `9` includes the parent and up to eight delegated workers.
It is separate from deep-scan and bulk-scan worker counts.

Quote string values as TOML, for example
`--codex 'model_reasoning_effort="high"'`. Do not pass both `--model` and
`--codex 'model="..."'`, or both `--effort` and
`--codex 'model_reasoning_effort="..."'`: conflicting or repeated keys are
rejected.

Choose plugins with `--plugin-path`. Overrides of `plugins`, `marketplaces`,
or `features.plugins` are rejected, including in profiles. Multi-agent v2 must
stay enabled: `agents.max_threads` and
`features.multi_agent_v2.enabled=false` are rejected.

`validate` and `patch` accept `--effort` and the `model` and
`model_reasoning_effort` keys in `--codex`, but no other runtime overrides.

See [Local security model](#local-security-model) for approval and filesystem
restrictions.

### Environment variables

| Variable                                                                    | Effect                                                                               |
| --------------------------------------------------------------------------- | ------------------------------------------------------------------------------------ |
| `OPENAI_API_KEY`, `CODEX_API_KEY`                                           | Scan credentials; `OPENAI_API_KEY` wins if both are set.                             |
| `CODEX_SECURITY_LINEAR_TEAM`, `CODEX_SECURITY_LINEAR_PROJECT`               | Default team and project for completed-scan publication.                             |
| `CODEX_SECURITY_LINEAR_API_KEY`                                             | Personal API key for Linear patching and direct publication.                         |
| `CODEX_SECURITY_LOG_LEVEL`                                                  | CLI-only; `debug` enables verbose diagnostics.                                       |
| `LOG_LEVEL`                                                                 | CLI-only fallback when `CODEX_SECURITY_LOG_LEVEL` is unset.                          |
| `CODEX_SECURITY_STATE_DIR`                                                  | Private scan-history, workbench, and default artifact directory.                     |
| `CODEX_HOME`                                                                | Ambient Codex home for file-based sign-in and default state; defaults to `~/.codex`. |
| `CODEX_CLI_PATH`                                                            | Codex executable for authentication, plugin setup, scans, and workers.               |
| `PYTHON`                                                                    | Python interpreter when `--python` or SDK `pythonPath` is unset.                     |
| `GH_HOST`                                                                   | GitHub Enterprise host for interactive `bulk-scan` discovery.                        |
| `CODEX_SECURITY_NO_UPDATE_NOTICE`, `NO_UPDATE_NOTIFIER`                     | Either variable disables interactive update notices.                                 |
| `CODEX_SECURITY_NPM_REGISTRY`, `npm_config_registry`, `NPM_CONFIG_REGISTRY` | Update-check registry, in precedence order.                                          |
| `CI`                                                                        | Disables interactive update notices.                                                 |
| `NO_COLOR`, `TERM`                                                          | Disables colored scan history when `NO_COLOR` is defined or `TERM=dumb`.             |

Custom Codex executables need thread source attribution for `exec` and
`app-server` (Codex 0.149.1+). On Windows, use a native `.exe` or `.com`;
command shims such as `codex.cmd` fall back to the bundled executable.

Python lookup order: `--python` (on `scan`, `bulk-scan`, or `export`) or SDK
`pythonPath`, then `PYTHON`, the managed Codex runtime, and `python3` or `python`
on `PATH` (`py` also works on Windows). `CODEX_SECURITY_STATE_DIR` overrides
`CODEX_HOME` for state storage. Keep state and results outside the repository.

### Progress and cost

Interactive scans show full-screen progress; CI, redirected output, and
`--headless` use plain status lines. Results go to stdout, progress and
diagnostics to stderr. Add `--verbose` for diagnostics. Check logs for
sensitive information before sharing them.

JSON results, scan history, and bulk-scan receipts record the model, tokens,
and estimated cost. Estimates use
[standard API token prices](https://developers.openai.com/api/docs/models/compare),
including cached input and cache writes, but exclude fees and surcharges.

`--max-cost USD` stops the scan and its workers when estimated cost exceeds
the limit, though in-flight requests can finish above it. If deep-scan
discovery has finished, the scan returns a sealed partial report without more
model calls and lists unvalidated candidates as follow-up work. Bulk scans
apply the limit per repository attempt.

### Bulk scans

Run `gh auth login`, then `npx @openai/codex-security bulk-scan` to select
GitHub repositories pushed in the last 90 days. Forks and archived repositories
are excluded; private checkouts use your GitHub CLI sign-in. The command asks
for an output directory and saves your selection there as `repositories.csv`.
`--output-dir` requires CSV input.

For CI or an existing repository list, pass a CSV with `id`, `repository`, and
`revision` (full commit hash). Optional `scope`, `mode`, and `prompt` columns
customize each scan:

```csv
id,repository,revision,scope,mode,prompt
service,https://github.com/acme/service.git,0123456789abcdef0123456789abcdef01234567,src,standard,Focus on authentication and authorization.
```

```bash
npx @openai/codex-security bulk-scan repositories.csv \
  --output-dir /path/outside/repositories/security-scans --workers 4
```

`--scan-prompt-file PATH` adds instructions to a scan or all bulk scans. Each
repository's CSV `prompt` follows the shared instructions.
`--post-scan-prompt-file PATH` runs a follow-up in the same authenticated session,
even after a failed or incomplete scan, but not after cancellation or a
cost-limit stop.

`--workers` defaults to `4`. `--max-attempts` defaults to `1` attempt per pending
repository per invocation. Rerun the command to resume; `bulk-scan --help`
lists all options.

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

Put setup, allowed targets, required evidence, and cleanup in the prompt.
There are no separate setup or teardown hooks. Use environment variables for
credentials; keep secrets out of prompts and validation output. Deep scans
reject this option; scans without candidates skip it.

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

The scan saves candidates and results, including suppressed and deferred
cases, under `artifacts/custom-validation/`. Coverage is incomplete if setup
fails, output is incomplete or invalid, or any candidate is deferred. An
incompatible plugin stops the scan; validation never falls back to the default.
Repeat `--validation-prompt-file` on reruns.

### Publish findings to Cloud

Choose completed scans from local history:

```bash
npx @openai/codex-security publish scan --to cloud --dry-run --json
```

Press Space to select scans, then Enter to submit. Nothing is preselected.

For scripts, repeat `--scan` with saved IDs or unique prefixes of at least
eight characters:

```bash
npx @openai/codex-security publish scan \
  --scan SCAN_ID_A --scan SCAN_ID_B \
  --to cloud --dry-run --json
```

Find IDs with `scans list --json`, or use `--scan latest` for the current
repository's latest completed scan. You still need the local sealed artifacts.

`--dry-run` checks inputs and prints findings without logging in or uploading.
Uploads need ChatGPT credentials saved to a file. Set this in Codex
`config.toml`, then sign in with ChatGPT again:

```toml
cli_auth_credentials_store = "file"
```

Cloud publication rejects automatic and keyring storage, even if an
`auth.json` file exists: the file may be stale or belong to another account.

For CSV input, use an export from `codex-security export --export-format csv`:

```bash
npx @openai/codex-security publish scan --to cloud \
  --csv /path/outside/repository/findings.csv
```

The [findings CSV template](https://github.com/openai/codex-security/blob/main/examples/findings.csv)
has the required columns; deep-scan exports may add `candidate_id`. `--csv`
only supports Cloud and cannot be combined with scan IDs or directories.

For artifacts outside local history, pass a directory or repeat `--scan-dir PATH`.
Each directory must contain one completed, sealed scan. Bulk-run directories
and `results.jsonl` files aren't accepted. Don't mix directories with `--scan`.

Multiple scans return:

- `results`: receipts or dry-run previews, each with its `scanId` and `scanDir`.
- `failed`: errors with `scanDir` and, for saved selections, `scanId`.
- `notAttempted`: saved scan IDs, or paths for directory inputs, that the command
  did not reach before cancellation.

One scan returns its result directly. Uploads run sequentially. A failed upload
doesn't stop the rest, but the command exits with `2` if any failed. Cancellation
stops new requests and returns results so far with `130` (Ctrl-C) or `143`
(SIGTERM), unless all publications were already confirmed.

Save the output: Cloud receipts aren't stored in scan history. They contain
Cloud finding IDs in request order, not local IDs. Uploads aren't retried
automatically. Cloud may have accepted an upload even if its receipt is missing
or invalid. Check Cloud before retrying; never resend a scan with a confirmed
receipt.

### Publish completed scans to Linear

Linear publication accepts one completed scan:

```bash
npx @openai/codex-security publish scan --scan SCAN_ID \
  --to linear \
  --linear-team TEAM_ID
```

Choose a scan by ID, unique prefix, `latest`, or directory (positional or
`--scan-dir PATH`). Omit the selector for an interactive picker. Live publication
and `--skip-existing` require the scan in local history; a directory-based
`--dry-run` alone does not.

Add `--linear-project PROJECT_ID` (`--project` is an alias) to place issues in
a project. Destination flags override `CODEX_SECURITY_LINEAR_TEAM` and
`CODEX_SECURITY_LINEAR_PROJECT`. `--dry-run` previews issue titles without
contacting Linear; `--json` returns structured results.

Sign in to Codex and connect Linear to publish with your existing Codex
configuration; publication doesn't use the isolated scan home. To use the
Linear API directly, set a personal API key:

```bash
export CODEX_SECURITY_LINEAR_API_KEY=YOUR_LINEAR_PERSONAL_API_KEY
npx @openai/codex-security publish scan /path/to/completed-scan \
  --to linear \
  --linear-team TEAM_ID
```

Direct API publication leaves issues unassigned unless `--linear-assignee`
specifies a user ID or email. `--linear-api-key KEY` overrides the environment
variable, but exposes the key in shell history and process listings. Keys are
omitted from saved results and artifacts; error messages are returned unchanged.

Check scan integrity and recorded publications before publishing:

```bash
npx @openai/codex-security publish check /path/to/completed-scan \
  --to linear --linear-team TEAM_ID --json
```

`publish check` is read-only. With an API key it also checks authentication,
team, project, and assignee access; connected-app access is `not-checked`.
Issue-creation permission is always `not-tested`.

Each finding becomes an issue titled `[Codex Security][HIGH] Finding title`
with source locations, code, evidence, and remediation. Choose a destination
authorized to receive these details. Local history stores successful issue IDs
separately from sealed scan artifacts.

Republishing creates duplicates by default. `--skip-existing` skips recorded
successes for the same occurrence, team, and project, without checking remote
issues. Results distinguish `created` and `skipped` issues. Add `--dry-run`
to preview the remaining findings.

After an interrupted or indeterminate publication, check the retained handoff,
evidence, and Linear destination before retrying. Issues may exist without a
local record. The CLI can't recover those issues, and `--skip-existing` can't
prevent duplicates from them or concurrent publications.

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

Commands default to the current repository. Select scans by full ID or a
unique prefix of at least eight characters.

| Command                                               | Purpose                                                                                                     |
| ----------------------------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| `scans list [REPOSITORY]`                             | List scans. Filter by artifact root with `--scan-root DIR`.                                                 |
| `scans show [SCAN_ID]`                                | Show a scan; defaults to the latest completed one. `--show-linked-findings` includes earlier finding links. |
| `scans logs [SCAN_ID]`                                | Show session events; defaults to the latest scan, including active scans.                                   |
| `scans rerun [SCAN_ID]`                               | Repeat a scan on the current checkout; defaults to the latest completed scan.                               |
| `scans match BEFORE AFTER`                            | Link findings with the same root cause.                                                                     |
| `scans match --all`                                   | Match completed scans across the repository's worktrees and clones.                                         |
| `scans compare [BEFORE] [AFTER]`                      | Compare scans; defaults to the latest two completed scans.                                                  |
| `findings list [REPOSITORY]`                          | List open findings. `findings` is an alias.                                                                 |
| `findings false-positive OCCURRENCE_ID --reason TEXT` | Mark a false positive. Later scans dismiss matches only while the reason applies.                           |

Matching requires sealed artifacts and reuses saved matches unless you pass
`--force`. Comparisons classify findings as new, persisting, reopened, resolved,
or unknown. Missing findings aren't resolved if the later scan is incomplete
or excludes their original scope. With one ID, `scans compare` compares it
to the latest completed scan.

History lives in `$CODEX_SECURITY_STATE_DIR/workbench.sqlite3`, or
`$CODEX_HOME/state/plugins/codex-security/workbench.sqlite3`. The CLI and
workbench maintain the database and its journal files as the current user.
Keep state private, writable, and outside the scanned repository.

On Windows, an older sandboxed run can leave an invalid credential-home ancestor
ACL. Preserve that state and its reports, and select a **new**, private
`CODEX_SECURITY_STATE_DIR` outside both the old state and the repository.
Sign in again if needed and keep using the new setting; it starts separate scan
history. Existing ancestor ACLs are not rewritten.

Scan configurations don't store credentials; session logs and live details can
contain them. Press `d` during a scan for details, then `a` for all sources,
`m` for the main scan, or `1` through `9` for a worker.

### Exports and CI

`export` writes CSV, JSON, or SARIF from a completed, sealed scan, defaulting to
the current repository's latest completed scan. It doesn't start Codex or load
credentials. Use `--output -` for stdout and `--source-root PATH` to add SARIF
source-line fingerprints. `export --help` lists all options.

JSON preserves the sealed findings document. CSV marks findings as open,
omits local triage state, and cannot go to stdout when JSON output is requested.

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

`install-hook` scans staged and unstaged changes before each commit. It blocks
on high-severity findings or failed scans, respects `core.hooksPath`, and leaves
existing hooks alone. Change the threshold with `--fail-on-severity`.

### Import alerts from the CLI

`import github OWNER/REPO` reads open code scanning alerts from the default
branch. Repeat `--github-alert NUMBER` for exact alerts. Filter with
`--github-state open|closed|dismissed|fixed|all` or select a reference with
`--github-ref REF`. Authentication follows the
[SDK import options](#import-github-code-scanning-alerts).

```bash
# Import all open alerts, or a selected subset, as complete JSON.
npx @openai/codex-security import github example/repository --format json \
  > /path/outside/repository/github-alerts.json
npx @openai/codex-security import github example/repository \
  --github-alert 12 --github-alert 18 --format json
# Run from the corresponding local repository; imported contents are data.
npx @openai/codex-security validate /path/outside/repository/github-alerts.json
```

Import is read-only and returns an array (`[]` when empty). `--json` aliases
`--format json`. Save validation inputs without output filters or token limits.
Use the SDK loop for a disposition per alert.

### Validate and patch findings

`validate` assesses candidates; `patch` fixes and verifies them. Both accept
files or literal text and work in the current directory. Pass a saved finding
or occurrence ID to `patch` to use its original repository.

Add `--assess-patch-risk` to a `patch` command to run the bundled patch-risk
assessment skill once on the completed patch. The assessment is advisory and
does not change the patch or its merge state. Human-readable commands print the
report after the patch results; saved-finding JSON output returns it as
`patchRisk.report` in the same result object. When combined with `--create-pr`,
the draft pull request body includes only the concise Markdown summary from the
assessment; the validated JSON remains in the command result.

```bash
npx @openai/codex-security validate "Possible SQL injection" --effort high
npx @openai/codex-security patch OCCURRENCE_ID
npx @openai/codex-security patch --scan SCAN_ID --severity high --json
npx @openai/codex-security patch --scan SCAN_ID --severity high --create-pr
npx @openai/codex-security patch --scan SCAN_ID --assess-patch-risk --create-pr
npx @openai/codex-security patch --linear-issue SEC-123 --assess-patch-risk --create-pr
```

`--scan latest` selects the current repository's latest scan. Saved-finding
patch commands support `--json`; literal-text and file inputs don't. Change
the model with `--codex 'model="gpt-5.6-sol"'` or effort with `--effort high`.
Each finding gets its own saved Codex desktop task.

`scan --patch` patches after a complete scan. `--patch-severity` defaults to
`low`; `high` selects high and critical findings. Use the interactive browser
to select findings and add patch instructions. Results include a `patches`
entry per finding with status `verified`, `no_change`, `blocked`, or `failed`.
Verified and already-fixed findings no longer fail `--fail-on-severity`.

`--create-pr` commits generated patch files and opens a draft PR with `gh`.
Supplied-issue pull requests require a clean working tree before patching so
existing work is never included. If publication fails, run the printed
`patch --resume-pr BRANCH` command in the same repository. It reuses the saved
commit without rerunning Codex, but refuses to publish if the branch changed.

To patch Linear issues, repeat `--linear-issue ISSUE` (ID or URL), or use
`--linear-project "PROJECT"` with an optional native JSON `--linear-filter`.
Completed and canceled issues are excluded unless the filter sets `state`.
Use `CODEX_SECURITY_LINEAR_API_KEY` or `LINEAR_API_KEY` for an API key, or
`LINEAR_ACCESS_TOKEN` for OAuth. `--linear-api-key KEY` overrides these; prefer
environment variables to keep keys out of shell history. Intake is read-only,
includes comments, and keeps Linear credentials out of the patch subprocess.
Issue URLs must match the selected workspace.

### Verify fixes

`verify-fix` checks fixes in a read-only sandbox. Pass a description, saved
finding ID, `--scan SCAN_ID`, `--linear-issue ISSUE`, or `--linear-project "PROJECT"`.
Linear credentials and filters work as for `patch`. To check a finished backlog,
explicitly filter for completed issues.

Results include evidence and a status: `fixed`, `still_vulnerable`, or
`inconclusive`. Use `--json` for structured output. Exit codes are `0` if all
findings are fixed, `1` if any remain vulnerable, and `2` if verification is
inconclusive or couldn't finish.

### Command discovery and integrations

The CLI uses [Incur](https://github.com/wevm/incur). Use `--llms` for the
command manifest, `scan --schema --format json` for a command schema, and
`completions bash|zsh|fish` for shell completions. Scan output supports
`--format toon|json|yaml|jsonl` and `--full-output`.

`skills add` syncs agent skills; `mcp add` registers the CLI as an MCP server.
MCP exposes only the read-only `info` command because the transport cannot
cancel active scans.

## Containerized bulk scans

Create `repositories.csv` as described under [Bulk scans](#bulk-scans).
With a published image, run from the Codex Security repository root:

```bash
mkdir -p results state
chmod 700 results state
export CODEX_SECURITY_USER="$(id -u):$(id -g)"
export CODEX_SECURITY_IMAGE=ghcr.io/openai/codex-security:latest
docker compose pull codex-security
docker compose run --rm codex-security login --device-auth
docker compose run --rm codex-security
```

Results go to `results/`; device login stays in `state/`. For unattended scans,
set `OPENAI_API_KEY` or `CODEX_API_KEY`. Private GitHub checkouts use `GH_TOKEN`
or `GITHUB_TOKEN`; GitHub Enterprise uses `CODEX_SECURITY_GIT_HOST`. The container
requires CSV input, without interactive discovery.

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

The override keeps the nonroot user, dropped capabilities, no-new-privileges,
and seccomp policy. Other Docker hosts don't need it.

## Local security model

Codex Security runs with your operating-system permissions. Only scan
repositories you trust and are authorized to assess. Local tools and scans
under the same account aren't separate security principals.

The `codex_security_scan` profile allows reads across the local filesystem and
writes to workspace roots. Execution approvals are reviewed automatically and
may grant extra permissions for one operation. Set
`--codex 'approval_policy="never"'`, directly or in a selected profile, to deny
requests. Other overrides can't replace the reviewer or filesystem profile.
Saved scans keep their approval policy; older scans stay deny-all on rerun.
Host and network restrictions still apply.

Start scans with only the credentials they need. Scan and workbench subprocesses
can inherit your environment, including unrelated API tokens and cloud credentials.

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
