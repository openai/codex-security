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
later in the 22.x release line, Node.js 24.x, or Node.js 26.x. Scanning and
exporting findings also require Python 3.10 or later. If you use Python 3.10,
install the `tomli` package. Select another interpreter with `--python`,
`pythonPath`, or `PYTHON` when needed.

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

Results can contain source excerpts, vulnerability details, and reproduction
steps. Keep result directories and saved reports outside the repository and
limit access to authorized reviewers.

### SDK configuration and scan options

Pass runtime configuration to the `CodexSecurity` constructor:

| Option           | Description                                                                 |
| ---------------- | --------------------------------------------------------------------------- |
| `pluginPath`     | Use a Codex Security plugin directory or ZIP instead of the bundled plugin. |
| `pythonPath`     | Select the Python interpreter before consulting `PYTHON`.                   |
| `codexOverrides` | Deep-merge supported settings into the isolated Codex configuration.        |
| `azureOpenAI`    | Select an Azure OpenAI resource endpoint for API-key scans.                 |

For Azure OpenAI, set `AZURE_OPENAI_API_KEY` and use the deployment name as
`model`:

```ts
import { CodexSecurity } from "@openai/codex-security";

const security = new CodexSecurity({
  azureOpenAI: {
    endpoint: "https://my-resource.openai.azure.com",
  },
  codexOverrides: {
    model: "my-security-deployment",
  },
});
```

`azureOpenAI` uses Azure's v1 API. A resource-root endpoint is normalized to
`/openai/v1`; a URL ending in `/openai` gets `/v1` appended. Endpoints must use
HTTPS and must not contain credentials, query parameters, or fragments.

Pass scan configuration to `security.run(repository, options)` or
`security.preflight(repository, options)`:

| Option                  | Description                                                                           |
| ----------------------- | ------------------------------------------------------------------------------------- |
| `auth`                  | Select `"auto"`, `"chatgpt"`, or `"api-key"`.                                         |
| `target`                | Select a repository, repository-relative paths, committed diff, or working-tree diff. |
| `mode`                  | Select `"standard"` or `"deep"`; deep mode supports repositories and paths.           |
| `knowledgeBasePaths`    | Add architecture documents, security policies, threat models, or directories.         |
| `outputDir`             | Choose an artifact directory outside the enclosing Git worktree.                      |
| `archiveExisting`       | Archive results already in `outputDir` before starting a scan.                        |
| `maxCostUsd`            | Stop after the estimated model cost exceeds a positive USD amount.                    |
| `failureSeverity`       | Record a finding-severity policy in the saved scan recipe.                            |
| `parentScanId`          | Link a rerun to an existing parent scan.                                              |
| `expectedPluginVersion` | Require the original plugin version when replaying a scan.                            |
| `signal`                | Cancel a scan with an `AbortSignal`.                                                  |

Progress and lifecycle callbacks are `onAuthentication`, `onCost`,
`onOutputArchived`, `onOutputDirReady`, `onScanStarted`, `onReconnect`,
`onWorkerStatus`, `onWarning`, and `onObserverError`. Preflight does not start
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

On Windows, set the API key in PowerShell:

```powershell
$env:OPENAI_API_KEY = "<your-api-key>"
npx @openai/codex-security scan C:\code\repository
```

Azure OpenAI uses `AZURE_OPENAI_API_KEY` directly from the environment; it is
not stored by `codex-security login`. Pass `--azure-endpoint` and use the Azure
deployment name with `--model`. The integration currently supports API-key
authentication only; it does not support Microsoft Entra ID, managed identity,
or `--auth chatgpt`.

For repeatable Azure rate-limit failures, review the deployment's TPM/RPM
allocation in Foundry, reallocate or request more quota, or use a deployment
with capacity in another region. See Microsoft's
[Azure OpenAI quota guide](https://learn.microsoft.com/en-us/azure/foundry/openai/how-to/quota).

Check or remove the stored sign-in with `npx @openai/codex-security login status`
and `npx @openai/codex-security logout`. Codex Security keeps its sign-in in a
private, stable Codex home at `$CODEX_SECURITY_STATE_DIR/codex-home`, or at
`$CODEX_HOME/state/plugins/codex-security/codex-home` when no state directory is
configured. Login, status, logout, and scans use the same home. Codex manages
credentials using its configured file or system-keyring backend and honors
managed-device policies. An existing file-based Codex sign-in is imported only
when the dedicated home does not already contain stored credentials. Logging
out prevents later scans from automatically reimporting that ambient sign-in
until you explicitly log in again.

An environment API key takes precedence over a stored sign-in by default.
When both a stored ChatGPT sign-in and an environment API key are available, an
interactive scan asks which credential to use. JSON output, dry runs, CI, and
other noninteractive scans never prompt and retain automatic API-key
precedence. Select the credential source explicitly with `--auth`:

```bash
npx @openai/codex-security scan . --auth chatgpt
npx @openai/codex-security scan . --auth api-key
```

`--auth chatgpt` uses the stored sign-in and ignores `OPENAI_API_KEY` and
`CODEX_API_KEY`. For OpenAI, `--auth api-key` requires one of those variables;
with `--azure-endpoint`, it requires `AZURE_OPENAI_API_KEY`. Omit `--auth`, or
pass `--auth auto`, to preserve automatic API-key precedence for existing CI
and unattended scans. The SDK accepts the same selection as
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

## CLI

```bash
npx @openai/codex-security scan /path/to/repository
npx @openai/codex-security scan /path/to/repository --model gpt-5.6-terra
npx @openai/codex-security scan /path/to/repository --model gpt-5.6-terra --effort high
npx @openai/codex-security scan /path/to/repository --path src --path tests
npx @openai/codex-security scan /path/to/repository --knowledge-base /path/to/threat-models --knowledge-base /path/to/architecture.pdf
npx @openai/codex-security scan /path/to/repository --diff origin/main --json
npx @openai/codex-security scan /path/to/repository --output-dir /path/outside/repository/results
npx @openai/codex-security scan /path/to/repository --output-dir /path/outside/repository/results --archive-existing
npx @openai/codex-security scan /path/to/repository --dry-run
npx @openai/codex-security scan /path/to/repository --fail-on-severity high
npx @openai/codex-security scan /path/to/repository --max-cost 5
npx @openai/codex-security scan /path/to/repository --azure-endpoint https://my-resource.openai.azure.com --model my-security-deployment
npx @openai/codex-security install-hook
npx @openai/codex-security bulk-scan
npx @openai/codex-security bulk-scan --model gpt-5.6-terra --effort high
npx @openai/codex-security bulk-scan repositories.csv --output-dir /path/outside/repositories/security-scans --azure-endpoint https://my-resource.openai.azure.com --model my-security-deployment
npx @openai/codex-security bulk-scan repositories.csv --output-dir /path/outside/repositories/security-scans --workers 4
npx @openai/codex-security scans list /path/to/repository
npx @openai/codex-security scans list --scan-root /path/outside/repository/results
npx @openai/codex-security scans show SCAN_ID
npx @openai/codex-security scans rerun SCAN_ID
npx @openai/codex-security scans match PREVIOUS_SCAN_ID CURRENT_SCAN_ID
npx @openai/codex-security scans match --all
npx @openai/codex-security scans compare PREVIOUS_SCAN_ID CURRENT_SCAN_ID
npx @openai/codex-security findings false-positive OCCURRENCE_ID --reason "The route already checks permissions"
npx @openai/codex-security export /path/outside/repository/results --export-format sarif --output /path/outside/repository/results.sarif
npx @openai/codex-security export /path/outside/repository/results --export-format csv --output /path/outside/repository/findings.csv
npx @openai/codex-security export /path/outside/repository/results --export-format json --output /path/outside/repository/findings.json
npx @openai/codex-security validate /path/outside/repository/findings.json "Possible SQL injection in src/query.ts:42"
npx @openai/codex-security validate "Possible SQL injection" --effort high
npx @openai/codex-security patch /path/outside/repository/findings.json "Missing authorization check in src/routes.ts:18"
npx @openai/codex-security patch "Missing authorization check" --effort high
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

Repeat `--knowledge-base PATH` for multiple files or directories. Directories are
searched recursively for Markdown, text, PDF, and Word (`.docx`) files.

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

Scans use `gpt-5.6-sol` with extra-high reasoning effort by default. OpenAI is
the implied provider unless `--azure-endpoint` configures Azure OpenAI. Use
`--model gpt-5.6-terra` to switch OpenAI models; with Azure, `--model` is the
deployment name. Use `--effort minimal|low|medium|high|xhigh` to set reasoning
effort. Repeat `--codex KEY=VALUE` for other Codex settings; existing
`--codex 'model_reasoning_effort="high"'` overrides remain supported.

### Runtime configuration and worker limits

The standalone CLI and SDK do not load an unrelated user or repository Codex
configuration. Each scan starts with a private runtime and these Codex
defaults:

```toml
cli_auth_credentials_store = "file"
model = "gpt-5.6-sol"
model_reasoning_effort = "xhigh"

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
runtime overrides. Azure's `--azure-endpoint` option is currently available to
`scan` and `bulk-scan`; it is not available to `validate` or `patch`.

These overrides do not change the scan's approval policy or filesystem
permissions. See [Local security model](#local-security-model).

### Deep-scan engine configuration

When the bundled plugin runs in a normal Codex host, its repeated-discovery
engine reads `$CODEX_HOME/codex-security/config.toml`, defaulting to
`~/.codex/codex-security/config.toml`:

```toml
[deep_scan]
workers = "auto"
subagents = 3
stop_after_no_new = 6
max_discovery_runs = 60
```

`workers = "auto"` uses half the available parallelism, with a minimum of one
and a maximum of six discovery workers. Set `workers` to a positive integer to
choose an explicit count. `subagents` must be a nonnegative integer;
`stop_after_no_new` and `max_discovery_runs` must be positive integers. Unknown
`[deep_scan]` keys are rejected.

These settings are separate from Codex's
`features.multi_agent_v2.max_concurrent_threads_per_session` and
`bulk-scan --workers`. Importantly, standalone CLI and SDK scans create an
isolated `CODEX_HOME` and do not import the ambient deep-scan configuration
file. Consequently, `scan --mode deep` currently uses the deep engine's
defaults; there are no standalone CLI flags for these four settings. Use
`--codex` to adjust the Codex session thread limit, not to set `[deep_scan]`
values.

### Environment variables

The CLI and SDK recognize the following user-configurable environment:

| Variable                                                                    | Effect                                                                                        |
| --------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------- |
| `OPENAI_API_KEY`, `CODEX_API_KEY`                                           | Scan authentication; `OPENAI_API_KEY` wins when both are present.                             |
| `AZURE_OPENAI_API_KEY`                                                      | Azure OpenAI scan authentication when an Azure endpoint is configured.                        |
| `CODEX_SECURITY_STATE_DIR`                                                  | Override the private scan-history, workbench, and default artifact directory.                 |
| `CODEX_HOME`                                                                | Set the ambient Codex home for file-backed sign-in and default state; defaults to `~/.codex`. |
| `PYTHON`                                                                    | Select a Python interpreter when `--python` or SDK `pythonPath` is not set.                   |
| `GH_HOST`                                                                   | Select a GitHub Enterprise host during interactive `bulk-scan` discovery.                     |
| `CODEX_SECURITY_NO_UPDATE_NOTICE`, `NO_UPDATE_NOTIFIER`                     | Disable interactive update notices when either variable is defined.                           |
| `CODEX_SECURITY_NPM_REGISTRY`, `npm_config_registry`, `NPM_CONFIG_REGISTRY` | Select the update-check registry, in the listed precedence order.                             |
| `CI`                                                                        | Disable interactive update notices in automated environments.                                 |
| `NO_COLOR`, `TERM`                                                          | Disable colored scan-history output when `NO_COLOR` is defined or `TERM=dumb`.                |

Interpreter discovery uses `--python` or `pythonPath` first, then `PYTHON`,
the managed Codex runtime, and finally `python3` or `python` from `PATH`.
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

Scan progress identifies the requested paths and reports actual ranking,
file-review, validation, and attack-path phases as they become available.
Completion summarizes findings, severity, coverage, elapsed time, available
token and worker counts, estimated cost, the results directory, and the next
useful command.
Progress and summaries use stderr; structured scan results remain on stdout.

Each scan records its model and token usage in its JSON result, scan history,
and bulk-scan receipt. For the built-in OpenAI provider, it also records an
estimated cost using
[standard API token prices](https://developers.openai.com/api/docs/models/compare),
including cached input and cache writes; fees and surcharges are not included.

Use `--max-cost USD` to stop a scan, including its delegated workers, when its
running cost exceeds the limit. Partial results are preserved. Requests
already in progress can finish above the limit. Cost estimates and cost limits
are not available for non-OpenAI providers: Azure scans report a null estimated
cost and reject CLI `--max-cost` or SDK `maxCostUsd`.

Run `npx @openai/codex-security scan --help` or `npx @openai/codex-security bulk-scan --help`
for the complete CLI references.

Sign in with `gh auth login`, then run `npx @openai/codex-security bulk-scan` to discover
GitHub repositories pushed in the last 90 days. Archived
repositories and forks are excluded. Search the repository list, select the
repositories to scan, and confirm before scanning.
Private checkouts reuse your GitHub CLI sign-in without changing your global Git
configuration. The selected repositories are saved to
`<output-dir>/repositories.csv` for review or resumption.

To use an existing repository list or run in CI, pass a CSV with required `id`,
`repository`, and `revision` columns. Revisions must be full commit hashes;
optional `scope` and `mode` columns narrow individual scans:

```csv
id,repository,revision,scope,mode
service,https://github.com/acme/service.git,0123456789abcdef0123456789abcdef01234567,src,standard
```

`--workers` limits concurrent scans and `--max-attempts` retries failures.
Results remain under `--output-dir`; rerun the same command to resume.

### Scan history and reruns

`npx @openai/codex-security scans list` lists scans for the current repository. Pass a
repository path to inspect another checkout, `--scan-root DIR` to list scans
whose artifacts are under a particular root. `scans show SCAN_ID` includes the
scan configuration, results, coverage, and artifact locations. Add
`--show-linked-findings` to include finding links from previous scans.

Every scan history command accepts a full scan ID or a unique prefix of at
least eight characters.

Scan history uses the existing Codex Security workbench database at
`$CODEX_HOME/state/plugins/codex-security/workbench.sqlite3`. Set
`CODEX_SECURITY_STATE_DIR` to place the database elsewhere. Scan credentials
are never stored in the scan configuration. An Azure recipe retains only the
normalized endpoint and replay-safe scan configuration; the provider definition
is reconstructed, and the API-key value is never stored.

The scan sandbox permits writes to the selected state directory so SQLite can
maintain its database and journal files. If the host itself cannot write to the
default directory, select a writable directory outside the scanned repository:

```bash
export CODEX_SECURITY_STATE_DIR=/path/to/writable/codex-security-state
```

Use `findings false-positive OCCURRENCE_ID --reason TEXT` to mark a finding as
a false positive and explain why. Later scans dismiss a matching finding only
when the same reason still applies.

`scans rerun SCAN_ID` repeats the original configuration against the current
checkout so a fixed vulnerability can be checked again. Before rerunning an
Azure scan, set `AZURE_OPENAI_API_KEY` again in the current environment.

`scans match BEFORE_SCAN_ID AFTER_SCAN_ID` links findings with the same root
cause; `scans match --all` matches all completed scans of the current repository,
including other worktrees and clones. Saved matches appear in `scans show` and
are reused unless `--force` is passed. Scans without sealed artifacts are skipped.

`scans compare BEFORE_SCAN_ID AFTER_SCAN_ID` automatically matches findings by
root cause, reuses saved matches, and reports findings as new, persisting,
reopened, resolved, or unknown. Missing findings are not treated as resolved when
the later scan is incomplete or does not cover their original scope.

The CLI uses [Incur](https://github.com/wevm/incur) for agent-friendly discovery
and structured output. Inspect the command manifest with `--llms`, inspect a
command schema with `scan --schema --format json`, register the CLI as an MCP
server with `mcp add`, sync agent skills with `skills add`, or generate shell
completions with `completions bash|zsh|fish`. Scan results support
`--format toon|json|yaml|jsonl` and `--full-output`.
Use `info --json` for SDK and bundled-plugin metadata. MCP exposes only this
read-only metadata command; scans, bulk repository scans,
authentication, exports, validation, and patching remain CLI-only because the
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
The `validate`, `patch`, `login`, and `logout` commands reject `--json` because
they do not produce structured CLI output. Sign-in commands remain interactive.
CSV exports cannot be written to stdout while JSON output is requested.

Use `export` to create CSV, JSON, or SARIF from a completed, sealed scan without
starting Codex or loading credentials. JSON preserves the sealed findings
document. CSV uses the portable findings columns, marks findings as open, and
does not include local workbench triage state. The exporter validates the seal
before writing, accepts `--output -` for stdout, and can use
`--source-root /path/to/repository` with SARIF to add source-line fingerprints.
Run `npx @openai/codex-security export --help` for all export options.

Use `validate` to run the bundled validation skill on candidate findings and
`patch` to run the bundled fix-finding skill on security issues. Each positional
input can be either a file, whose contents are read into the request, or literal
text. Both commands operate on the current directory, use the scan model
and reasoning defaults, ignore unrelated user configuration and plugins, and
print the final response without the underlying Codex event stream. Override
the model with `--codex 'model="gpt-5.6-sol"'` and the reasoning effort with
`--effort high` or `--codex 'model_reasoning_effort="high"'`. Inputs are
limited to 64 items and 1 MiB total.

Canonical scan documents are limited to 16 MiB for the manifest, 128 MiB for
findings, and 32 MiB for coverage. Oversized scans are rejected before sealing.

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
export CODEX_SECURITY_IMAGE=ghcr.io/openai/codex-security:0.1.4
docker compose pull codex-security
docker compose run --rm codex-security login --device-auth
docker compose run --rm codex-security
```

Reports and resumable scan results are written to `results/`; the reusable
device login remains in `state/`. For unattended scans, set `OPENAI_API_KEY`
or `CODEX_API_KEY` instead. Set `GH_TOKEN` or `GITHUB_TOKEN` for private
GitHub repositories.

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
`approvalPolicy: "never"`. It can read the local filesystem and write to
workspace roots and the selected scan state directory. Scans do not request
interactive approval. Setting `approval_policy`, `sandbox_mode`, or permissions
through `--codex` or SDK `codexOverrides` does not replace these controls or
make them more restrictive. Independently enforced host and network
restrictions still apply.

Scan and workbench subprocesses can inherit your environment, including
unrelated API tokens and cloud credentials. For Azure scans,
`AZURE_OPENAI_API_KEY` is removed from plugin-Python, workbench, and bootstrap
helper processes, supplied separately to the parent Codex model runtime, and
excluded from model-run shell commands. Host tools such as Git can still
inherit ambient variables. Start a scan with only the credentials it needs.

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
