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
[findings guide](docs/findings-service.md), or
[online documentation](https://learn.chatgpt.com/docs/security) for setup and examples.

Before version `1.0.0`, minor releases may change the public API.

## Install

Supported runtimes:

- Node.js 22.13.0+ within 22.x, or Node.js 24.x or 26.x, on macOS, Linux, or Windows.
- Python 3.10+ for scans, policy generation, exports, scan history, and saved
  findings. Python 3.10 also needs `tomli`. The findings server (`serve`) uses
  Node’s built-in SQLite and does not require Python.

Reading compressed Codex session logs (`.jsonl.zst`) requires Node.js 22.15.0+
within 22.x, or Node.js 24.x or 26.x. On Node.js 22.13–22.14, compressed sessions
are unavailable when reading saved activity or attaching scan logs to feedback, and
scans whose original session is compressed cannot resume. Plain `.jsonl` logs
work on all supported runtimes.

`LocalPluginBootstrapError` identifies local plugin setup failures and extends
`PluginBootstrapError`, so existing catches keep working. Knowledge-base
preparation errors use `ConfigurationError`; wrapped diagnostics remain in `cause`.

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

Custom plugins must support the current workbench protocol for scan comparison
and archival. Update an older custom plugin or omit `pluginPath` to use the
bundled version. The SDK no longer adapts payloads or archives scan directories
on behalf of older workbench implementations.

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

For `scan --mode deep`, `--workers` sets the number of independent Standard scans
in each batch, and `--subagents` sets subagents per scan. Each batch finishes and
merges before the next starts. With `--workers 1`, each scan is merged immediately.

`--stop-after-no-new` stops after that many successfully merged scans without new
issues. Within each batch, scans count in their original order, and each new
issue is credited to the first scan that found it. A scan credited with a new
issue resets the count; other successful scans increase it. The scan checks this
threshold after each batch merge, so a batch can pass the threshold. Failures do not count as
no-new results, and retries do not consume additional discovery runs.
`--max-discovery-runs` and `--max-time-hours` cap discovery runs and duration.
SDK equivalents:

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

CLI and SDK options override these defaults. Project files can use
`scan.deep.stop_after_consecutive_errors`, and SDK calls can use
`stopAfterConsecutiveErrors`; there is no new CLI flag for it. `--codex` cannot
configure this section. Worker and run counts must
be positive integers; `subagents` can be zero. Legacy `workers = "auto"` means
four workers. Unknown keys are rejected.

`max_time_hours` accepts positive values up to 96, including fractional hours.
At the deadline, discovery stops; the scan combines and returns completed findings.
If the deadline expires before any child starts, the result is an empty sealed
report with partial coverage and a `null` `threadId`; no model turn is needed.
Failed or canceled checkpoints are terminal and cannot be resumed as running work.

Knowledge documents are extracted once for a Deep Scan. Every child receives the
same immutable content, even if the original files change during the scan. Resume
checks the saved content digest and rejects changed inputs before starting work.

Merge inputs retain exact original findings and evidence. A compact index points
to complete retained source and history records; the merger must read those records
before consolidating findings. Host validation preserves every source reference,
while merge-quality evaluation also checks independent issues, canonical repairs,
and severity. See the [completed-report evaluation](scripts/merge-eval/README.md).

`scan --workers` controls discovery workers within one deep scan;
`bulk-scan --workers` controls how many repositories are scanned concurrently.

The project-file deep block uses `subagents_per_worker` for the existing SDK/CLI
`subagents` setting. A valid deep block can remain inactive in standard mode;
explicit deep CLI options require deep mode. All six active values are resolved
before runtime preparation and saved in new recipes. Complete saved values are
independent of later changes to the legacy TOML file.

### Runtime configuration and worker limits

Scans use these isolated Codex defaults instead of your user or repository
configuration:

```toml
approval_policy = "on-request"
approvals_reviewer = "auto_review"
cli_auth_credentials_store = "auto"
model = "gpt-5.6-sol"
model_reasoning_effort = "xhigh"
model_reasoning_summary = "detailed" # "none" for amazon-bedrock
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

Use `--model MODEL` to choose a model and `--effort EFFORT`
for reasoning effort. Both flags work with `scan`, `bulk-scan`, `scan-components`,
`policy`, `validate`, `patch`, `verify-fix`, `suggest-owners`, `classify-severity`,
`scans match`, and `scans compare`.

Model IDs and reasoning effort values are passed through to Codex unchanged.
The wrapper accepts values such as `minimal`, `none`, and `high`, as
well as future values, without requiring a wrapper update. Supported combinations
depend on the model, inference provider, installed Codex version, and credentials.
Codex and provider errors are reported without substituting another model or effort.
Omitting these flags preserves each command's defaults: scans, policy generation,
validation, patching, verification, and owner suggestions use `gpt-5.6-sol`/`xhigh`;
matching and severity classification use Codex's configured model and `medium` effort.

Repeat `--codex KEY=VALUE` for other TOML settings on commands that support it:

```bash
npx @openai/codex-security scan . \
  --model gpt-6.1-sol \
  --effort high \
  --codex features.multi_agent_v2.max_concurrent_threads_per_session=4

npx @openai/codex-security patch issues.md --model gpt-6-astra --effort max
npx @openai/codex-security verify-fix issues.md --model gpt-6.1-sol --effort high
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

`validate`, `patch`, and `verify-fix` accept `--auth`, `--model`, and `--effort`.
Their `--codex` overrides are limited to `model`, `model_reasoning_effort`,
`model_provider`, `model_providers`, and `analytics.enabled`.
Use the same provider settings as `scan` when routing a standalone patch
through a custom inference gateway:

```bash
npx @openai/codex-security patch "Security issue" \
  --model gateway-model \
  --codex 'model_provider="gateway"' \
  --codex 'model_providers.gateway.name="Gateway"' \
  --codex 'model_providers.gateway.base_url="https://gateway.example.test/v1"' \
  --codex 'model_providers.gateway.wire_api="responses"' \
  --codex 'model_providers.gateway.env_key="GATEWAY_API_KEY"'
```

Set the selected provider's API-key environment variable before running the
command; `--auth api-key` uses that configured variable. For `patch` and
`verify-fix`, provider overrides preserve unspecified fields from the provider's
existing Codex configuration. With `auto` or `api-key` authentication, a configured
`env_key` takes precedence over OpenAI account authentication, matching native Codex.
Explicit `--auth chatgpt` omits the selected custom provider's API-key environment
variable, clears any configured `experimental_bearer_token`, and selects stored
account authentication in its runtime configuration, even if the provider normally
uses only an API key or bearer token. The original environment and
Codex configuration remain unchanged.
Model, effort, and provider settings also apply to
`patch --assess-patch-risk`.
Sandbox, approval, and plugin settings remain controlled by the command.

`scans resume` and `scans rerun` retain the saved scan's settings. `dedupe` uses
separate screening and review models, so it does not expose a single model/effort
override.

Use `--codex 'analytics.enabled=false'` to disable Codex usage analytics and
built-in metrics for a command:

```bash
npx @openai/codex-security validate "Candidate finding" --codex 'analytics.enabled=false'
npx @openai/codex-security patch "Security issue" --codex 'analytics.enabled=false'
npx @openai/codex-security verify-fix "Security issue" --codex 'analytics.enabled=false'
```

The same setting works for `scan` and `bulk-scan`. An explicit setting is
preserved when `scan --patch` starts remediation and when
`patch --assess-patch-risk` starts its follow-up assessment. Boolean `true`
is also accepted; omitting the setting preserves the command's existing
configuration and Codex defaults. Validation ignores user configuration.
For stored OpenAI credentials, patching and verification read configuration
from the shared credential home. API-key commands and custom providers that use their own credentials retain
their ambient Codex configuration. Patching and verification preserve project trust from the
ambient home; explicit `--codex` settings apply to the command and its
patch-risk assessment.

This setting does not control explicitly configured OpenTelemetry log or trace
exporters, authentication, integrations, or CLI update checks.

See [Local security model](#local-security-model) for approval and filesystem
restrictions.

### Environment variables

| Variable                                                                    | Effect                                                                                                    |
| --------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------- |
| `OPENAI_API_KEY`, `CODEX_API_KEY`                                           | Scan credentials; `OPENAI_API_KEY` wins if both are set.                                                  |
| `CODEX_SECURITY_EMBEDDINGS_URL`                                             | Findings service endpoint; see [Embeddings and storage](#embeddings-and-storage).                         |
| `CODEX_SECURITY_LINEAR_TEAM`, `CODEX_SECURITY_LINEAR_PROJECT`               | Default team and project for completed-scan publication.                                                  |
| `CODEX_SECURITY_LINEAR_API_KEY`                                             | Personal API key for Linear patching and direct publication.                                              |
| `CODEX_SECURITY_LOG_LEVEL`                                                  | CLI-only; `debug` enables verbose diagnostics.                                                            |
| `LOG_LEVEL`                                                                 | CLI-only fallback when `CODEX_SECURITY_LOG_LEVEL` is unset or blank.                                      |
| `CODEX_SECURITY_STATE_DIR`                                                  | Private scan-history, workbench, and default artifact directory.                                          |
| `CODEX_SECURITY_PROJECT_CONFIG`                                             | Trusted project file for `scan`, `bulk-scan`, `scan-components`, and `info`; `-c` wins. Unset by default. |
| `CODEX_HOME`                                                                | Ambient Codex home for file-based sign-in and default state; defaults to `~/.codex`.                      |
| `CODEX_CLI_PATH`                                                            | Codex executable for authentication, plugin setup, scans, and workers.                                    |
| `PYTHON`                                                                    | Python interpreter when `--python` or SDK `pythonPath` is unset.                                          |
| `GH_HOST`                                                                   | GitHub Enterprise host for interactive `bulk-scan` discovery.                                             |
| `CODEX_SECURITY_NO_UPDATE_NOTICE`, `NO_UPDATE_NOTIFIER`                     | Either variable disables interactive update notices.                                                      |
| `CODEX_SECURITY_NPM_REGISTRY`, `npm_config_registry`, `NPM_CONFIG_REGISTRY` | Update-check registry, in precedence order.                                                               |
| `CI`                                                                        | Disables interactive update notices.                                                                      |
| `NO_COLOR`, `TERM`                                                          | Disables colored scan history when `NO_COLOR` is defined or `TERM=dumb`.                                  |

Custom Codex executables need thread source attribution for `exec` and
`app-server` (Codex 0.149.1+). On Windows, use a native `.exe` or `.com`;
command shims such as `codex.cmd` fall back to the bundled executable.

Python lookup order: `--python` (on `scan`, `bulk-scan`, or `export`) or SDK
`pythonPath`, then `PYTHON`, the managed Codex runtime, and `python3` or `python`
on `PATH` (`py` also works on Windows). `CODEX_SECURITY_STATE_DIR` overrides
`CODEX_HOME` for state storage. Keep state and results outside the repository.

### Troubleshooting

By default, scans show progress, state transitions, warnings, and summaries.
Add `--verbose` or set
`CODEX_SECURITY_LOG_LEVEL=debug` to include lifecycle, configuration, retry,
and worker diagnostics on stderr. `LOG_LEVEL=debug` is the fallback when
`CODEX_SECURITY_LOG_LEVEL` is unset or blank.

```bash
npx @openai/codex-security scan . --verbose
```

Codex Security preserves diagnostic text, including credential-shaped values,
in CLI output, stored failures, publication receipts, and patch-risk summaries.
Verbosity controls the amount of diagnostic detail. Native Codex and upstream
SDK output may already have been redacted before reaching Codex Security.
Review output and artifacts for sensitive information before sharing them.

### Progress and cost

Use `onProgress` for scan progress and `onCost` for cost updates.

The token summary shows uncached input, cache reads, cache writes, output,
and total tokens. Total tokens include all input plus output; cache reads and
writes are subsets of input, not extra tokens. When cache-write usage is missing,
the summary shows uncached input and cache writes as unavailable.
The final summary preserves missing-data information from a matching session log.
If the Codex runtime converts an omitted count to zero before recording it, the
CLI cannot distinguish that zero from reported usage.

Cost displays show a range using
[standard API prices](https://developers.openai.com/api/docs/pricing), because
runtime usage does not identify which requests received long-context pricing.
The minimum assumes short-context pricing; the maximum assumes long-context
pricing. These are token-cost estimates for the observed usage, excluding other
processing tiers, fees, surcharges, and account-specific pricing.

JSON results, scan history, and bulk-scan receipts preserve
`cost.estimatedUsdRange`: `min`, `max`, and `context: "unknown"`. A `null` maximum
means an upper estimate is unavailable, including models without verified
long-context rates. `cost.pricing` records the price source, verification date,
processing tier, short-context rates, and verified long-context rates when known.
Models without known short-context prices still have no cost estimate.
GPT-6 Astra, GPT-6.1 Sol, and GPT-6 Luna have verified standard prices for cost
estimates and `--max-cost` limits.

For compatibility, `cacheWriteInputTokens` remains the reported token subtotal.
`cacheWriteInputTokensReported: false` means at least one included usage record
did not report cache writes. Raw usage uses `cache_write_input_tokens_reported`.
In that case, the range minimum prices unclassified input as ordinary input,
and the maximum allows it to be cache writes. Token counts remain unchanged.
Older saved records remain readable and display a labeled legacy estimate;
they are not repriced using current rates.

For compatibility, `cost.estimatedUsd` retains the short-context baseline used
by existing spending limits. `cost.pricing.context: "short"` describes that
baseline, not observed request contexts. Use `estimatedUsdRange` for cost
reporting. This change does not change when spending limits stop scans.

`--max-cost USD` stops the scan and its workers when estimated cost exceeds
the limit, though in-flight requests can finish above it. If deep-scan
discovery has finished, the scan returns a sealed partial report without more
model calls and lists unvalidated candidates as follow-up work. Bulk scans
apply the limit per repository attempt.

With `--max-cost`, automatic finding-history matching makes at most one extra
model call. If it needs more context, the completed scan is kept and a warning
directs you to run `scans match --all` explicitly.

For a single scan in the interactive dashboard, reaching 80% of the limit
offers a higher **total** USD limit. Enter a larger amount to approve it, or
press Enter with an empty input or Escape to keep the current limit. The scan
continues running while you decide, and the existing limit remains enforced
until the increase is saved. Increases keep the same scan and accumulated cost;
they do not restart work or extend time or discovery limits. CI, JSON/JSONL,
`--headless`, and `--verbose` scans do not offer budget increases. If usage crosses the limit
before an increase is approved, the scan still stops.

SDK callers can supply `onBudgetApproaching({ maxCostUsd, cost, signal })` and
return a higher total limit, or `undefined` to keep the current limit. The
callback runs once per limit at 80% usage without blocking tracking or
execution. Its signal aborts when the scan stops or finishes model work; late
answers are ignored. Invalid increases or failures to save them leave the
existing limit in place and report a warning. `onCost(cost, maxCostUsd)` reports
the current limit, including after an approved increase.

These amounts estimate API-equivalent model usage, not ChatGPT subscription
allowance. Post-scan prompts run after scan cost tracking ends and are outside
this limit.

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
`-c FILE` shares config with single scans: CSV mode/scope override file defaults,
and deep settings apply only to deep rows. `output.directory` can supply the
results directory. `fail_on_severity` returns exit `1` without retrying completed
scans, including when resuming saved results. A changed project configuration
requires a new campaign output directory.
`--post-scan-prompt-file PATH` runs a follow-up in the same authenticated session,
even after a failed or incomplete scan, but not after cancellation or a
cost-limit stop.

`--workers` defaults to `4`. `--max-attempts` defaults to `1` attempt per pending
repository per invocation. Rerunning the command continues the campaign, skips
completed results, and starts new attempts for pending repositories. If an
attempt directory is occupied, that repository stops before replacing its
checkout and the command recommends `--recover`.

#### Recovering failed or interrupted bulk scans

Use the original CSV, output directory, and campaign options with `--recover`:

```bash
npx @openai/codex-security bulk-scan repositories.csv \
  --output-dir /path/outside/repositories/security-scans --recover
```

Recovery requires an existing campaign with a matching manifest. It skips
completed results, including partial coverage, and repositories never started.
For each failed or interrupted repository, it checks the latest attempt:

- A sealed scan is recorded in `results.jsonl` without scanning again.
- An eligible running Deep Scan resumes saved work in its original output
  directory, keeping its scan ID, completed workers, artifacts, saved settings,
  and accumulated cost.
- A failed, canceled, or otherwise unavailable scan starts a new attempt at the
  CSV's pinned revision. Attempt numbers account for both receipts and existing
  directories. Old artifacts and checkouts are preserved; new attempts use
  `recovery-checkouts/<id>/attempt-<n>`.

`--workers` still defaults to `4`; `--max-attempts` defaults to one recovery or
new attempt per repository. A resume connection failure stops that repository
for this invocation instead of starting another scan. Other repositories
continue. Failed and interrupted recovery checkouts remain available for a later
`--recover`; fresh completed checkouts are removed after recording the result.
If a reboot interrupted a receipt write, its unfinished tail is saved beside
`results.jsonl` as `results.jsonl.interrupted-<id>` before appending valid records.

Same-scan resume requires the original checkout, session logs, and Codex Security
state directory. Recovery does not reconstruct deleted checkpoints or fix the
underlying cause of execution failures. New attempts incur new scan costs.
Any remaining failures or partial coverage keep exit code `2`.
`bulk-scan --help` lists all options.

### Custom validation

Replace the final validation step of a standard or diff scan with a prompt
file. Source review still runs; discovery workers do not receive this prompt.

```bash
npx @openai/codex-security scan . --validation-prompt-file validation.md
```

The SDK accepts the same file as `validationPromptFile`, or inline text as
`validationPrompt`:

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
configured cap, not a percentage denominator. The optional `consolidating` flag
reports when results are being combined or the coordinator has finished.
`ScanOptions` lists all callbacks.

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

After [installing the CLI](#install-the-cli), sign in if needed:

```bash
cs login
```

From your repository directory, optionally draft security guidance before scanning:

```bash
cs policy .
```

The command saves a draft outside the checkout. Review the proposed diff and
notes, edit the draft as needed, then copy it to the displayed `Policy target`
so future scans use it. Generating the draft alone does not install it.
Skip this step to keep an existing policy or scan without one. See
[Generate a security policy](#generate-a-security-policy) for details.

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
for high or critical findings; incomplete scans and execution failures return `2`.

The [CLI reference](docs/cli.md) covers scan history, reruns, bulk and component
scans, custom validation, imports, patching, and integrations.

### Generate a security policy

The command uses existing Codex credentials and the Codex Security default model and effort.
Use `--model` and `--effort` to override them. Model selection runs with tools and
network access disabled. Exit code `0` includes successful recommendations and
abstentions; `2` means invalid input or at least one failed recommendation. A
per-finding failure retains the other results in the report. Cancellation uses
exit code `130` for SIGINT or `143` for SIGTERM.

The SDK accepts finding IDs, titles, summaries, and source locations directly:

```ts
import { suggestOwners } from "@openai/codex-security";

const owners = await suggestOwners("/path/to/repo", result.findings, {
  reasoningEffort: "high",
});
```

SDK inputs may include `sourceRevision`. If it differs from `HEAD`, the collector
ignores the old line ranges and reports the mismatch. Reports record the analyzed
revision, model, effort, and limitations; they remain separate from scan artifacts.

### Feedback

Send a problem report to OpenAI and share the returned feedback ID with support:

```sh
codex-security feedback --reason "The scan stopped before it finished"
codex-security feedback SCAN_ID --reason "The scan stopped before it finished" --include-logs
```

Without an ID, `feedback` selects the most recently started scan in the current
repository, including active or failed scans. If there are no saved scans, it sends
a general report. The report includes your description, version details, and the selected
scan and session IDs. Add `--json` for structured output.

Logs are off by default. `--include-logs` uploads Codex diagnostics and saved scan
and worker activity. These can contain source code, prompts, findings, tool
output, and other sensitive data. Only include logs you can share with OpenAI.
The command uses Codex's feedback service and respects `feedback.enabled = false`.

For scans started through the Desktop plugin, run the command on the machine
where the scan ran, using the same Codex home and Codex Security state directory.
It searches active and archived sessions in both that Codex home and the CLI's
managed home, and attaches available worker logs even if the parent log is missing.
Earlier retries that started separate sessions may be missing when their session
IDs are no longer recorded.

Standard scans run inside an existing Codex conversation attach only the owner's
saved session; they do not record which subagents belong to the scan. Deep Scans
and scans launched by `codex-security` also attach their recorded execution
threads and descendants, without following unrelated children of the owner.

### Scan history and reruns

Commands default to the current repository. Select scans by full ID or a
unique prefix of at least eight characters.

New recipes retain resolved settings and the authentication choice, not
credentials. Reruns do not reload project files; complete saved deep settings do
not use current legacy defaults. Older partial recipes retain their previous
fallback behavior. Context paths and the current checkout are not immutable input
snapshots.

Reruns require replacement scan instructions when the original scan used them.
New recipes mark this requirement, and `scans rerun` refuses to omit them silently; use
`scans rerun [SCAN_ID] --scan-prompt-file FILE` to supply a nonempty replacement.
Replacement files resolve from the invocation directory. Custom validation keeps its existing
`scans rerun --validation-prompt-file` requirement.

| Command                                               | Purpose                                                                                                     |
| ----------------------------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| `scans list [REPOSITORY]`                             | List scans. Filter by artifact root with `--scan-root DIR`.                                                 |
| `scans show [SCAN_ID]`                                | Show a scan; defaults to the latest completed one. `--show-linked-findings` includes earlier finding links. |
| `scans logs [SCAN_ID]`                                | Show session events; defaults to the latest scan, including active scans.                                   |
| `scans resume SCAN_ID`                                | Resume saved Deep Scan work in its original output directory.                                               |
| `scans rerun [SCAN_ID]`                               | Repeat a scan on the current checkout; defaults to the latest completed scan.                               |
| `scans match BEFORE AFTER`                            | Link findings with the same root cause.                                                                     |
| `scans match --all`                                   | Match completed scans across the repository's worktrees and clones.                                         |
| `scans compare [BEFORE] [AFTER]`                      | Compare scans; defaults to the latest two completed scans.                                                  |
| `findings list [REPOSITORY]`                          | List open findings. `findings` is an alias.                                                                 |
| `findings false-positive OCCURRENCE_ID --reason TEXT` | Mark a false positive. Later scans dismiss matches only while the reason applies.                           |

#### Resuming an interrupted Deep Scan

After the CLI process or host stops unexpectedly, find the scan and rejoin it:

```bash
cs policy . --path services/api
```

The scan must still be `running`, with its original checkout, output directory,
and Codex Security state directory available.
The checkout's identity, revision, and contents must match the saved target.
Completed, failed, and canceled scans cannot resume; `scans rerun` starts a new scan.

Resume uses the saved configuration and instructions with the installed plugin.
New scans save the selected authentication mode, explicit safety identifier, and
post-scan prompt contents. Resume restores the authentication choice without
saving credentials. Single-scan resume restores the prompt even if its original
file changes or disappears.
Older records that did not save these values cannot reconstruct them. Bulk
recovery still requires matching campaign inputs and options; it uses the supplied
post-scan prompt when the scan has no saved prompt.
It keeps the scan ID, completed workers, artifacts, and accumulated session cost.
If discovery finished before the interruption, resume completes and seals the
same scan. No archiving or new attempt directory is needed. A failed connection
leaves the existing scan available for another resume attempt.

Compatible saved scans can resume after a plugin update. Unsealed scans from the
retired Deep Scan runtime cannot resume; start a fresh scan instead. Saved drafts
must match the current schema. Recover unfinished worker or reducer fragments
from that runtime with the prior release; the current runtime reads parent drafts
and ordinary scan checkpoints. Existing report files remain available, and
rejecting a failed or canceled checkpoint leaves its saved accounting unchanged.
Historical checkpoints without a pending checkpoint index are no longer imported
automatically into unfinished scans. Use the prior release to finish those scans,
or start a fresh scan; completed reports remain readable.
Older unreleased builds identified child scans by their artifact paths. That
state is no longer migrated; start fresh scans for those database snapshots.
Existing report files remain available.
Already-sealed results
keep their original producer version and contents when completion is recorded.
Unsupported or invalid sealed artifacts are rejected before resuming, preserving
the saved scan state and files.

For bulk campaigns, use [`bulk-scan --recover`](#recovering-failed-or-interrupted-bulk-scans)
to recover eligible attempts and update `results.jsonl`. Individual `scans resume`
does not update campaign receipts.

#### Matching saved scans

Matching requires sealed artifacts and reuses saved matches unless you pass
`--force`. Comparisons classify findings as new, persisting, reopened, resolved,
or unknown. Missing findings aren't resolved if the later scan is incomplete
or excludes their original scope. With one ID, `scans compare` compares it
to the latest completed scan.

Use `scans match --all --force` to rebuild comparisons chronologically while
retaining stable finding identities. Ctrl-C keeps comparisons already saved.
Only high-confidence duplicates are grouped; uncertain and independently
related findings stay separate. Matching preserves triage and sealed artifacts.

Codex runs only for new matching decisions, using existing authentication.
`scans match` and `scans compare` accept `--model` and `--effort`; the defaults
are Codex's configured model and `medium` effort. Cached matches are reused
even when these flags change. To recompute all matches:

```bash
npx @openai/codex-security scans match --all --force \
  --model gpt-6.1-sol --effort high
```

Scans without sealed artifacts are skipped, but their confirmed links can still
be reused. Older custom plugins save confirmed and uncertain matches; use the
bundled plugin for related links and large comparisons.

SDK callers can compare findings without saving a workbench comparison:

```ts
import { readFile } from "node:fs/promises";
import {
  matchScanFindings,
  type FindingsDocument,
} from "@openai/codex-security";

const before = JSON.parse(
  await readFile("/path/to/earlier-scan/findings.json", "utf8"),
) as FindingsDocument;
const after = JSON.parse(
  await readFile("/path/to/later-scan/findings.json", "utf8"),
) as FindingsDocument;

const comparison = await matchScanFindings(
  { before: before.findings, after: after.findings },
  { workingDirectory: "/path/to/repository" },
);
console.log(comparison.matches, comparison.uncertain, comparison.related ?? []);
```

Pass `knownFindingGroups` to reuse confirmed groups of stable `findingId` values
from your store. Results identify the original `occurrenceId` values. Options
include model, reasoning effort, `AbortSignal`, and an optional `onProgress`
callback whose errors do not interrupt matching.

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

Export saved findings or a threat model without starting another analysis:

```bash
cs export --scan SCAN_ID --export-format sarif --output results.sarif
cs export --scan SCAN_ID --artifact threat-model --output threatmodel.md
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

## Findings storage and deduplication

Saved-scan deduplication uses local SQLite directly:

```bash
cs dedupe --scan SCAN_ID --json
```

The [findings guide](docs/findings-service.md) covers local storage, embedding
credentials, deduplication, backups, and independently operated HTTP endpoints.
The local `serve` command and browser dashboard have been removed. Existing
scans, findings, and duplicate groups remain in the workbench database.
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
Host and network restrictions still apply.

Repository contents, model output, and imported artifacts do not authorize
access to other targets, disclosure of credentials, or writes outside approved
paths. Keep state and scan artifacts private and outside the repository.

## Documentation and security

- [Online SDK guide](https://learn.chatgpt.com/docs/security/sdk)
- [CLI reference](docs/cli.md)
- [Findings guide](docs/findings-service.md)
- [GitHub issues](https://github.com/openai/codex-security/issues) for bugs and feature requests
- [Security policy](https://github.com/openai/codex-security/blob/main/SECURITY.md) for private vulnerability reporting
