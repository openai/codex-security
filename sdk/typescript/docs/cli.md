# CLI and workflows

Use `npx @openai/codex-security` without a global install. The examples below
use `codex-security`, which is available after
`npm install --global @openai/codex-security`.

```bash
codex-security --help
codex-security scan --help
codex-security --version
codex-security info --json
```

`--help` lists commands by task; `<command> --help` lists its options.
`info --json` reports package, plugin, runtime, and model details.
`scans` and `findings` default to their `list` subcommands.

## Authentication

Sign in with ChatGPT, or supply an API key for CI:

```bash
codex-security login
codex-security scan .

# Save an API key from the environment.
printenv OPENAI_API_KEY | codex-security login --with-api-key
```

`OPENAI_API_KEY` and `CODEX_API_KEY` also work without saving a login.
Environment keys apply to the current command; only `login --with-api-key`
saves them. `login --with-access-token` accepts a Codex access token on stdin.
Access-token environment variables are not scan API keys.

On remote or headless machines, use `login --device-auth` if your workspace
allows it. If device auth is disabled, use SSH forwarding below.

On Windows, set a key in PowerShell:

```powershell
$env:OPENAI_API_KEY = "<your-api-key>"
codex-security scan C:\code\repository
```

### Remote login with SSH forwarding

On your local machine, open a tunnel to the remote host:

```bash
ssh -L 1455:localhost:1455 user@remote-host
```

Run `codex-security login` in that SSH session and open its sign-in URL in
your local browser. Keep SSH connected until login finishes.

### OpenAI credentials

Interactive scans ask which credentials to use when both ChatGPT and an
environment API key are available. Noninteractive commands prefer
`OPENAI_API_KEY`, then `CODEX_API_KEY`, then stored credentials. Choose explicitly
with `--auth`:

```bash
codex-security scan . --auth chatgpt
codex-security scan . --auth api-key
codex-security patch OCCURRENCE_ID --auth chatgpt
codex-security verify-fix OCCURRENCE_ID --auth api-key
```

`--auth chatgpt` ignores environment API keys. `--auth api-key` requires a key.
The default is `auto`. Scans, validation, patching, and fix verification share
the stored login. Patch follow-up assessments and `scan --patch` retain the
chosen authentication. Environment keys do not replace the saved login.
The SDK uses `auth` on `run()`, `validate()`, and `preflight()`.

Stored OpenAI credentials live in
`$CODEX_SECURITY_STATE_DIR/codex-home`, or
`$CODEX_HOME/state/plugins/codex-security/codex-home`. Keep this private home
outside the target and every enclosing Git worktree. It also serves providers
with `requires_openai_auth = true`.

Codex carries credential-storage, forced-login, and workspace settings from the
ambient configuration into this home. Managed-device policies still apply;
workspace-managed policies may require ChatGPT credentials even with an API key.
If the home has no credentials, it imports an existing file-based Codex login.
Logout disables imports until the next login.

If credentials cannot refresh, run `login status`. Retry if the sign-in recently
changed; otherwise run `logout`, then `login`.
Some cybersecurity requests and protected findings require
[Trusted Access for Cyber](https://chatgpt.com/cyber).

### Select a Cyber access program

For the built-in OpenAI provider, choose `standard`, `daybreak_blue`, or
`daybreak_red`:

```bash
codex-security scan . --auth api-key --cyber-access-program daybreak_blue
```

```ts
await security.run("/path/to/repository", {
  auth: "api-key",
  cyberAccessProgram: "daybreak_blue",
});
```

`scan-components` accepts the same flag. Project files use
`scan.cyber_access_program`, including for bulk scans. Explicit CLI or SDK values
override the file; omission preserves Codex defaults. `standard` explicitly
selects the standard program.

The selection applies to workers, resumed scans, planning, matching, and scan
follow-ups. Recipes retain it for resume and rerun. API-key selection enables
Codex's experimental Cyber support unless native configuration explicitly disables
`features.api_key_cyber_access_programs`. A selection does not grant entitlement;
explicit disables and access denials remain errors.

### Native command authentication and other providers

SDK callers can select a native command provider through
`codexOverrides.model_providers.<id>.auth` and `model_provider`, including a
selected profile. Codex runs the credential helper and renews its token. Scans,
comparisons, and deduplication preserve that selection. Relative helper paths and
`auth.cwd` resolve from `CODEX_HOME` (default `~/.codex`). Comparisons and reviews
also honor the selected command provider in that home's `config.toml`.

For other providers, set their key and select a model the provider supports:

```bash
export OPENROUTER_API_KEY="<your-openrouter-api-key>"
codex-security scan . --provider openrouter --model anthropic/claude-sonnet-4.5

export FIREWORKS_API_KEY="<your-fireworks-api-key>"
codex-security scan . --provider fireworks --model accounts/fireworks/models/qwen3-235b-a22b
```

### Amazon Bedrock

Use AWS credentials and a region with access to the exact Bedrock model ID:

```bash
export AWS_PROFILE="security-scan"
export AWS_REGION="us-east-2"
codex-security scan . --provider amazon-bedrock --model openai.gpt-5.6-luna
```

Run credential setup and the scan in the same shell or job. Bedrock scanning
uses AWS authentication, including in Deep Scan workers; it does not need an
OpenAI API key or separate CLI login. Publishing to Cloud requires separate
ChatGPT credentials. `info` and `--dry-run` do not verify AWS access.

See the [Bedrock guide](https://github.com/openai/codex-security/blob/main/docs/bedrock.md)
for credential alternatives, restricted-model access, cost estimates, and
reasoning-summary configuration.

## Generate a security policy

`policy` drafts `SECURITY.md` guidance for later scans. Review the draft before
copying it into the checkout; the command saves it outside the repository.

```bash
codex-security policy .
codex-security policy . --path services/api
codex-security policy . --knowledge-base architecture.md --model gpt-5.6-terra --effort high
codex-security policy . --dry-run --json
```

The repository defaults to the current directory. `--path` selects a component,
which inherits policies from its Git root, with the closest policy taking
precedence. Targets and links stay within the checkout and outside Git metadata.
Inherited policies may refer to ancestor `SECURITY.md` files or the checkout's
`.github/SECURITY.md` and `docs/SECURITY.md`; they cannot widen a component's scope.
Linked worktrees and initialized submodules use their own roots. For a separate
Git directory, set `core.worktree` to the checkout's absolute path; use
`git worktree repair` for moved linked worktrees.

Generation describes the system, builds a threat model, then drafts the policy.
In a terminal it asks about facts the source cannot establish and previews the
diff. `--headless` skips questions; unanswered questions remain in review notes.
The command uses scan authentication and read-only access to the selected source.
It denies Git metadata and sibling-component access, disables network, web, apps,
and MCP, and uses only Codex's core shell environment. Knowledge-base text stays
in private review artifacts during generation and is removed afterward.

| Invocation                   | Result                                                    |
| ---------------------------- | --------------------------------------------------------- |
| `policy .`                   | Generate documents, ask questions, and preview the draft. |
| `policy . --headless --json` | Generate without prompts; return paths and review notes.  |
| `policy . --format md`       | Generate and write the draft to stdout.                   |
| `policy . --dry-run --json`  | Check local inputs without calling Codex.                 |

Generation currently fails on Unix directories with non-UTF-8 names. On macOS,
the bundled runtime does not fully enforce write restrictions under `/tmp`
(including `/private/tmp`); keep source and artifacts elsewhere when read-only
enforcement is required. See the
[upstream sandbox issue](https://github.com/openai/codex/issues/32395).

### Review the draft

Preserve reporting instructions and obtain owner approval for exclusions,
accepted risks, and severity decisions. Check linked `.github/SECURITY.md` and
`docs/SECURITY.md` files: installing the draft can affect their guidance too.
Regenerate if relevant source or neighboring policies changed during generation.

Use an empty output directory outside every enclosing checkout and its Git
metadata, or keep the default location in the Codex Security state directory:

```bash
codex-security policy . --path services/api --headless \
  --output-dir /path/outside/repository/api-policy --json
```

| Artifact               | Contents                                        |
| ---------------------- | ----------------------------------------------- |
| `SECURITY.md`          | Policy draft.                                   |
| `threatmodel.md`       | Threat model with source references.            |
| `project-spec.md`      | System description and security boundaries.     |
| `previous-SECURITY.md` | Original policy used for the diff.              |
| `policy-draft.json`    | Target, hashes, stage status, and review notes. |

Keep supporting documents private until reviewed for disclosure. If governing
policies change during generation, the documents remain for inspection but no
completed-draft manifest is written. A preview failure reports saved paths.

`--max-cost` applies to the whole generation. Progress goes to stderr;
`--json` includes status and estimated cost. `--full-output` reports failures
with `ok: false`. If a stage cannot inspect required evidence, generation stops
and keeps completed documents. Fix the problem and retry in a new directory.

### Generate a policy from TypeScript

```ts
import { CodexSecurity } from "@openai/codex-security";

const security = new CodexSecurity();
try {
  const draft = await security.generatePolicy("/path/to/repository", {
    path: "services/api",
    knowledgeBasePaths: ["/path/to/architecture.md"],
    onStage: (stage) => console.error(stage),
  });
  console.log(await security.previewPolicy(draft));
  // Review the saved policy at draft.draftPath before installing it.
} finally {
  await security.close();
}
```

`preflightPolicy()` checks local inputs. `previewPolicy()` previews the supplied
in-memory draft and escapes terminal controls; editing its saved file does not
change that object. `securityPolicyDiff()` returns a raw diff for files and other
non-terminal uses, with an optional Python interpreter.

`generatePolicy()` accepts `auth`, `path`, `knowledgeBasePaths`, `outputDir`,
`maxCostUsd`, `signal`, and progress/cost callbacks. `answerQuestions` receives
groups of up to three owner questions and a cancellation signal. Without the
callback, questions remain unresolved.

## Scan options and output

```bash
codex-security scan .
codex-security scan . --path src --path tests
codex-security scan . --diff origin/main --json
codex-security scan . --working-tree
codex-security scan . --output-dir /path/outside/repository/results --dry-run
```

`--diff` scans committed changes; `--working-tree` scans staged and unstaged
changes. Deep scans support whole repositories and path scopes. Working-tree
snapshots include untracked nested Git repositories. Initialized submodules must
be clean and at the commit recorded by the parent.

Repeat `--knowledge-base PATH` for context: UTF-8 text files (including JSON and
SARIF), PDF, DOCX, or directories. Directory traversal skips other binary files;
explicit unsupported binary files are rejected. Bulk scans share this context
with every repository.

Output directories must be empty and outside the scanned directory and enclosing
Git worktree. On macOS/Linux, existing directories must be private (`chmod 700`).
`--archive-existing` moves earlier output to
`<output-dir>.previous-<timestamp>-<id>`; `--dry-run` previews the move.
SARIF, when produced, is saved at `<scan-dir>/exports/results.sarif`.

Scans are report-only by default. `--fail-on-severity high` exits with `1` for
high or critical findings. Incomplete scans exit with `2`, returning available
results and a coverage warning. `scan`, `scans rerun`, and `scans resume`
execution failures with `--json`, JSON, or JSONL output produce:

```json
{ "status": "failed", "code": "SCAN_FAILED", "message": "..." }
```

With `--full-output`, the error appears under `error` in an `ok: false` envelope.
Saved-scan setup failures use the same output shape with
`SCAN_REPLAY_UNAVAILABLE` for `scans rerun` (including when no completed scan is
available) or `SCAN_RESUME_UNAVAILABLE` for `scans resume`. Rerunning an imported
scan uses `SCAN_IMPORT_FAILED` if the import fails. Other output formats retain
stderr-only failures, including when `--full-output` is selected.

Diagnostics stay on stderr. Each command's `--schema --format json` describes
its successful output and failure codes.
See [Exports and CI](#exports-and-ci) for exit codes and CI examples.

### Project files

```bash
codex-security init
codex-security scan . -c codex-security.yaml --dry-run --json
codex-security info -c codex-security.yaml --json
```

Select a YAML or JSON file with `-c`, or set `CODEX_SECURITY_PROJECT_CONFIG`.
Explicit `-c` wins. Without either, no file is discovered. `scan`, `bulk-scan`,
`scan-components`, and `info` accept project files. SDK calls and saved reruns
do not load them automatically.

Treat the selected file as trusted operator configuration: native settings can
start MCP processes and choose model-service destinations. Keep CI scanner
configuration outside the untrusted checkout being assessed.

See [Project configuration](https://github.com/openai/codex-security/blob/main/docs/project-configuration.md)
for settings, precedence, paths, schemas, and SDK loading. File paths resolve
from the config directory; scope paths resolve from the repository.

### Import findings as a saved scan

```bash
codex-security scan import --csv /path/to/findings.csv
codex-security scan import --json /path/to/findings.json --format json
codex-security scan import --csv /path/to/findings.csv --dry-run
```

Supply exactly one input. CSV follows the
[findings template](https://github.com/openai/codex-security/blob/main/examples/findings.csv).
JSON accepts a complete `codex-security.findings` document or
`{ "findings": [...] }` matching the findings schema. For this command, `--json`
selects the input file; use `--format json` for JSON output. The input must be a
regular file with no symlinks or directory junctions in its path.

Each import creates a completed scan in local history, retains the input under
`artifacts/import/`, and preserves each occurrence, including duplicates.
Original identifiers live in `extensions.import`; referenced writeup paths are
metadata only. Completion means import finished; no security analysis occurred.
Import needs no model calls or authentication. `--dry-run` validates without
saving; `--output-dir` and `--archive-existing` control output. `scans rerun`
reimports the retained input.

### Generate mock scan results

```bash
codex-security scan /path/to/repository --mock
```

The SDK equivalent is `security.run(repository, { mock: true })`. Mock scans
save synthetic results through the normal reporting and history flow without
model calls or authentication. Each contains 12 findings: eight stable across
runs, four with new identities, and two duplicate pairs for testing deduplication.
Paths and snippets are fictional; repository files remain unchanged.

Use a separate `CODEX_SECURITY_STATE_DIR` for disposable data. Output, exports,
archiving, and severity thresholds work normally. Reruns preserve mock mode.
Separate matching or deduplication commands still make their usual model calls.

Mock mode supports Standard repository, path, and diff scans. It cannot combine
with `--dry-run`, `--patch`, Deep mode, custom validation, or post-scan prompts.
Scan prompts and knowledge bases do not change the fixtures.

### Attribute scans to end users

Pass a stable hashed ID when scanning on behalf of users:

```bash
codex-security scan . --auth api-key --safety-identifier hashed-user-id
```

```ts
await security.run("/path/to/repository", {
  auth: "api-key",
  safetyIdentifier: hashedUserId,
});
```

Use 1–64 characters, with no NUL or personal data such as email addresses.
The ID applies to workers, retries, and follow-ups. Supply it again for reruns.

The bundled runtime does not yet support native `--safety-identifier`; select a
compatible build with `CODEX_CLI_PATH` and a plugin that forwards it to workers.
The SDK checks the format, not runtime/plugin compatibility. Older versions may
omit the ID.

### Scan project components

`scan --path` runs one scan over selected paths. `scan-components` runs a separate
scan for each component:

```bash
codex-security scan-components /path/to/project \
  --component apps/api --component apps/web --component packages/shared \
  --workers 4 --output-dir /path/outside/project/results
```

Use `-c FILE` to share scan settings, including Deep mode, context, cost limits,
and severity policy. Component plans override the file's scope. Use `--auto` to
propose a split, then review the saved plan:

```bash
codex-security scan-components . --auto --plan-only \
  --output-dir /path/outside/project/plan
codex-security scan-components . \
  --components-file /path/outside/project/plan/components.json \
  --output-dir /path/outside/project/results
```

Plans use repository-relative paths:

```json
{
  "components": [
    { "name": "API", "paths": ["apps/api", "packages/auth"] },
    { "name": "Web", "paths": ["apps/web"] }
  ]
}
```

Automatic planning respects Git ignore rules and includes omitted inventory
files in `Other files` components. Large inventories require multiple planning
calls and may produce more components. Planning leaves source unchanged.

Each component saves artifacts under `component-N/`. Combined `findings.json`
groups high-confidence root-cause matches, keeping original IDs and the highest
severity. Uncertain matches stay separate. `summary.json` records coverage and
matching status; `report.md` links to component reports. Export or publish each
individual scan folder.

Failures do not stop other components. Failed scans, incomplete coverage, or
failed matching return `2`; severity-policy violations return `1`. Retry with
`--components-file retry-components.json` and a new empty output directory.
The retry report covers only those components.

`--max-cost` applies per component, excluding planning and matching. `--model`
and `--effort` also apply to matching; `--auth` applies throughout. Planning and
matching reject ambient command providers that conflict with explicit ChatGPT
or API-key auth. SDK-selected command providers retain their authentication.

From TypeScript, use `runComponentScans({ repository, outputDir, components })`.
Use `auto: true`, `planOnly: true`, and `scanOptions.auth` for the corresponding
planning and authentication choices.

### Configure deep scans

```ts
await security.run("/path/to/repository", {
  mode: "deep",
  workers: 2,
  subagents: 0,
  stopAfterNoNew: 3,
  stopAfterConsecutiveErrors: 2,
  maxDiscoveryRuns: 10,
  maxTimeHours: 1.5,
});
```

For `scan --mode deep`, `--workers` controls discovery concurrency and
`--subagents` controls subagents per worker. `--stop-after-no-new`,
`--max-discovery-runs`, and `--max-time-hours` stop discovery by novelty, count,
or duration. At the deadline, discovery stops; the scan then combines and returns
completed findings.

Use project-file `scan.deep` settings or legacy
`$CODEX_HOME/codex-security/config.toml` defaults. Counts must be positive except
that `subagents` can be zero. Time accepts positive fractional hours up to 96.
`stopAfterConsecutiveErrors` is an SDK/project-file setting, with no CLI flag.
`--codex` does not configure deep-scan settings. See
[Deep settings and limits](https://github.com/openai/codex-security/blob/main/docs/project-configuration.md#deep-settings-and-limits).

`bulk-scan --workers` controls concurrent repositories; `scan --workers` controls
workers within one Deep Scan. New recipes save all resolved deep settings so
resume and rerun do not depend on later changes to legacy defaults.

### Runtime configuration and worker limits

Scans use an isolated Codex configuration. The default model and effort are
`gpt-5.6-sol` and `xhigh`. Multi-agent v2 allows nine concurrent threads: the
parent and up to eight delegated workers. That limit is separate from Deep Scan
and bulk worker counts.

```bash
codex-security scan . --model gpt-6.1-sol --effort high \
  --codex features.multi_agent_v2.max_concurrent_threads_per_session=4
```

Model IDs and `--effort` values pass through to Codex unchanged, including values
such as `minimal`, `none`, and `high`. Supported combinations depend on the model,
provider, Codex version, and credentials. Codex and provider errors are reported
without substituting another model or effort.
The flags also work with bulk/component scans, policy, validation, patching,
verification, owner suggestions, severity classification, and scan matching.
Matching and severity classification default to Codex's configured model and
`medium` effort. `dedupe` has separate screening and review models.

Repeat `--codex KEY=VALUE` for supported native settings. Quote strings as TOML:
`--codex 'model_reasoning_effort="high"'`. Repeated or conflicting keys are
rejected, including a `--model` or `--effort` flag plus its native equivalent.
Choose plugins with `--plugin-path`; native plugin and marketplace overrides are
rejected. Multi-agent v2 must remain enabled; `agents.max_threads` is unsupported.

`validate`, `patch`, and `verify-fix` limit native overrides to `model`,
`model_reasoning_effort`, `model_provider`, `model_providers`, and
`analytics.enabled`. For a custom provider:

```bash
codex-security patch "Security issue" --model gateway-model \
  --codex 'model_provider="gateway"' \
  --codex 'model_providers.gateway.name="Gateway"' \
  --codex 'model_providers.gateway.base_url="https://gateway.example.test/v1"' \
  --codex 'model_providers.gateway.wire_api="responses"' \
  --codex 'model_providers.gateway.env_key="GATEWAY_API_KEY"'
```

Set the provider's key environment variable before running. Patching and
verification preserve unspecified provider settings from Codex configuration.
With `auto` or `api-key`, the provider's `env_key` takes precedence over OpenAI
account authentication. Explicit `--auth chatgpt` selects stored account auth,
omits the provider key, and clears any configured experimental bearer token for
that command. Model, effort, and provider choices carry into patch-risk assessment.

Disable Codex usage analytics and built-in metrics with
`--codex 'analytics.enabled=false'`. The setting carries into `scan --patch`
and patch-risk assessment. It does not control configured OpenTelemetry exporters,
integrations, authentication, or CLI update checks. Validation uses isolated
configuration; patching and verification preserve ambient project trust.

For filesystem and approval behavior, see the
[local security model](../README.md#local-security-model).

### Environment variables

| Variable                                                                    | Effect                                                             |
| --------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| `OPENAI_API_KEY`, `CODEX_API_KEY`                                           | Scan credentials; the first takes precedence.                      |
| `CODEX_SECURITY_STATE_DIR`                                                  | Private history, database, and default artifacts.                  |
| `CODEX_SECURITY_PROJECT_CONFIG`                                             | Selected project file; `-c` overrides it.                          |
| `CODEX_HOME`                                                                | Ambient Codex home; default `~/.codex`.                            |
| `CODEX_CLI_PATH`                                                            | Codex executable for login, setup, scans, and workers.             |
| `PYTHON`                                                                    | Python interpreter unless an explicit option overrides it.         |
| `CODEX_SECURITY_LOG_LEVEL`                                                  | CLI diagnostics; `debug` enables verbose output.                   |
| `LOG_LEVEL`                                                                 | Fallback if `CODEX_SECURITY_LOG_LEVEL` is unset or blank.          |
| `CODEX_SECURITY_LINEAR_TEAM`, `CODEX_SECURITY_LINEAR_PROJECT`               | Default publication destination.                                   |
| `CODEX_SECURITY_LINEAR_API_KEY`                                             | Linear personal API key.                                           |
| `CODEX_SECURITY_EMBEDDINGS_URL`                                             | Findings service embeddings endpoint.                              |
| `GH_HOST`                                                                   | GitHub Enterprise host for bulk discovery.                         |
| `CODEX_SECURITY_NO_UPDATE_NOTICE`, `NO_UPDATE_NOTIFIER`                     | Disable interactive update notices.                                |
| `CODEX_SECURITY_NPM_REGISTRY`, `npm_config_registry`, `NPM_CONFIG_REGISTRY` | Update registry, in precedence order.                              |
| `CI`                                                                        | Disable interactive update notices.                                |
| `NO_COLOR`, `TERM`                                                          | Disable colored history when `NO_COLOR` is defined or `TERM=dumb`. |

Custom Codex executables need thread source attribution for `exec` and
`app-server` (Codex 0.149.1+). On Windows, use a native `.exe` or `.com`;
command shims such as `codex.cmd` fall back to the bundled executable.

Python lookup: `--python` on commands that expose interpreter selection or SDK
`pythonPath`, then
`PYTHON`, the managed runtime, and `python3` or `python` on `PATH` (`py` also
works on Windows). `CODEX_SECURITY_STATE_DIR` overrides `CODEX_HOME` for storage.

### Troubleshooting

Use `--verbose` or `CODEX_SECURITY_LOG_LEVEL=debug` for lifecycle, configuration,
retry, and worker diagnostics on stderr. Diagnostic text is preserved in output,
saved failures, receipts, and patch-risk summaries. Review it for sensitive
information before sharing; upstream Codex output may already be redacted.

Keep state and reports when recovering authentication or locking problems.
Finish older-version operations before upgrading. Never remove
`.codex-security-scan.sqlite3` during an operation. Stop all operations using the
credential home before manually removing an old `.codex-security-scan.lock`.

On Windows, an older sandboxed run can leave invalid ACLs on a credential-home
ancestor. Preserve that state, then select a new private `CODEX_SECURITY_STATE_DIR`
outside the old state and repository. Sign in again if needed; the new directory
has separate scan history.

### Progress and cost

Interactive scans show full-screen progress. CI, redirected output, `--headless`,
and `--verbose` use plain status lines. Results go to stdout; progress and
diagnostics go to stderr. Press `d` in the dashboard for details, then `a` for
all sources, `m` for the main scan, or `1`–`9` for a worker.

Token totals include input plus output; cache reads and writes are subsets of
input. Missing cache-write usage makes the uncached/cache-write breakdown
unavailable. The CLI cannot recover missing information already recorded as zero
by the runtime.

Cost displays use [standard API prices](https://developers.openai.com/api/docs/pricing)
and show a short/long-context range. They estimate model usage, excluding other
tiers, fees, surcharges, and account-specific pricing. They do not measure ChatGPT
subscription allowance. Models without known prices have no estimate.

JSON, history, and bulk receipts include `cost.estimatedUsdRange` (`min`, `max`,
and `context: "unknown"`). A null maximum means no upper estimate is available.
`cost.pricing` records source, verification date, tier, and rates. Older results
keep their legacy estimates. `cost.estimatedUsd` is the short-context baseline
used for spending limits; use the range for reporting. Missing cache-write usage
is recorded by `cacheWriteInputTokensReported: false`.

`--max-cost USD` stops the scan and workers after estimated cost exceeds the
limit; in-flight requests can finish above it. Bulk limits apply per repository
attempt. Post-scan prompts run after cost tracking and are outside this limit.
Automatic history matching gets at most one extra call with a limit; if more
work is needed, the scan is preserved and you can run `scans match --all`.

When Deep discovery has finished at a cost stop, the scan returns a sealed
partial report and lists unvalidated candidates as follow-up work.

At 80% of a single interactive scan's limit, the dashboard offers a higher total
budget. Enter a larger total, or leave it blank/press Escape to keep the limit.
Work continues while you decide; the old limit remains active until saved.
CI, JSON/JSONL, headless, and verbose scans do not offer increases.

SDK callers can use `onBudgetApproaching({ maxCostUsd, cost, signal })`, returning
a larger total or `undefined`. It runs once per limit without blocking the scan.
Late responses after cancellation/completion are ignored; invalid increases or
save failures keep the existing limit. `onCost(cost, maxCostUsd)` reports changes.

## Bulk scans

Run `gh auth login`, then `codex-security bulk-scan` for interactive GitHub
selection. It lists repositories pushed in the last 90 days, excluding forks
and archives, asks for output, and saves the selection as `repositories.csv`.
Private checkouts use your GitHub CLI login.

For CI, provide CSV with `id`, `repository`, and a full commit `revision`.
Optional `scope`, `mode`, and `prompt` customize each row:

```csv
id,repository,revision,scope,mode,prompt
service,https://github.com/example/service.git,0123456789abcdef0123456789abcdef01234567,src,standard,Review authentication and authorization.
```

```bash
codex-security bulk-scan repositories.csv \
  --output-dir /path/outside/repositories/results --workers 4
```

Bulk scans use clean shallow checkouts and support repository/path scopes.
Configured diff or working-tree scopes are rejected unless every affected row
overrides them with a path scope. `--output-dir` requires CSV input.

Use `-c FILE` for shared settings; CSV mode/scope override file values.
`--scan-prompt-file` adds shared instructions before each row's prompt.
`--post-scan-prompt-file` runs a follow-up even after failure or incomplete
coverage, but not after cancellation or a cost stop.

Concurrency defaults to four repositories. `--max-attempts` defaults to one
attempt per pending repository per invocation. Repeating the command continues
the campaign, skips completed results, and starts pending attempts. Occupied
attempt directories stop that repository and suggest `--recover`.
Changed project configuration requires a new output directory.

### Recovering failed or interrupted bulk scans

Use the original CSV, output directory, and options:

```bash
codex-security bulk-scan repositories.csv \
  --output-dir /path/outside/repositories/results --recover
```

Recovery requires a matching campaign manifest. It skips completed results
(including partial coverage) and repositories never started. For each latest
failed or interrupted attempt:

- A sealed scan is recorded in `results.jsonl` without scanning again.
- An eligible running Deep Scan resumes its original session, keeping its ID,
  workers, artifacts, settings, and accumulated cost.
- An unavailable, failed, or canceled scan starts a new attempt at the pinned
  revision, preserving old artifacts and checkouts.

New attempts use `recovery-checkouts/<id>/attempt-<n>`. Recovery defaults to four
workers and one recovery/new attempt per repository. A resume connection failure
stops only that repository for this invocation. Failed recovery checkouts remain;
fresh completed checkouts are removed after recording their result.

Same-scan resume needs the original checkout, session logs, and state directory.
Recovery cannot reconstruct deleted checkpoints or fix execution failures.
New attempts incur new costs. Remaining failures or partial coverage return `2`;
completed severity-policy violations return `1` without retrying the scan.

## Custom validation

Replace the final validation step of a Standard or diff scan with a prompt:

```bash
codex-security scan . --validation-prompt-file validation.md
```

```ts
const result = await security.run(repository, {
  validationPrompt:
    "Run scripts/validate.sh, test each candidate through the local API, and stop the test environment when finished.",
});
```

Source review still runs; discovery workers do not receive this prompt. Include
setup, authorized targets, required evidence, and cleanup. Use environment
variables for credentials. Deep scans reject custom validation; scans with no
candidates skip it. The SDK also accepts `validationPromptFile`.

The model must return a `CustomValidationResult` with one entry per candidate:

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

Dispositions are `reportable`, `suppressed`, `not_applicable`, or `deferred`.
Set severity/impact to `{ "level": "medium", "rationale": "..." }` to revise
them, or null to retain them. Identity and source locations stay unchanged.

Candidates and results remain under `artifacts/custom-validation/`. Setup
failure, incomplete/invalid output, or any deferred candidate means incomplete
coverage. An incompatible plugin stops the scan. Supply the validation prompt
again when rerunning.

## Publish findings to Cloud

Preview selected completed scans before uploading:

```bash
codex-security publish scan --to cloud --dry-run --json
codex-security publish scan --scan SCAN_ID_A --scan SCAN_ID_B \
  --to cloud --dry-run --json
```

The interactive picker starts with nothing selected; press Space to select and
Enter to submit. Find IDs with `scans list --json`. Select by full ID, unique
prefix of at least eight characters, or `latest` for the current repository.
Local sealed artifacts are required. Dry runs need no login or network access.

Uploads require ChatGPT credentials saved to a file. Set
`cli_auth_credentials_store = "file"` in Codex `config.toml`, then sign in again.
Cloud publication rejects automatic/keyring storage even when `auth.json` exists,
because that file may be stale or belong to another account.

Use a positional scan directory or repeated `--scan-dir PATH` for artifacts
outside history. Each must contain one completed sealed scan, not a bulk-run
directory or `results.jsonl`. Do not mix directories with `--scan`.
Cloud also accepts exported CSV:

```bash
codex-security publish scan --to cloud --csv /path/outside/repository/findings.csv
```

CSV cannot combine with scan selectors. Use the
[CSV template](https://github.com/openai/codex-security/blob/main/examples/findings.csv)
or `export --export-format csv` output.

One scan returns a receipt directly. Multiple scans return `results`, `failed`,
and `notAttempted` arrays. Uploads run sequentially and continue after individual
failures, returning `2` if any fail. Cancellation returns results so far with
`130` (Ctrl-C) or `143` (SIGTERM), unless every upload was already confirmed.

Save receipts: Cloud does not store them in local history. IDs are Cloud finding
IDs in request order. Uploads are not retried automatically. A missing receipt
can still mean the upload succeeded; check Cloud before retrying and do not
resend a confirmed upload.

## Publish completed scans to Linear

```bash
codex-security publish scan --scan SCAN_ID --to linear --linear-team TEAM_ID
```

Select one completed scan by ID, prefix, `latest`, or directory; omit the selector
for the picker. Live publication and `--skip-existing` require local history.
A directory-only dry run does not.

`--linear-project PROJECT_ID` (`--project`) selects a project. Flags override
`CODEX_SECURITY_LINEAR_TEAM` and `CODEX_SECURITY_LINEAR_PROJECT`. `--dry-run`
previews titles offline; `--json` returns structured output.

Sign in to Codex and connect Linear, or set `CODEX_SECURITY_LINEAR_API_KEY` to
use its API directly. Direct API publication leaves issues unassigned unless
`--linear-assignee` gives a user ID or email. Prefer the environment variable
over `--linear-api-key`, which exposes the key in shell history/process listings.
Keys are omitted from saved results; diagnostic messages remain unchanged.

```bash
codex-security publish check /path/to/completed-scan \
  --to linear --linear-team TEAM_ID --json
```

`publish check` verifies artifacts and recorded publications. With an API key,
it also checks authentication and destination access. It does not test issue
creation; connected-app access is reported as `not-checked`.

Each finding becomes an issue with severity, source, evidence, and remediation.
Choose a destination authorized to receive that content. Local history records
successful issue IDs separately from sealed artifacts.

Republishing creates duplicates unless `--skip-existing` finds a recorded success
for that occurrence, team, and project. It does not check remote issues or cover
unrecorded/concurrent publication. After interruption, inspect the handoff,
evidence, and destination before retrying.

```ts
import { publishScan } from "@openai/codex-security";

const publication = await publishScan("/path/to/completed-scan", {
  destination: "linear",
  teamId: "TEAM_ID",
  skipExisting: true,
});
console.log(publication.scanId, publication.created.length);
```

Options also include `projectId`, `linearApiKey`, and `assigneeId` (ID or email).
`checkScanPublication()` takes the same destination options for a read-only check.

## Classify finding severity

Apply a rubric to completed findings without repeating discovery:

```bash
codex-security classify-severity --scan latest --rubric /path/to/policy.md --json
codex-security classify-severity --scan-dir /path/to/completed-scan --json
```

Use exactly one of `--scan` (ID, prefix, or `latest`) and `--scan-dir`.
Omitting `--rubric` inherits original severity without model calls. Rubrics and
repeatable `--knowledge-base` context accept text, PDF, DOCX, and directories.
Each finding is classified in a separate read-only turn using its report and
supplied context, without tools or source inspection. `--model` and `--effort`
override Codex's configured model and the default medium effort.

Assessments contain `decision` (`assessed` or `excluded`), normalized `level`,
the original `rubricLabel`, rationale, confidence, and a `reviewTrigger` for
missing facts that could change the result. Exclusions have a null level.
Finding/occurrence IDs and input hashes bind each assessment to its evidence.

Successful assessments checkpoint immediately in local SQLite. Retries reuse
matching evidence, rubric, and context hashes; failed/canceled runs keep completed
work. Use `--reprocess` to replace assessments, including when changing only model
or effort. A successful run also writes `severity-classification.json`, but
publication reads the database. Original findings and sealed artifacts remain
unchanged.

Repeat `--finding-id ID` for a subset, such as dedupe's `uniqueFindingIds`.
Linear publication defaults to saved classification selection, omits exclusions,
and uses assessed severity for title and priority. Descriptions retain original
severity and add the classification rationale. Publication rejects incomplete or
stale assessments. It never reclassifies or rereads the rubric at publication time.

```bash
codex-security classify-severity --scan SCAN_ID --rubric /path/to/policy.md \
  --finding-id FINDING_ID
codex-security publish scan --scan SCAN_ID --to linear --linear-team TEAM_ID --dry-run
```

Linear publication also accepts `--finding-id`. If a classification exists, every
selected finding needs an assessment. Existing tickets are not changed;
`--skip-existing` preserves recorded tickets and human priority edits.

```ts
import {
  classifySeverity,
  classifyScanSeverity,
  classifyScanDirectorySeverity,
  publishScan,
} from "@openai/codex-security";

// Assess supplied reports in memory.
const classification = await classifySeverity(findings, {
  rubricPath: "/path/to/policy.md",
  knowledgeBasePaths: ["/path/to/context.md"],
});

// Save assessments for a scan ID or sealed directory.
await classifyScanSeverity("SCAN_ID", { rubricPath: "/path/to/policy.md" });
await classifyScanDirectorySeverity(scanDirectory, {
  rubricPath: "/path/to/policy.md",
  findingIds: dedupeResult.uniqueFindingIds,
});

// Or supply an in-memory assessment directly to publication.
await publishScan(scanDirectory, {
  destination: "linear",
  teamId: "TEAM_ID",
  classification,
  findingIds: classification.assessments.map(({ findingId }) => findingId),
  dryRun: true,
});
```

`classifySeverity()` accepts `findingId`, `title`, `summary`, and available
evidence/metadata. Imported reports may lack severity or occurrence IDs; missing
severity requires a rubric. Scan wrappers persist checkpoints (including for
external directories), accept `reprocess: true`, and treat `findingIds: []` as an
empty selection. Use the same `CODEX_SECURITY_STATE_DIR` for classification and
publication. Older JSON-only assessments need reclassification once. All
classification methods accept `signal`; keep human overrides in your workflow.

## Suggest finding owners

```bash
codex-security suggest-owners findings.json --source-root /path/to/repo --json > owners.json
```

Input is a findings document or `{ "findings": [...] }`. The source root
defaults to the current directory. The command reads committed `HEAD`, relevant
source, blame, and history; it does not read uncommitted source or assign tickets.
Linked worktrees and bound separate Git directories are supported; borrowed
external object stores such as `git clone --shared` are rejected.

Results preserve IDs and report `identified`, `abstained`, or `error`. Identified
owners include an observed Git name/email, reason, and checked citations.
Git identities do not establish current employment or tracker accounts; match
accounts before assigning. Use a checkout matching the findings.

The command uses scan-default model/effort; override with `--model` and `--effort`.
The model receives collected evidence with tools/network disabled. Exit `0`
includes abstentions; `2` means invalid input or a failed recommendation, while
retaining other results. Cancellation uses `130` or `143`.

```ts
import { suggestOwners } from "@openai/codex-security";

const owners = await suggestOwners("/path/to/repo", result.findings.findings, {
  reasoningEffort: "high",
});
```

SDK inputs can include `sourceRevision`. If it differs from `HEAD`, the collector
ignores stale line ranges and reports the mismatch. Reports remain separate from
scan artifacts and record the analyzed revision and limitations.

## Feedback

```bash
codex-security feedback --reason "The scan stopped before it finished"
codex-security feedback SCAN_ID --reason "The scan stopped before it finished" --include-logs
```

Share the returned ID with support. Without a selector, `feedback` uses the most
recently started scan in the current repository, including failed/active scans,
or sends a general report if none exist. Reports include your description,
versions, and selected scan/session IDs. `--json` returns structured output.

Logs are off by default. `--include-logs` sends Codex diagnostics and saved scan/
worker activity, potentially including source, prompts, findings, and tool output.
Include only logs you can share with OpenAI. `feedback.enabled = false` disables
the service.

For Desktop-plugin scans, run on the machine where the scan ran with the same
Codex home and state directory. The command searches active/archived sessions and
recorded worker descendants. Standard scans in an existing Codex conversation
attach only their owner's session. Unrecorded earlier retry sessions may be absent.

## Scan history and reruns

Commands default to the current repository. IDs accept unique prefixes of at
least eight characters.

| Command                                               | Purpose                                                    |
| ----------------------------------------------------- | ---------------------------------------------------------- |
| `scans list [REPOSITORY]`                             | List scans; `--scan-root DIR` filters artifact roots.      |
| `scans show [SCAN_ID]`                                | Show a scan; defaults to latest completed.                 |
| `scans logs [SCAN_ID]`                                | Show session events; defaults to latest, including active. |
| `scans resume SCAN_ID`                                | Continue an interrupted Deep Scan.                         |
| `scans rerun [SCAN_ID]`                               | Repeat on the current checkout.                            |
| `scans match BEFORE AFTER`                            | Link findings with the same root cause.                    |
| `scans match --all`                                   | Match completed scans across worktrees/clones.             |
| `scans compare [BEFORE] [AFTER]`                      | Compare scans; defaults to latest two completed.           |
| `findings list [REPOSITORY]`                          | List open findings.                                        |
| `findings false-positive OCCURRENCE_ID --reason TEXT` | Dismiss a finding while the reason applies.                |

Recipes save settings and authentication choice, not credentials. Reruns use the
current checkout/context files and do not reload project files. Supply replacement
scan and custom-validation prompts when the original used them:

```bash
codex-security scans rerun SCAN_ID --scan-prompt-file instructions.md
```

History lives in `$CODEX_SECURITY_STATE_DIR/workbench.sqlite3`, or
`$CODEX_HOME/state/plugins/codex-security/workbench.sqlite3`. Keep it private,
writable, and outside the target repository. Session logs may contain sensitive
data even though scan recipes do not store credentials.

### Resuming an interrupted Deep Scan

```bash
codex-security scans list --scan-root /path/to/security-scans
codex-security scans resume SCAN_ID
```

The scan must still be `running`, with its original checkout, output directory,
and Codex session in the same state directory. Checkout identity, revision, and
contents must match. Completed, failed, and canceled scans need a rerun instead.

Resume retains scan ID, completed workers, artifacts, accumulated cost, and saved
settings/instructions. New records save the authentication mode, explicit safety
identifier, and post-scan prompt; older records cannot reconstruct missing values.
A failed connection leaves the scan available for another resume attempt.
Compatible scans can resume after plugin updates; sealed results keep their
original producer version. Unsupported artifacts are rejected without rewriting them.

For bulk scans, use [bulk recovery](#recovering-failed-or-interrupted-bulk-scans)
to update campaign receipts. Individual resume does not update `results.jsonl`.

### Matching saved scans

Matching uses sealed artifacts and cached decisions unless `--force` is supplied.
Comparisons classify findings as new, persisting, reopened, resolved, or unknown.
An absent finding is not resolved when the later scan is incomplete or excludes
its scope. One comparison ID is compared with the latest completed scan.

```bash
codex-security scans match --all --force --model gpt-6.1-sol --effort high
```

Only high-confidence root-cause matches are grouped. Uncertain and related
findings remain separate. Rebuilding retains stable identities, triage, and
sealed artifacts; interruption preserves completed comparisons. Model/effort
changes alone do not invalidate cached decisions.

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

This SDK method does not save a workbench comparison. `knownFindingGroups` can
reuse confirmed stable `findingId` groups; results identify original occurrence
IDs. Options include model, reasoning effort, `signal`, and `onProgress`.
Progress callback failures do not stop matching.

## Exports and CI

`export` reads saved results without Codex or credentials. It defaults to the
current repository's latest completed scan. Choose either a positional result
directory or `--scan ID`. Findings require sealed results and support
`--export-format csv|json|sarif` (default SARIF). `--source-root PATH` adds SARIF
source-line fingerprints.

```bash
codex-security export --scan SCAN_ID --export-format json --output findings.json
codex-security export --artifact threat-model --output docs/threatmodel.md
codex-security export /path/to/policy-results --artifact threat-model --output -
```

Threat-model exports use Markdown and default to `./threatmodel.md`. Standard,
Deep, Diff, and policy workflows retain models when available; component/bulk
runs save one per child. Explicit results may expose a model before completion
or after later failure. Missing models return an error rather than generating
or substituting one. Historical models in sealed scans need a matching manifest
digest.

`--output -` emits only artifact content, with diagnostics on stderr. Markdown
and CSV stdout cannot combine with JSON command output. Exporting into a checkout
does not make the model scan input; pass it with `--knowledge-base`.

`ScanResult.threatModel` and `threatModelPath` expose the retained model and
document, or null. Export still works if the document could not be written.

```ts
import { exportArtifact } from "@openai/codex-security";

const exported = await exportArtifact({
  source: { directory: "/path/to/scan-results" }, // Or { scanId: "SCAN_ID" }.
  artifact: "threat-model",
  output: "/path/to/threatmodel.md",
});
console.log(exported.path, exported.provenance);
```

Use `artifact: "findings"` with `format: "csv" | "json" | "sarif"` for findings.
`output: "-"` streams stdout and returns null path/provenance. `pythonPath`
selects an interpreter; `signal` cancels.

JSON preserves sealed findings. CSV marks them open, omits local triage state,
and retains distinct occurrence IDs. It escapes spreadsheet-formula prefixes and
leading apostrophes; import removes the escape. Use JSON to recover ambiguous
apostrophes from older CSV exports.

For CI, place output outside the checkout and set a severity threshold:

```bash
SCAN_ROOT="$(mktemp -d)"
codex-security scan . --diff origin/main \
  --output-dir "$SCAN_ROOT/results" --json --fail-on-severity high \
  > "$SCAN_ROOT/findings.json"
```

| Exit code     | Meaning                                                               |
| ------------- | --------------------------------------------------------------------- |
| `0`           | Complete report-only scan or passing severity policy.                 |
| `1`           | Severity policy violation.                                            |
| `2`           | Invalid input, incomplete coverage, runtime error, or export failure. |
| `130` / `143` | Interrupt / termination.                                              |

JSON scans have no interactive controls. `validate`, `login`, and `logout` reject
`--json`. For GitHub Actions setup, see the
[Action guide](https://github.com/openai/codex-security/blob/main/github-action/README.md)
or the [Bedrock workflow](https://github.com/openai/codex-security/blob/main/examples/github-actions/README.md).

### Local pre-commit checks

`install-hook` checks staged and unstaged changes, blocking the commit on scan
failure or findings at/above its threshold (`high` by default). Use required CI
for enforcement; local hooks are optional.

Install the CLI outside the target repository and run that copy directly. `npx`
can select a repository-local package. Before installation, inspect:

```bash
git -C /path/to/repository rev-parse --git-path hooks/pre-commit
```

Resolve relative output against the repository. Leave custom, linked, shared, or
unverified hooks/directories alone; contact their owner or use CI. If the directory
belongs only to this repository and no hook exists, run from outside the checkout:

```bash
codex-security install-hook /path/to/repository
```

To migrate an existing generated hook, verify it is a regular file used only by
this repository and contains only the generated command. Preserve its severity.
The installer can update older `npx` hooks when the severity matches. New hooks
record absolute Node/CLI paths. If those change, back up and remove the verified
generated hook, then reinstall with the same threshold. Restore the backup if
installation fails. The installer respects `core.hooksPath`.

## Import alerts from the CLI

```bash
codex-security import github example/repository --format json > /path/outside/repository/alerts.json
codex-security import github example/repository --github-alert 12 --github-alert 18 --format json
codex-security validate /path/outside/repository/alerts.json
```

Run validation from the matching local repository. Import defaults to open alerts
on the default branch. Use `--github-state open|closed|dismissed|fixed|all` or
`--github-ref REF` to filter. Exact alert numbers ignore state and reject a
nondefault state.

Import is read-only and returns an array. Save validation inputs without output
filters or token limits. It includes third-party SARIF uploads, does not start
Codex, and does not check out code. Each record contains `source`, `repository`,
`number`, `url`, and the full upstream `alert`.

For a disposition per alert, import and validate through the SDK:

```ts
import {
  CodexSecurity,
  importGitHubCodeScanningAlerts,
} from "@openai/codex-security";

const findings = await importGitHubCodeScanningAlerts({
  repository: "example/repository",
  alertNumbers: [12, 18], // Omit for all open alerts on the default branch.
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

SDK options include `state` (default `"open"`), `ref`, and `signal`.
Supply `githubToken` or use `gh auth token` credentials, including GitHub CLI
token environment variables. `githubHost` defaults to `GH_HOST` or `github.com`.
The token needs code-scanning read access; access failures reject the import.

## Validate and patch findings

`validate` assesses candidates; `patch` fixes and verifies them. Both accept files
or literal text and work in the current directory. Saved finding/occurrence IDs
select their original repository for patching.

```bash
codex-security validate "Possible SQL injection" --effort high
codex-security patch OCCURRENCE_ID
codex-security patch --scan SCAN_ID --severity high --json
codex-security patch --scan SCAN_ID --assess-patch-risk --create-pr
```

`--scan latest` uses the current repository's latest completed scan. Patching
supports JSON for saved findings, literal text, and files. Each finding gets a
saved Codex desktop task. `--model` and `--effort` control the model.

`--validation-prompt-file PATH` supplies setup, authorized targets, expected
results, and cleanup for dynamic validation. It works with saved findings,
text/files, and Linear inputs. Paths resolve from the invocation directory, even
when the finding belongs to another repository. The file must be nonempty and
regular, is read before patching, and cannot combine with `--resume-pr`.

`--assess-patch-risk` runs an advisory assessment after patching. Human-readable
output prints its report; saved-finding JSON includes `patchRisk.report`.
With `--create-pr`, the draft description includes the concise Markdown summary.
The assessment does not change the patch or merge state.

Patching first checks that its sandbox can start. Failure reports
`SANDBOX_UNAVAILABLE`; no file changes from the task reports `NO_PATCH_APPLIED`.
Results list `applied`, `filesChanged`, and `files`, excluding preexisting edits.
File changes alone do not prove a fix; saved findings require a verified result.

For a controlled container providing its own isolation:

```bash
codex-security patch "Security issue" --external-sandbox --json
```

This explicit option disables Codex filesystem/network enforcement for the patch
task. The container must provide it. There is no automatic fallback; optional
patch-risk assessment still uses its read-only sandbox.

`scan --patch` runs after a complete scan. `--patch-severity` defaults to `low`;
`high` selects high and critical findings. Interactive users can select findings
and add instructions. Patch results are `verified`, `no_change`, `blocked`, or
`failed`. Verified/already-fixed findings no longer fail the severity threshold.

### Create or resume a draft pull request

`--create-pr` commits generated patch files and opens a draft GitHub PR with `gh`
or a GitLab merge request with `glab`. Authenticate the appropriate CLI first.
The `origin` push URL selects GitLab.com, including SSH and subgroup projects.
For self-hosted GitLab, set `GITLAB_HOST` to that host and authenticate with
`glab auth login --hostname HOST`. `GITLAB_URI` and `GL_HOST` are fallback aliases.

```bash
GITLAB_HOST=gitlab.example.com codex-security patch --scan SCAN_ID --create-pr
```

Both providers return `pullRequest: { branch, url }`. Supplied-issue patching
requires a clean tree. If publication fails, run the printed
`patch --resume-pr BRANCH` command in the same repository. It reuses the saved
commit and refuses changed branches. Retain the GitLab host setting on resume.

### Patch Linear issues

Repeat `--linear-issue ISSUE` (ID or URL), or select `--linear-project "PROJECT"`
with optional native JSON `--linear-filter`. Completed/canceled issues are
excluded unless the filter sets `state`.

Use `CODEX_SECURITY_LINEAR_API_KEY` or `LINEAR_API_KEY` for an API key, or
`LINEAR_ACCESS_TOKEN` for OAuth. Prefer environment variables over
`--linear-api-key`. Intake is read-only, includes comments, and keeps Linear
credentials out of the patch subprocess. URLs must match the selected workspace.

## Verify fixes

`verify-fix` checks fixes in a read-only sandbox. It accepts descriptions, saved
finding IDs, `--scan`, and the Linear issue/project selectors above. Explicitly
filter for completed Linear issues to check a finished backlog.

Results include evidence and `fixed`, `still_vulnerable`, or `inconclusive` status.
`--json` returns structured output. Exit codes are `0` when all findings are
fixed, `1` when any remain vulnerable, and `2` for inconclusive/failed checks.

## Command discovery and integrations

Use `--llms` for the command manifest, `scan --schema --format json` for its
schema, and `completions bash|zsh|fish` for shell completions. Scan output supports
`--format toon|json|yaml|jsonl` and `--full-output`.

`skills add` syncs agent skills; `mcp add` registers the CLI as an MCP server.
MCP exposes only read-only `info`, because the transport cannot cancel scans.

For a local findings API and deduplication, see the
[findings service guide](findings-service.md).

## Containerized bulk scans

Create `repositories.csv` as described under [Bulk scans](#bulk-scans), then run
from the repository root with the published image:

```bash
mkdir -p results state
chmod 700 results state
export CODEX_SECURITY_USER="$(id -u):$(id -g)"
export CODEX_SECURITY_IMAGE=ghcr.io/openai/codex-security:latest
docker compose pull codex-security
docker compose run --rm codex-security login --device-auth
docker compose run --rm codex-security
```

Use device login only if your workspace permits it. For unattended scans, set
`OPENAI_API_KEY` or `CODEX_API_KEY`. Results go to `results/`; login stays in
`state/`. Private GitHub checkouts use `GH_TOKEN` or `GITHUB_TOKEN`; Enterprise
uses `CODEX_SECURITY_GIT_HOST`. The container requires CSV input.

Compose accepts `CODEX_SECURITY_IMAGE`, `CODEX_SECURITY_USER`,
`CODEX_SECURITY_SECCOMP`, `CODEX_SECURITY_CSV`, `CODEX_SECURITY_RESULTS`, and
`CODEX_SECURITY_STATE` for its image, user, seccomp policy, and mounts.

Codex requires Bubblewrap for filesystem-restricted Linux execution. On Ubuntu
hosts that restrict unprivileged user namespaces, an administrator must install
the AppArmor profile and use the Compose override:

```bash
sudo install -m 0644 docker/codex-security.apparmor /etc/apparmor.d/codex-security-container
sudo apparmor_parser -r -W /etc/apparmor.d/codex-security-container
docker compose -f compose.yaml -f compose.apparmor.yaml run --rm codex-security
```

The override enables nested namespaces while keeping the nonroot user, dropped
capabilities, no-new-privileges, and seccomp policy. Hosts that permit nested user
namespaces do not need it. The legacy Landlock fallback is unsupported.
See the [Docker guide](https://github.com/openai/codex-security/blob/main/docker/README.md)
for deployment and source-build instructions.
