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
npx codex-security --version
```

The package supports macOS, Linux, and Windows and requires Node.js 22 or
later. Scanning and exporting findings also require Python 3.10 or later. If
you use Python 3.10, install the `tomli` package. Select another interpreter
with `--python`, `pythonPath`, or `PYTHON` when needed.

When a newer version is available, the CLI shows the update command for your
installation method. Set `CODEX_SECURITY_NO_UPDATE_NOTICE=1` to hide the
notice. Notices are also disabled in CI and when stderr is not a terminal.

## Run a scan from TypeScript

Sign in with `npx codex-security login` or set `OPENAI_API_KEY` or
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

## Authentication

For local use, sign in with ChatGPT:

```bash
npx codex-security login
npx codex-security scan .
```

On a remote or headless machine, use device authentication:

```bash
npx codex-security login --device-auth
```

For CI, set `OPENAI_API_KEY` or `CODEX_API_KEY`. To store an API key instead,
pass it on stdin:

```bash
printenv OPENAI_API_KEY | npx codex-security login --with-api-key
```

On Windows, set the API key in PowerShell:

```powershell
$env:OPENAI_API_KEY = "<your-api-key>"
npx codex-security scan C:\code\repository
```

Check or remove the stored sign-in with `npx codex-security login status` and
`npx codex-security logout`. Codex Security reuses an existing file-based Codex
sign-in. If Codex stores credentials in the system keyring, run
`npx codex-security login` once before scanning.

An environment API key takes precedence over a stored sign-in by default.
When both a stored ChatGPT sign-in and an environment API key are available, an
interactive scan asks which credential to use. JSON output, dry runs, CI, and
other noninteractive scans never prompt and retain automatic API-key
precedence. Select the credential source explicitly with `--auth`:

```bash
npx codex-security scan . --auth chatgpt
npx codex-security scan . --auth api-key
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

## CLI

```bash
npx codex-security scan /path/to/repository
npx codex-security scan /path/to/repository --model gpt-5.6-terra
npx codex-security scan /path/to/repository --path src --path tests
npx codex-security scan /path/to/repository --knowledge-base /path/to/threat-models --knowledge-base /path/to/architecture.pdf
npx codex-security scan /path/to/repository --diff origin/main --json
npx codex-security scan /path/to/repository --output-dir /path/outside/repository/results
npx codex-security scan /path/to/repository --output-dir /path/outside/repository/results --archive-existing
npx codex-security scan /path/to/repository --dry-run
npx codex-security scan /path/to/repository --fail-on-severity high
npx codex-security scan /path/to/repository --max-cost 5
npx codex-security install-hook
npx codex-security bulk-scan
npx codex-security bulk-scan repositories.csv --output-dir /path/outside/repositories/security-scans --workers 4
npx codex-security scans list /path/to/repository
npx codex-security scans list --scan-root /path/outside/repository/results
npx codex-security scans show SCAN_ID
npx codex-security scans rerun SCAN_ID
npx codex-security scans match PREVIOUS_SCAN_ID CURRENT_SCAN_ID
npx codex-security scans match --all
npx codex-security scans compare PREVIOUS_SCAN_ID CURRENT_SCAN_ID
npx codex-security findings false-positive OCCURRENCE_ID --reason "The route already checks permissions"
npx codex-security export /path/outside/repository/results --export-format sarif --output /path/outside/repository/results.sarif
npx codex-security export /path/outside/repository/results --export-format csv --output /path/outside/repository/findings.csv
npx codex-security export /path/outside/repository/results --export-format json --output /path/outside/repository/findings.json
npx codex-security validate /path/outside/repository/findings.json "Possible SQL injection in src/query.ts:42"
npx codex-security patch /path/outside/repository/findings.json "Missing authorization check in src/routes.ts:18"
```

Run `npx codex-security --version` for the installed CLI version or
`npx codex-security info --json` for the package, bundled plugin, Codex runtime,
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

Scans use `gpt-5.6-sol` with extra-high reasoning effort by default. Use
`--model gpt-5.6-terra` to switch models. Use repeatable `--codex KEY=VALUE`
options for other Codex settings, such as
`--codex 'model_reasoning_effort="high"'`.

Scan progress identifies the requested paths and reports actual ranking,
file-review, validation, and attack-path phases as they become available.
Completion summarizes findings, severity, coverage, elapsed time, available
token and worker counts, estimated cost, the results directory, and the next
useful command.
Progress and summaries use stderr; structured scan results remain on stdout.

Each scan records its model, tokens, and estimated cost in its JSON result,
scan history, and bulk-scan receipt. Estimates use
[standard API token prices](https://developers.openai.com/api/docs/models/compare),
including cached input and cache writes; fees and surcharges are not included.

Use `--max-cost USD` to stop a scan, including its delegated workers, when its
running cost exceeds the limit. Partial results are preserved. Requests
already in progress can finish above the limit.

Run `npx codex-security scan --help` or `npx codex-security bulk-scan --help`
for the complete CLI references.

Sign in with `gh auth login`, then run `npx codex-security bulk-scan` to discover
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

`npx codex-security scans list` lists scans for the current repository. Pass a
repository path to inspect another checkout, `--scan-root DIR` to list scans
whose artifacts are under a particular root. `scans show SCAN_ID` includes the
scan configuration, results, coverage, and artifact locations.

Every scan history command accepts a full scan ID or a unique prefix of at
least eight characters.

Scan history uses the existing Codex Security workbench database at
`$CODEX_HOME/state/plugins/codex-security/workbench.sqlite3`. Set
`CODEX_SECURITY_STATE_DIR` to place the database elsewhere. Scan credentials
are never stored in the scan configuration.

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
checkout so a fixed vulnerability can be checked again.

`scans match BEFORE_SCAN_ID AFTER_SCAN_ID` links findings with the same root
cause; `scans match --all` matches all completed scans of the current repository,
including other worktrees and clones. Saved matches appear in `scans show` and
are reused unless `--force` is passed. Scans without sealed artifacts are skipped.

`scans compare BEFORE_SCAN_ID AFTER_SCAN_ID` reads saved matches and reports
findings as new, persisting, reopened, resolved, or unknown. Missing findings
are not treated as resolved when the later scan is incomplete or does not cover
their original scope.

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
npx codex-security scan . \
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
Run `npx codex-security export --help` for all export options.

Use `validate` to run the bundled validation skill on candidate findings and
`patch` to run the bundled fix-finding skill on security issues. Each positional
input can be either a file, whose contents are read into the request, or literal
text. Both commands operate on the current directory, use the scan model
and reasoning defaults, ignore unrelated user configuration and plugins, and
print the final response without the underlying Codex event stream. Override
the model or reasoning effort with `--codex 'model="gpt-5.6-sol"'` or
`--codex 'model_reasoning_effort="high"'`. Inputs are limited to 64 items and
1 MiB total.

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

## Documentation and security

- [CLI quickstart](https://developers.openai.com/codex/security/cli)
- [TypeScript SDK guide](https://developers.openai.com/codex/security/sdk)
- [GitHub issues](https://github.com/openai/codex-security/issues) for bugs and
  feature requests
- [Security policy](https://github.com/openai/codex-security/blob/main/SECURITY.md)
  for private vulnerability reporting and safe operation
