# CLI and workflows

The global installation provides both `codex-security` and its short alias `cs`.
They accept the same arguments and options. The examples below use
`codex-security`; you can also use `cs` or, without a global installation,
`npx @openai/codex-security`. See the [installation guide](../README.md#install).

```bash
codex-security --help
codex-security scan --help
codex-security --version
codex-security info --json
```

`--help` lists commands by task; `<command> --help` lists its options.
`info --json` reports package, plugin, runtime, and model details.
`scans` and `findings` default to their `list` subcommands.

To retrieve GitHub code scanning alerts without an MCP server, use
[`import github`](#import-alerts-from-the-cli). To save an existing CSV or JSON
findings file in local scan history, use
[`scan import`](#import-findings-as-a-saved-scan). These are separate workflows:
GitHub import returns upstream alerts for validation; file import saves findings
without running security analysis.

## Find a workflow

- [Sign in or configure a provider](#authentication).
- [Scan a repository or selected paths](#scan-options-and-output),
  [configure a Deep Scan](#configure-deep-scans), or
  [save project settings](#project-files).
- [Review one system across repositories](#review-one-system-across-repositories)
  or [run independent bulk scans](#bulk-scans).
- [Import vendor findings locally](#import-vendor-findings-locally),
  [save findings as a scan](#import-findings-as-a-saved-scan), or
  [retrieve GitHub alerts](#import-alerts-from-the-cli).
- [Inspect saved scans and rerun them](#scan-history-and-reruns),
  [classify severity](#classify-finding-severity), or
  [suggest owners](#suggest-finding-owners).
- [Validate and patch findings](#validate-and-patch-findings) or
  [verify an existing fix](#verify-fixes).
- [Publish to Cloud](#publish-findings-to-cloud) or
  [Linear](#publish-completed-scans-to-linear), or [export results](#exports-and-ci).
- [Draft a security policy](#generate-a-security-policy).
- [Use a hosted executor](#hosted-standard-scan) or
  [run bulk scans in containers](#containerized-bulk-scans).

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
Without an overriding environment API key, scans and status checks import
existing file-based Codex credentials when this home is empty. Import errors make
`login status` exit with code 2 and SDK `account()` reject its promise. Logout
disables imports until you log in again. Status imports and logout share the
credential-home lock so a concurrent status check cannot restore credentials
after logout completes.

Scans and status checks expand a home-relative `CODEX_HOME` using the caller's
`HOME` or `USERPROFILE` environment setting.

If credentials cannot refresh, run `login status`. Retry if the sign-in recently
changed; otherwise run `logout`, then `login`.
Some cybersecurity requests and protected findings require
[Trusted Access for Cyber](https://chatgpt.com/cyber).

### Daybreak opt-in

Codex 0.163.0 and later default the Daybreak toggle to off. Enable it through
the existing native configuration override:

```bash
codex-security scan . --codex daybreak=true
codex-security scan . --mode deep --codex daybreak=true
```

In the SDK, use `new CodexSecurity({ codexOverrides: { daybreak: true } })`.
In project files, set `daybreak: true` inside the `codex` mapping. Use `false`
to explicitly turn it off.
The setting carries through saved scan recipes, resumed scans, Deep Scan
discovery and reducer workers, and `scan --patch`. Standalone `validate`,
`patch`, and `verify-fix` accept the same `--codex daybreak=true` override.
Threads created by these commands retain the setting when resumed in Codex.
Scans use isolated configuration, so set it on the CLI, SDK client, or project
file even if it is enabled in your personal Codex configuration.

For the plugin inside Codex, use the desktop Daybreak toggle or `/daybreak` in
an interactive CLI session. For headless Codex, use `codex exec -c daybreak=true`
or set top-level `daybreak = true` in the configuration loaded by the runner.
Deep Scan inherits the active turn's effective access program from its saved
Codex session, including an explicit Standard selection. Discovery and reducer
workers retain that selection when resumed. If the host does not supply a
persisted turn context, workers use their runner configuration; CLI and SDK scans
use the explicit scan settings above.

Daybreak requires the built-in OpenAI provider and compatible account or API
project access. Codex selects the available program; this setting does not
grant access. An explicit [Cyber access program](#select-a-cyber-access-program)
takes precedence over the toggle for that turn.

### Daybreak Blue with an API key

The [Responses API defaults](https://developers.openai.com/api/docs/guides/daybreak#understand-defaults-when-omitted)
can apply Daybreak Blue to compatible mainline models when the API organization
and project have access. An omitted `access_programs.cyber` field does not by
itself mean that Daybreak treatment is disabled.

Choose a compatible model available to your project and select Daybreak Blue
explicitly:

```bash
codex-security scan /path/to/repository \
  --auth api-key --model "<model>" --cyber-access-program daybreak_blue
```

In the SDK, select your model through `codexOverrides.model` and pass
`auth: "api-key"` and `cyberAccessProgram: "daybreak_blue"` in the scan options.
Use `--mode deep` in the CLI or `mode: "deep"` in SDK scan options for Deep Scan.
The selection reaches discovery and reducer workers, including resumed workers. See [Select a Cyber access program](#select-a-cyber-access-program)
for configuration precedence and the API-key feature setting.

The previously documented `gpt-daybreak-blue-latest` alias is
[deprecated](https://developers.openai.com/api/docs/models/gpt-daybreak-blue-latest).
Use a current model available to your project. `access_programs.cyber` is a
Responses API field; use the supported selector instead of passing it as a
`--codex` configuration key.

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

export CHEAPER_INFERENCE_API_KEY="<your-cheaper-inference-api-key>"
codex-security scan . --provider cheaperinference --model gpt-5.4
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

Use `policy` to draft or update `SECURITY.md` before a scan. The policy describes
the project's security boundaries and what should count as a finding. This step
is optional: you can scan with an existing policy or without one.

From the repository root, run:

```bash
codex-security policy .
```

The command saves a draft outside the repository and leaves existing files
unchanged. In a terminal, it asks about facts the source cannot establish and
shows the proposed diff.

1. Read the saved `SECURITY.md`, diff, and **Review notes**. Edit the draft as
   needed. Preserve reporting instructions and confirm exclusions, accepted
   risks, and severity decisions with the project owner.
2. If you choose to use the draft, copy only the reviewed `SECURITY.md` to the
   displayed **Policy target**. Keep the supporting documents outside the
   repository.
3. Run `codex-security scan .`. The scan reads the policy from the repository.

If you reject the draft, skip the copy and scan with your existing policy or
without one. If the command reports that `SECURITY.md` is already up to date, no
copy is needed; review any notes and continue to the scan.

You can leave answers blank during generation. Keep unresolved decisions
explicit in any policy you adopt, or scan without adopting the draft while you
resolve them. Regenerate if relevant source or neighboring policies changed
during generation.

### Existing policies and components

If your existing root or component `SECURITY.md` already describes the relevant
security boundaries, scan with it directly. To propose an update, use `policy .`
for the root policy or select a component:

```bash
codex-security policy . --path services/api
```

This drafts `services/api/SECURITY.md`, whether or not that file already exists.
The repository defaults to the current directory. A component inherits policies
from its Git root, with the closest policy taking precedence. Inherited policies
may refer to ancestor `SECURITY.md` files or the checkout's `.github/SECURITY.md`
and `docs/SECURITY.md`; they cannot widen the component's scope.

A `.github/SECURITY.md` or `docs/SECURITY.md` often describes how to report
vulnerabilities. Keep those instructions: these files do not automatically
provide repository-wide scan guidance. Use a root `SECURITY.md` for that guidance,
or a component `SECURITY.md` for guidance specific to that directory. Before
replacing the policy target, check whether either reporting file links to it;
the replacement can affect their guidance too.

### Generation options and saved files

Generation describes the system, builds a threat model, then drafts the policy.
Add context with `--knowledge-base`:

```bash
codex-security policy . --knowledge-base architecture.md
```

| Invocation                   | Result                                                   |
| ---------------------------- | -------------------------------------------------------- |
| `policy . --headless --json` | Generate without prompts; return paths and review notes. |
| `policy . --format md`       | Generate and write the draft to stdout.                  |
| `policy . --dry-run --json`  | Check local inputs without calling Codex.                |

`--headless` leaves unanswered questions in the review notes. By default, files
go in the Codex Security state directory. To choose a location, use an empty
directory outside every enclosing checkout and its Git metadata:

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

### Source access and restrictions

The command uses scan authentication and read-only access to the selected source.
It denies Git metadata, the credential home, and private runtime configuration,
disables network, web, apps, and MCP, and uses only Codex's core shell environment.
On Unix, filesystem reads are limited to the selected source, runtime files, and
review artifacts. Windows' elevated sandbox requires broader local read access,
including sibling components, while keeping those explicit denials and read-only
permissions. Ambient Codex authentication and provider-profile files remain
excluded; Windows resolves file-pattern denials when each sandboxed command
starts. Knowledge-base text stays in private review artifacts during
generation and is removed afterward.

Targets and links stay within the checkout and outside Git metadata. Linked
worktrees and initialized submodules use their own roots. For a separate Git
directory, set `core.worktree` to the checkout's absolute path; use
`git worktree repair` for moved linked worktrees.

Generation currently fails on Unix directories with non-UTF-8 names. On macOS,
the bundled runtime does not fully enforce write restrictions under `/tmp`
(including `/private/tmp`); keep source and artifacts elsewhere when read-only
enforcement is required. See the
[upstream sandbox issue](https://github.com/openai/codex/issues/32395).

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
non-terminal uses. Both preview methods compute the diff in Node without
discovering or launching Python; `pythonPath` and `PYTHON` do not affect previews.

The optional second argument to `securityPolicyDiff(draft, python, signal)` is
deprecated. Interpreter paths, including paths returned by a resolver callback,
no longer select an executable or get validated. For compatibility, an explicitly
supplied resolver is still awaited when the draft changes, and any error it throws
propagates. Omit that argument for new code, or pass `undefined` when supplying a
cancellation signal. Source freshness is checked before and after computing the
diff.

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
codex-security scan . --owner-suggestions
codex-security scan . --output-dir /path/outside/repository/results --dry-run
```

`--path` selects files or directories. The scan summary and saved scan details
show requested paths and exclusions. `coverage.deferred` records unfinished
requested work separately from optional `coverage.openQuestions` follow-up.
Human-readable output quotes ambiguous paths, while JSON retains their original strings.

Whole-codebase and path scans also accept ordinary directories, including SVN
working copies. Their source inventories exclude `.git` and `.svn` metadata.

`--diff` scans committed changes; `--working-tree` scans staged and unstaged
changes. Both require Git. Deep scans support whole repositories and path scopes.
Working-tree snapshots include untracked nested Git repositories. Initialized submodules must
be clean and at the commit recorded by the parent.

Committed-diff scans require a clean, full checkout at the requested head
revision, including when using `--validate`. A different checkout revision or
local changes are rejected before scanning; check out the requested head and
commit or stash local changes before retrying.

`--owner-suggestions` writes optional `owner-suggestions.json` after a completed
committed Git scan, using the same checkout, model, and reasoning effort. Owner
errors leave the base scan completed. The JSON result includes
`ownerSuggestionsPath` or `ownerSuggestionsError`; the sealed findings and
manifest stay unchanged. This option is unsupported for working-tree and
directory snapshots. It works with `--max-cost`: hints are recorded within the
existing scan execution and budget, and the report is finalized without another
model call. Missing hints abstain; invalid hints produce per-finding owner errors.
Use the separate `suggest-owners` command for explicit owner-only jobs.

Repeat `--knowledge-base PATH` for context: UTF-8 text files (including JSON and
SARIF), PDF, DOCX, or directories. Directory traversal skips other binary files;
explicit unsupported binary files are rejected. Bulk scans share this context
with every repository.

Use `--output-dir DIR` to choose where a scan saves its results. The directory
must be empty and outside the scanned directory and enclosing Git worktree. On
macOS/Linux, existing directories must be private (`chmod 700`).
`--archive-existing` moves earlier output to
`<output-dir>.previous-<timestamp>-<id>`; `--dry-run` previews the move.

Scans also attempt to write SARIF to `<scan-dir>/exports/results.sarif`. If that
optional export fails, the scan can still complete. Use the
[export command](#export-findings) to write or retry SARIF from the saved results.

Completed scans exit with `0` by default. Configure `--fail-on-severity high`
to return `1` for high or critical findings. Scope exclusions, skipped files, and follow-up notes
do not fail a scan or bypass the findings threshold. Execution, target-integrity,
and required-output failures exit with `2`.

New reports omit `coverage.completeness`. Use `manifest.scan.status` and the
command exit code to distinguish execution failures from findings-policy violations.
Legacy completeness values affect neither.
Bulk and component summaries report completed and failed scans without an
`incomplete` count. Component matching errors have status `failed`.

Usage coverage is separate from execution status. A recorded interruption or a
closed turn without a numeric usage receipt makes usage coverage `partial`, even
if a later turn succeeds. Recorded numeric zero is distinct from a missing
receipt. These checks describe available local records; they cannot reconstruct
requests whose usage was never persisted locally or prove an exhaustive billing
total.

New drafts use the current finding schema: `codeEvidence`, `rootCause`,
`attackPath.dataflow`, and `evidenceRefs`. Source snippets belong in
`codeEvidence`; `rootCause.evidenceRefs` links to them. Legacy aliases and
malformed optional fields are rejected before completion rather than repaired.
This applies to model-authored files, worker results, custom validation, and new
imports. Existing sealed reports remain readable and exportable without
rewriting their contents. Older unfinished drafts must be updated to the current
schema or completed with their original CLI/plugin version.

`scan`, `scans rerun`, and `scans resume` execution failures with `--json`, JSON,
or JSONL output produce:

```json
{ "status": "failed", "code": "SCAN_FAILED", "message": "..." }
```

With `--full-output`, the error appears under `error` in an `ok: false` envelope.
If the scan target changed, the error explains that the results no longer
represent the current checkout. Retained sealed results remain available under
`data`, including their manifest, findings, coverage, scan directory, and report
path. Unsealed or invalid artifacts are not included. This also applies to
`scans rerun` and `scans resume`.
For `scans rerun` and `scans resume`, `--filter-output` applies to retained `data`;
selecting an unavailable field can return `null` or omit `data`.

Saved-scan setup failures use the same output shape with
`SCAN_REPLAY_UNAVAILABLE` for `scans rerun` (including when no completed scan is
available) or `SCAN_RESUME_UNAVAILABLE` for `scans resume`. Rerunning an imported
scan uses `SCAN_IMPORT_FAILED` if the import fails. Other output formats retain
stderr-only failures, including when `--full-output` is selected.

Diagnostics stay on stderr. Each command's `--schema --format json` describes
its successful output and failure codes.
See [Exports and CI](#exports-and-ci) for exit codes and CI examples.

### Follow-up finding validation

Scans already validate findings against local source. Add `--validate` to run
the existing standalone validation workflow for each reported finding after
the scan, using the same selected Cyber access program. Validation has read-only
filesystem access with network and web search disabled. Each assessment uses a
separate evidence directory; the combined report is saved as
`<scan-dir>/validation.md`, or a uniquely suffixed report
if that path already exists. Each completed assessment is saved immediately;
failed or interrupted runs retain the partial report. JSON scan output includes
the execution status, completed assessment count, and report path. Completion means the assessments finished,
not that every finding was confirmed. A scan with no findings needs no second
pass.

With `--workflow-id`, retries reuse completed assessments for unchanged findings,
source, validation settings, and saved evidence. Missing or changed evidence
causes validation to run again, as do older assessments without recorded evidence
fingerprints. By default, regeneration uses a new evidence directory. An explicit
SDK validation `outputDir` reuses an assessment only when it points to the same
evidence directory. A different destination starts a new assessment. The requested
directory must be empty when regenerating; existing files are never overwritten.
When `--knowledge-base` is supplied, the scan and all follow-up assessments use
one captured copy of those documents. A workflow retry must use the same document
contents. Use a new workflow ID if they changed or if the workflow was created
before document snapshots were bound to follow-up validation.

The report is supplemental: its assessments are not applied to the saved
findings or the `--fail-on-severity` decision. Validation failures exit with
`2` while retaining the completed scan. The additional model calls are not
cost-tracked, so `--validate` cannot be combined with `--max-cost` (including a
configured scan cost limit), `--dry-run`, or `--mock`.

### Understand scan scope and follow-up work

A completed scan means the requested workflow finished. It does not mean every
file or possible vulnerability was examined. A scan can finish with intentional
exclusions, deferred review work, or unanswered questions.

To investigate a particular run, use its scan ID explicitly:

```bash
codex-security scans show SCAN_ID --json
codex-security scans logs SCAN_ID
```

Replace `SCAN_ID` with the ID from the completion or failure summary. A scan can
fail after registration but before writing its artifacts; investigate those
failures through its history record and any available logs. When artifacts were
retained, use the saved results directory returned by `scans show` to inspect
whichever of these files are present:

| File                 | What to check                                                                                                                                                                                                    |
| -------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `scan-manifest.json` | `scan.status`, the target snapshot, and any recorded `scan.scope` limitations.                                                                                                                                   |
| `report.md`          | Scope, reviewed surfaces, and open questions or follow-up work.                                                                                                                                                  |
| `coverage.json`      | `includePaths` and `excludePaths` for scope boundaries; `explicitExclusions` for recorded exclusion reasons; `surfaces` for reviewed areas; `deferred` for unfinished review work; and optional `openQuestions`. |

Deferred items can identify affected `paths` or `surfaceIds`. Surface
`receiptRefs` link to retained evidence under `artifacts/` when available.
Deep Scan summaries retain coverage from accepted worker reviews, including
worker-specific deferred work. Check those details as well as the final findings.

These records describe what the scan recorded, not an exhaustive file-by-file
audit. A retained source inventory, when present, lists inputs rather than
proving that each file was reviewed. An absent path in a surface summary does not
establish whether it was read, and the scan ID cannot reconstruct evidence that
was never saved.
Session logs can help explain failures and tool activity, but do not prove
complete review either.

For a local plugin scan, ask Codex to open the saved scan and explain its scope,
exclusions, deferred work, and follow-up questions. CLI history can also locate
that scan when it uses the same Codex home and state directory on the machine
where the scan ran. A scan ID alone does not download another machine's or
Cloud's artifacts. Preserve the saved results directory with the ID.

Choose the next step from the recorded reason:

- **The run completed and its scope matches your intent:** analyze the findings.
  Record any remaining limitations; an exclusion or follow-up note alone is not
  an execution failure.
- **An important path or security question remains unreviewed:** run a focused
  scan with `--path`, adding relevant context with `--knowledge-base` or specific
  instructions with `--scan-prompt-file`. Address missing access or context first.
  Repeating the same scan does not guarantee that an omission will be resolved.
- **The run failed or was canceled:** inspect its logs and address the cause.
  Use `scans rerun SCAN_ID` when the scan has a saved launch recipe; otherwise,
  start a new scan with the intended scope, including for plugin scans without
  a recipe. Retained findings can still be reviewed, but absence of findings
  from a stopped run is inconclusive.
- **A Deep Scan was interrupted and is still recorded as `running`:** it may
  support [resume](#resuming-an-interrupted-deep-scan) with the original checkout,
  artifacts, and session. Completed, failed, and canceled scans cannot resume.

For example, after identifying an omitted API directory:

```bash
codex-security scan . --path services/api --knowledge-base architecture.md
```

Replace the path and context file with those for your repository. A new scan
reviews the current checkout; it does not amend the original saved report.

Older reports may still contain `coverage.completeness: "partial"` or
`"unknown"`. Read their scope and follow-up details to understand the limitation.
Current reports omit that field, and current commands do not use legacy
completeness values to determine scan status or exit codes.

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

For vendor exports, use [local vendor import](#import-vendor-findings-locally)
instead. That flow retains unassessed source evidence without creating a scan.

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

Plans use literal repository-relative paths, so `~/src` selects a directory
named `~` inside the repository rather than expanding the home directory.
Existing absolute paths inside the repository are also accepted.

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
severity. Uncertain matches stay separate. `summary.json` records component execution and
matching status; `report.md` links to component reports. Export or publish each
individual scan folder.

Failures do not stop other components. Failed scans or
failed matching return `2`; severity-policy violations return `1`. Retry with
`--components-file retry-components.json` and a new empty output directory.
The retry report covers only those components.

`--max-cost` applies per component, excluding planning and matching. `--model`
and `--effort` also apply to matching; `--auth` applies throughout. Planning and
matching reject ambient command providers that conflict with explicit ChatGPT
or API-key auth. SDK-selected command providers retain their authentication.

From TypeScript, use `runComponentScans({ repository, outputDir, components })`.
Use `auto: true`, `planOnly: true`, and `scanOptions.auth` for the corresponding
planning and authentication choices. Custom `createSecurity` clients receive
absolute targets; saved plans and component receipts retain relative paths.

### Set investigation time

```bash
codex-security scan . --max-time 15
codex-security scan . --diff origin/main --max-time 15
codex-security scan . --mode deep --max-time 90
```

`--max-time` accepts positive fractional **minutes**. Standard scans have no
time allowance by default. When selected, it is advisory: spend the available
time on useful investigation and validation, finish early if no worthwhile work
remains, and stop starting investigations at the deadline. Reporting can run
longer. This is not a hard timeout or a minimum runtime. The allowance covers
repository, path, diff, and working-tree scans; standalone custom validation and
post-scan instructions are outside it. Existing `--max-cost` and cancellation
behavior are unchanged.

The SDK setting is `maxTimeMinutes`; project files use `scan.max_time_minutes`.
Each launched scan or rerun gets its own allowance after setup, and reconnects
do not reset it. Standard scans still do not support resume. For batch and
component scans, the project setting applies separately to each scan attempt,
not to planning, result matching, or the total campaign.

### Configure deep scans

```bash
codex-security scan . --mode deep --workers 2 --subagents 0 \
  --stop-after-no-new 3 --max-discovery-runs 10 --max-time 90
```

For `scan --mode deep`, `--workers` controls discovery concurrency and
`--subagents` controls subagents per worker. `--stop-after-no-new`,
`--max-discovery-runs`, and `--max-time` stop discovery by novelty, count,
or duration. At the deadline, discovery stops; the scan then combines and returns
completed findings.

For TypeScript, see the [SDK Deep Scan example](../README.md#configure-deep-scans).

Use project-file `scan.deep` settings or legacy
`$CODEX_HOME/codex-security/config.toml` defaults. Counts must be positive except
that `subagents` can be zero. Discovery time accepts positive fractional minutes;
its default and maximum are 5760 minutes (96 hours). Unlike Standard's
advisory allowance, the Deep discovery limit is enforced. Resuming a
Deep scan keeps its original deadline; rerunning starts a new scan.
`--max-time-hours`, SDK `maxTimeHours`, project `scan.deep.max_time_hours`, and
legacy TOML `deep_scan.max_time_hours` remain deprecated Deep-only aliases in
hours. Explicit settings override lower-priority configuration across units.
At the winning source, conflicting minute/hour durations are errors; equivalent
durations are accepted.
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
`medium` effort. `dedupe` has separate default screening and review models;
the host's Codex model and effort settings override those defaults for both
stages.

`codex-security dedupe --scan SCAN_ID --json` prepares embeddings and deduplicates
directly in local SQLite. An optional `--findings-url URL` selects an existing
findings service instead. Local mode needs an embedding API key for missing or
stale vectors and a model provider for fresh reviews; it does not publish to
Cloud. See [deduplication](findings-service.md#deduplicate-a-scan) for scope,
credentials, and workflow resume behavior.

For `dedupe --scan latest`, matching across worktrees or clones requires a Git
executable outside all saved scan targets. If a historical target includes the
available Git installation, use `codex-security dedupe --scan SCAN_ID` with an
explicit saved scan ID. Exact-path `latest` lookup still works without Git.

Repeat `--codex KEY=VALUE` for supported native settings. Quote strings as TOML:
`--codex 'model_reasoning_effort="high"'`. Repeated or conflicting keys are
rejected, including a `--model` or `--effort` flag plus its native equivalent.
Choose plugins with `--plugin-path`; native plugin and marketplace overrides are
rejected. New and resumed Deep Scans require the current plugin's direct engine,
worker provider snapshot, and isolated worker configuration capabilities. Update
older custom plugins or omit `--plugin-path` to use the bundled plugin. The SDK
no longer adapts direct `node ./mcp/server.mjs` entrypoints; use the current shell
or Windows MCP launcher. Saved reports remain readable.
Multi-agent v2 must remain enabled; `agents.max_threads` is unsupported.

`validate`, `patch`, and `verify-fix` limit native overrides to `model`,
`model_reasoning_effort`, `model_provider`, `model_providers`, `daybreak`, and
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

Model requests include Codex Security attribution in `responses_api_metadata`:
`codex_security_surface` (`cli` or `sdk`), `codex_security_command`,
`codex_security_package_version`, and `codex_security_plugin_version` when the
selected plugin declares a version. The shared context adds
`codex_security_provider` for the configured provider family when the wrapper
selects a provider, and
`codex_security_scan_mode` for scans. Custom provider names use `custom`.
Provider attribution reflects the wrapper's selected profile or default;
native managed configuration may select a different provider before inference.
The GitHub Action supplies `codex_security_integration=github_action`;
Deep Scan workers retain the context and add `codex_security_worker_role`.
Caller metadata, including literal dotted keys, is preserved. Connected-app
publication uses the same request attribution; embedding requests identify
the package and version in their `User-Agent`.

These fields provide request attribution for supported inference providers, including
Bedrock. They do not create a separate telemetry collector or make another
provider's traffic visible to OpenAI. Local operation receipts separately record
starts, outcomes, duration, and usage coverage; see
[telemetry and measurement](telemetry.md).

Disable Codex usage analytics and built-in metrics with
`--codex 'analytics.enabled=false'`. The setting carries into `scan --patch`,
patch-risk assessment, and Deep Scan discovery and reducer workers, including
resumed workers. Selected-profile settings take precedence over root settings.
Explicit OpenTelemetry settings also carry into scan patches and Deep Scan
workers, including exporter choices and prompt-logging controls.
Model-request attribution metadata remains attached when analytics are disabled.
The setting does not control configured OpenTelemetry exporters, integrations,
authentication, or CLI update checks. Validation uses isolated configuration;
patching and verification preserve ambient project trust.

For filesystem and approval behavior, see the
[local security model](../README.md#local-security-model).

### Environment variables

| Variable                                                                    | Effect                                                                                                               |
| --------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------- |
| `OPENAI_API_KEY`, `CODEX_API_KEY`                                           | Scan credentials; the first takes precedence.                                                                        |
| `CODEX_SECURITY_STATE_DIR`                                                  | Private history, database, and default artifacts.                                                                    |
| `CODEX_SECURITY_PROJECT_CONFIG`                                             | Selected project file; `-c` overrides it.                                                                            |
| `CODEX_HOME`                                                                | Ambient Codex home; default `~/.codex`.                                                                              |
| `CODEX_CLI_PATH`                                                            | Codex executable for login, setup, scans, and workers.                                                               |
| `PYTHON`                                                                    | Python interpreter unless an explicit option overrides it.                                                           |
| `CODEX_SECURITY_LOG_LEVEL`                                                  | CLI diagnostics; `debug` enables verbose output.                                                                     |
| `LOG_LEVEL`                                                                 | Fallback if `CODEX_SECURITY_LOG_LEVEL` is unset or blank.                                                            |
| `CODEX_SECURITY_LINEAR_TEAM`, `CODEX_SECURITY_LINEAR_PROJECT`               | Default publication destination.                                                                                     |
| `CODEX_SECURITY_LINEAR_API_KEY`                                             | Linear personal API key.                                                                                             |
| `CODEX_SECURITY_CLOUD_BASE_URL`                                             | Cloud API root for discovery, imports, and scan publication. Defaults to `https://chatgpt.com/backend-api/aardvark`. |
| `CODEX_SECURITY_CLOUD_WEB_URL`                                              | Cloud app URL for repository links when an alternate deployment serves its UI separately.                            |
| `CODEX_SECURITY_EMBEDDINGS_URL`                                             | Local dedupe and findings service embeddings endpoint.                                                               |
| `GH_HOST`                                                                   | GitHub Enterprise host for bulk discovery.                                                                           |
| `CODEX_SECURITY_NO_UPDATE_NOTICE`, `NO_UPDATE_NOTIFIER`                     | Disable interactive update notices.                                                                                  |
| `CODEX_SECURITY_NPM_REGISTRY`, `npm_config_registry`, `NPM_CONFIG_REGISTRY` | Update registry, in precedence order.                                                                                |
| `CI`                                                                        | Disable interactive update notices.                                                                                  |
| `NO_COLOR`, `TERM`                                                          | Disable colored history when `NO_COLOR` is defined or `TERM=dumb`.                                                   |

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

On Windows, credential-home checks require trusted ownership and permissions
through every ancestor, including the volume root. Codex Security can repair
the credential home and its descendants; it does not change ancestor ownership
or ACLs. An error identifies the rejected ancestor and its underlying ACL
problem. A volume root owned by `Everyone` (`S-1-1-0`) is unsupported, even when
the credential home itself is private.

Preserve existing state, then choose a private `CODEX_SECURITY_STATE_DIR` outside
the rejected ancestor and the repository, with a full ancestor chain that passes
the same checks. If the volume root is rejected, another directory on that
volume cannot resolve it; use a separately provisioned volume with trusted
ancestry. On Windows, local runtime bootstrap directories are created beside
`codex-home` in the state directory and removed when the SDK client closes.
They use the same trusted ancestry checks, so sandbox write permissions on
`TEMP` do not prevent runtime preparation. `TEMP`, `TMP`, and scan output
locations are unchanged. Do not change the system volume's owner or ACL to
make a scan run. If no suitable
location is available, this layout cannot provision credentials safely under
the current checks. Sign in again if needed; a new state directory has separate
scan history and does not migrate credentials or reports from the old state
directory.

### Progress and cost

Interactive scans show full-screen progress. CI, redirected output, `--headless`,
and `--verbose` use plain status lines. Results go to stdout; progress and
diagnostics go to stderr. Press `d` in the dashboard for details, then `a` for
all sources, `m` for the main scan, or `1`–`9` for a worker.

Token totals include input plus output; cache reads and writes are subsets of
input. Missing cache-write usage makes the uncached/cache-write breakdown
unavailable. The CLI cannot recover missing information already recorded as zero
by the runtime.

Completed scan history also saves rollout observations under `usage`, alongside
any `cost` estimate. `byRole` separates parent tokens from combined worker tokens.
`window` bounds the counted events, `observedAt` records collection time, and
`tokensUpdatedAt` records the newest token receipt. Partial coverage means some
work could not be measured, including in-flight turns or missing earlier attempts.
The parent can continue after report completion, so final CLI tokens can exceed
the saved measurement window.

During a scan, progress shows when Codex reported the displayed token and cost
totals, in UTC. If the report has no timestamp, progress says so.
In-flight requests may add tokens and cost after that time. When Codex supplies
account allowance, progress shows the percentage used in each reported window
and the time of that reading. On a short terminal, resize the window or press
`d` to scroll through the full readings in Details. With ChatGPT authentication,
progress also says when Codex has yet to report allowance.

`usage.accountRateLimits` saves the latest observed account-wide readings with
their own timestamps, window durations, and reset times. These are historical
observations, not a live allowance check or scan-only consumption. Empty readings
mean allowance was unavailable. There is no token-to-allowance conversion here.

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
report and lists unvalidated candidates as follow-up work. Reaching a configured
limit with a valid finalized report returns `0` by default, or `1` if findings
meet a configured failure threshold.

When Codex reports an exhausted usage limit, Deep Scan cancels active workers
and stops retrying or launching replacements. Completed worker artifacts are retained.

At 80% of a single interactive scan's limit, the dashboard offers a higher total
budget. Enter a larger total, or leave it blank/press Escape to keep the limit.
Work continues while you decide; the old limit remains active until saved.
CI, JSON/JSONL, headless, and verbose scans do not offer increases.

SDK callers can use `onBudgetApproaching({ maxCostUsd, cost, signal })`, returning
a larger total or `undefined`. It runs once per limit without blocking the scan.
Late responses after cancellation/completion are ignored; invalid increases or
save failures keep the existing limit. `onCost(cost, maxCostUsd)` reports changes.

## Review one system across repositories

Use a single directory/path scan when an application spans repositories and you
want Codex to follow relationships between their source files. Put the checkouts
under one parent directory; that parent does not need to be a Git repository.
Select the relevant paths beneath it and supply the shared architecture and
reporting instructions explicitly:

```text
workspace/
├── application/
│   ├── api/       # Git checkout
│   ├── web/       # Git checkout
│   └── shared/    # Git checkout
├── context/
│   ├── architecture.md
│   └── scan-instructions.md
└── results/
```

From `workspace/`, run:

```bash
codex-security scan ./application \
  --mode deep \
  --path api/src --path web/src --path shared/src \
  --knowledge-base ./context/architecture.md \
  --scan-prompt-file ./context/scan-instructions.md \
  --output-dir ./results/system-review
```

Scope paths are relative to `application/`. Context and output paths in this
example are relative to the working directory. Keep results outside the scanned
directory and any enclosing Git worktree. You do not need to add `AGENTS.md` or
`SECURITY.md` to each checkout to pass these documents.

Include both sides of a boundary you want reviewed, such as an API caller and
its authorization implementation. Architecture documents can explain deployment
facts and trust boundaries, but cannot replace missing source evidence. Identify
excluded or unavailable services in the context so their dependencies remain
explicit coverage limitations. Distinguish source that supports an investigation
from locations where you want findings reported.

Record each checkout's commit and local changes before scanning, and keep the
checkouts unchanged while a scan or resume is active. A non-Git parent is recorded
as one directory snapshot, rather than one pinned revision per child repository.
Use the saved scan ID when inspecting results and logs:

```bash
codex-security scans show SCAN_ID
codex-security scans logs SCAN_ID
```

See [scan history and reruns](#scan-history-and-reruns) for the distinction between
continuing an interrupted scan and starting a new run. Neither approach proves
that every possible cross-service path was reviewed; inspect the reported
coverage and unresolved questions alongside findings.

## Bulk scans

Bulk scans run independent repository reviews in one resumable campaign. Shared
knowledge-base documents give each review application context; they do not make
the campaign a joint source review across repositories. For that workflow, use
[one system scan](#review-one-system-across-repositories).

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
CSV scopes are literal paths relative to each checkout, including names such
as `~/src`.
Configured diff or working-tree scopes are rejected unless every affected row
overrides them with a path scope. `--output-dir` requires CSV input.

Use `-c FILE` for shared settings; CSV mode/scope override file values.
`--scan-prompt-file` adds shared instructions before each row's prompt.
`--post-scan-prompt-file` runs a follow-up even after failure, but not after
cancellation or a cost stop.

Concurrency defaults to four repositories. `--max-attempts` defaults to one
attempt per pending repository per invocation. Repeating the command continues
the campaign, skips completed results, and starts pending attempts. Occupied
attempt directories stop that repository and suggest `--recover`.
Completed results are skipped only when their saved contract and seal are valid
and the manifest records a completed scan. Damaged or unsuccessful results get a
new attempt, including with `--recover`, while the old artifacts remain available.
Missing or invalid plugin schemas stop resume without starting another scan.
Changes to project configuration, extracted knowledge-base text, staged document
filenames, direct Codex overrides, or explicit `--plugin-path`/`--python` selections
require a new output directory. Version 1 manifests also require a new directory
because their original knowledge inputs and direct overrides cannot be verified.
Worker and retry counts can change when resuming.

### Recovering failed or interrupted bulk scans

Use the original CSV, output directory, and options:

```bash
codex-security bulk-scan repositories.csv \
  --output-dir /path/outside/repositories/results --recover
```

Recovery requires a matching campaign manifest. It skips completed results
(including saved results with legacy coverage notes) and repositories never started. For each latest
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
New attempts incur new costs. Remaining execution failures return `2`;
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
failure or incomplete/invalid output fails the scan. Deferred candidates remain
follow-up notes and do not fail the scan. An incompatible plugin stops the scan.
Supply the validation prompt again when rerunning.

## Import vendor findings locally

Prefer the provider's supported native JSON from its CLI, plugin, or API. Native
reports can retain details omitted by SARIF. Use SARIF or CSV as compatibility
inputs only for providers and report profiles that support them. A JSON API
summary is not automatically a supported report; follow the provider's acquisition
instructions and retain the original records. The readers detect supported input
formats; `--format json` selects command output, not the input format.

Keep the acquisition format consistent across imports. Depending on the provider,
switching formats can create separate records for the same vulnerability or
replace a richer evidence snapshot with less detail. The importer does not merge
evidence or deduplicate equivalent vulnerabilities across different source IDs.

Use the same vendor input and parser as Cloud publication, selecting a local
repository path instead of a Cloud repository ID or URL. Supported inputs include
Wiz findings, [Snyk Open Source JSON and SARIF](#import-snyk-open-source-findings),
[Endor Labs Finding JSON and SARIF](#import-endor-labs-findings),
[Semgrep Code JSON and SARIF](https://github.com/openai/codex-security/blob/main/docs/scanner-imports/semgrep.md),
and [saved GitHub alerts and GHSA advisories](#import-github-findings-locally-or-to-cloud):

```bash
codex-security publish findings selected-wiz.json \
  --to local --repository ./project --provider wiz \
  --source-key TENANT_ID/vulnerability-finding --dry-run --format json
```

Review the normalized evidence, repository, source namespace, and exclusions.
Run the same command without `--dry-run` to confirm interactively, or add `--yes`
after reviewing the preview. `--to` is required; there is no default destination.
Local import uses the workbench SQLite database and requires no Cloud login,
network connection, or model call. `--dry-run` does not write findings.

Read the saved evidence with:

```bash
codex-security findings imported ./project --format json
```

The repository argument defaults to the current directory. Local imports are
separate from the assessed findings shown by `findings list`: they remain
`not_assessed`, retain the original vendor evidence, and do not create a completed
scan or automatically validate or patch findings. Missing revisions, locations,
and assessment fields stay unknown. When the source includes a repository URL and the local checkout has configured
Git remotes, the URL must match one of those remotes; the importer does not
substitute the checkout's current commit for an unknown scanner revision.

Repeated imports update the same record by repository, provider, source key, and
source finding ID. The result reports created, updated, and unchanged counts.
Keep the source key stable across exports. Records omitted from a later selection
remain stored; omission does not resolve or delete a finding. Excluded records
are reported, and an import with exclusions exits with status 1. The same
supported vendor formats and evidence requirements apply locally and in Cloud.

`scan import --json` and `scan import --csv` remain separate commands for importing
Codex Security's findings schema as a saved scan; they do not accept vendor
exports.

## Import Endor Labs findings

For local or Cloud import, prefer complete native Finding JSON from authenticated
`endorctl`, scoped to one project and context. Omit `--field-mask` and use
`--list-all` to finish pagination:

```sh
endorctl api list --resource Finding --namespace "YOUR_NAMESPACE" \
  --filter 'context.type==CONTEXT_TYPE_MAIN and spec.project_uuid=="PROJECT_UUID"' \
  --list-all --output-type json > endor-findings.json
codex-security publish findings endor-findings.json --to local \
  --provider endor --repository ./project \
  --source-key "YOUR_NAMESPACE/PROJECT_UUID/main" --dry-run
```

Replace the example namespace, project UUID and local repository with your selection.
Review the preview, remove `--dry-run` to confirm, then read the stored evidence
with `codex-security findings imported ./project --format json`. To publish to
Cloud instead, use `--to cloud --repository "CLOUD_REPOSITORY_ID"` with the same
file, provider and source key. The official
[Endor Labs Agent Kit for Codex](https://github.com/endorlabs/ai-plugins/tree/main/plugins/codex/endor-labs-agent-kit)
can help with setup and investigation, but summaries, counts and field-masked
results do not replace complete Finding objects. `endorctl` reads the Endor API;
the importer reads the saved export without maintaining an API connection or
writing changes back to Endor.

Native JSON retains severity, package and advisory data, primary SAST/AI SAST
locations and the scanned commit. Existing self-contained endorctl SARIF 2.1.0
reports are a lossy compatibility format, retaining finding links and UUIDs;
unavailable severity and revisions stay unknown. Both formats use the Endor UUID
within the selected repository and stable source key as identity. Importing SARIF
after native JSON for that UUID updates the same record by replacing its evidence
snapshot, not merging it. Native detail absent from SARIF is removed from the
snapshot. Use native JSON consistently for ongoing imports.

Local and Cloud records remain unassessed source evidence. Local imports use the
SQLite readback described above; Cloud imports use the login, preview,
confirmation and retry flow below.

## Publish findings to Cloud

### Import Snyk Open Source findings

Import **Open Source SCA vulnerabilities only**. Licenses, Code, Container, IaC,
SBOM results and platform backlog ingestion are outside this adapter.

Use the [official Snyk Codex plugin](https://github.com/snyk/studio-recipes/tree/main/plugins/codex)
with its `snyk-findings-export` skill to collect SCA findings from the repository's
Git root. It runs a fresh local scan and writes a `snyk-findings-export/v1` bundle;
it does not retrieve existing platform project findings.

The same saved bundle supports [local import](#import-vendor-findings-locally)
without a Cloud login:

```sh
codex-security publish findings snyk-findings.json --to local \
  --provider snyk --repository ./project \
  --source-key github.com/example/project/main/root/plugin-sca --dry-run
```

Or preview publication to a connected Cloud repository:

```sh
codex-security publish findings snyk-findings.json --to cloud \
  --provider snyk --repository https://github.com/example/project \
  --source-key github.com/example/project/main/root/plugin-sca --dry-run
```

Check the collection's scan outcomes and limitations. Only Open Source SCA
vulnerabilities are imported; other products and licenses are explicit exclusions.
The importer retains the selected finding, native MCP record and collection
context. MCP may shorten descriptions and omit dependency paths. Plugin paths
remain in original evidence because v1 lacks their offset from the Git root.

For automation, prefer native JSON from
`snyk test --file=package.json --json-file-output=snyk.json`. Exit 1 means findings;
stop on other nonzero exits before importing. The existing `--provider snyk`
autodetects a single project object or an `--all-projects` array; any project error
stops the import. Use default ungrouped output, without `--group-issues`.
Native JSON preserves individual dependency paths and remediation fields. Its
paths remain original evidence because it does not establish their Git-root offset.

Open Source SARIF from `snyk test --sarif-file-output=snyk.sarif` remains supported
for compatibility. Its target-relative manifest paths and synthetic line numbers
remain original evidence, without being projected as repository locations or
package manifest paths. All three formats accept either destination. Use a consistent
format and stable source key per repository, branch and scan target, for example
`github.com/example/project/main/root/native-sca` for native JSON. Their source
identities differ: use separate keys when switching acquisition formats. Imports
do not deduplicate across formats or remove earlier imported records.

Known repository claims must
match the selected Cloud repository or, when available, a configured local Git
remote. Unknown repository context still requires selecting the correct target;
the importer does not infer provenance from the current checkout.

Remove `--dry-run` from the selected command to review and confirm the import, or
use `--yes` after reviewing the preview. Read local records with
`codex-security findings imported ./project --format json`. Imported source
evidence is not a Codex assessment. No Snyk-side triage state is changed. See the
[Snyk import guide](https://github.com/openai/codex-security/blob/main/docs/scanner-imports/snyk.md) for format limits and
acquisition details.

### Import Wiz findings

Import selected Wiz package vulnerabilities, SAST findings, repository secrets,
and IaC findings without creating a scan. Imported records retain vendor evidence
and remain **not assessed by Codex**, including when Wiz marks them resolved or
reports an AI verdict. Workload secrets, cloud configuration findings, and external
network findings are not supported by this repository importer. Cloud destinations
currently support connected GitHub and GitHub Enterprise repositories, including
custom Enterprise hostnames. Named Wiz exports do not add other VCS destinations.

#### Select findings and a destination

Use an authorized [Wiz MCP](https://www.wiz.io/blog/introducing-wiz-mcp) or Wiz API
connection to acquire findings and save the supported native JSON. A configured
plugin may provide that connection; an official Codex plugin is not a prerequisite.
The publisher reads the saved records. It does not fetch from Wiz or require a
manual website download. The acquisition path still needs validation against
actual responses from an authorized Wiz tenant; local parser checks do not
establish that qualification.

Inspect the connection's actual response before importing it. MCP summaries,
Wiz Issues, and local Wiz CLI scan results are not automatically compatible with
this finding mapper. Keep the original occurrence IDs and evidence; use the
named collections below when the response contains repository findings.

Before the first import:

1. Select an existing repository in Codex Security Cloud and copy its URL or
   Cloud repository ID. The repository needs an
   authorized environment, but does not need a completed native scan.
2. Read the selected records through the authorized connection and save their
   JSON. For **package vulnerabilities**, include `id`, `name`, `detailedName`,
   `vendorSeverity` (or `severity`), and `vulnerableAsset.id`; retain available
   package, image, and source metadata. For SAST, repository secrets, and IaC,
   retain the named API collections and repository metadata described below.
   Complete the selected pages before importing; a summary or unfinished page
   is not a complete finding selection.
3. Choose a stable source key such as `TENANT_ID/vulnerability-finding`. Reuse it
   for that Wiz tenant and finding class across exports. Do not create a new key
   for each project filter or import; that creates different source identities.
4. Check the ChatGPT account used by your existing file-backed Codex Security
   login. API-key-only and keyring-only logins are not supported for Cloud
   publication. See the credential-storage instructions below.

Prefer the supported native JSON. Existing package-vulnerability CSV reports are
accepted as a compatibility input. **CSV support covers repository package
vulnerabilities (SCA) only; it does not add SAST, cloud posture (CSPM), or complete
Wiz code-to-cloud coverage.** The named JSON readers described below handle their
respective finding families separately.

When a UI report is needed, retain the repository and finding filters in Wiz
**Vulnerability Findings**, choose **Save as → Report**, select **Repository
Branch**, **JSON** or **CSV**, and **Detailed** columns, then download the completed
report. CSV must use the columns described below and a comma delimiter. Plain and
gzip-compressed JSON or CSV are accepted; gzip is detected regardless of the
filename extension. **Raw Event** on Code & Build Scans contains scan metadata
rather than findings.

#### Configure an alternate Cloud deployment

For an alternate Cloud deployment, set `CODEX_SECURITY_CLOUD_BASE_URL` to its
API root before previewing or uploading, for example
`https://cloud.example.test/backend-api/aardvark`. Remote APIs require HTTPS;
HTTP is accepted only for loopback development (`localhost`, `127.0.0.0/8`, or
`::1`). Use a login issued by that deployment and an isolated
`CODEX_SECURITY_STATE_DIR` for testing. The endpoint
does not change your login or sign you into another deployment. An invalid or
empty configured URL stops the import before authentication or network requests.
With the variable unset, the existing production endpoint remains the default.
The older `CODEX_SECURITY_CLOUD_PUBLISH_URL` overrides only the final native scan
publication endpoint; it does not route vendor imports.

If that deployment serves its UI separately, set `CODEX_SECURITY_CLOUD_WEB_URL`
to the full Cloud app URL shown in the browser. The import handoff supplies both
deployment settings. The preview and result include a repository-specific
`cloudUrl`, and terminal completion prints the link. This setting only controls
the return link; all API requests still use `CODEX_SECURITY_CLOUD_BASE_URL`.
For custom API destinations without a configured app URL, completion retains
the manual navigation guidance rather than guessing a UI host or port.

#### Preview and publish

Preview the selection and destination:

```bash
codex-security publish findings selected-wiz.json \
  --to cloud --repository https://github.com/example/project --provider wiz \
  --source-key TENANT_ID/vulnerability-finding --dry-run --format json
```

`--repository` accepts the repository's URL or ID. Both resolve to the same Cloud
destination and resume the same saved submission. This command reads the
authorized destination and current source versions during
preview. It uses the same saved ChatGPT file login as scan publication. The Cloud
repository needs an existing environment; no native scan is required. Review the
Cloud API endpoint, account, repository, environments, findings, and exclusions,
then rerun without
`--dry-run`. The default terminal prompt is No; `--yes` confirms a previously
reviewed input for scripts or the plugin. Without a terminal or `--yes`, no upload
occurs. Existing source findings keep their Cloud environment; new findings use
the repository’s current authorized default. Preview shows the environments that
will receive the selected findings. The terminal preview summarizes severities,
shows up to five finding IDs and titles, and identifies the evidence file and
exclusions. `--dry-run --format json` retains all normalized findings and complete
evidence for inspection. A prompt explicitly includes any records that will be
skipped.

#### Package vulnerability inputs

Native package input can be a Wiz JSON vulnerability report, a vulnerability
finding, an array, a complete `data.vulnerabilityFindings.nodes` response, or JSONL
with one package record per line. The repository package-vulnerability CSV
profile below is also supported. Plain and gzip-compressed files are accepted.
A response that advertises another page is rejected. Complete the requested pages
or save only the explicitly selected records; retain the named collection for
SAST, repository secrets, and IaC.

The CSV mapper requires `ID`, `Name`, `DetailedName`, `AssetID`, `WizURL`,
`CloudPlatform`, and `CloudProviderURL`. Check the actual report headers against
this profile; other Wiz report types use different fields.
For repository imports, `CloudPlatform` must identify GitHub and
`CloudProviderURL` must identify a repository branch. The repository URL must
match the selected Cloud repository or, for local import, one of the checkout's
Git remotes when configured. This also applies when the parsed findings are saved and
read again as normalized JSONL. Other resource types are excluded.

CSV imports use `ID` as the occurrence identity and retain every parsed field,
including unknown columns and quoted multiline values, in `source_data.row`.
Severity comes from `Severity`, then `VendorSeverity`, then `CVSSSeverity`.
Vendor resolution status stays in the original evidence. The importer does not
derive a branch or revision from a tree URL, or treat last-detected time as a
record-update timestamp. Duplicate headers, damaged CSV rows, invalid UTF-8,
and duplicate occurrence IDs among otherwise importable records stop the import.
Review any excluded records in the preview before publishing.

Normalized JSONL is also accepted:

```json
{
  "source_finding_id": "vendor-finding-42",
  "evidence": {
    "title": "Vulnerable example package",
    "severity": "high",
    "source_data": { "id": "vendor-finding-42" }
  }
}
```

Use Wiz's finding `id` (`ID` in CSV), not a CVE, as identity. Keep the source key stable across
exports; a selected project filter does not change the vendor namespace. Confirm
that the selected assets or builds map to this repository. The raw Wiz adapter
retains each record in `source_data`, uses reported severity, and leaves unknown
branch/revision empty. Repository-branch findings retain their repository-relative
file paths; container and other workload paths remain vendor evidence rather than
source-code locations. It does not
fetch from Wiz, assess findings, or change vendor or Cloud triage decisions.
Findings from external network scans are excluded from this package vulnerability
mapping.

#### SAST, repository secrets, and IaC inputs

For SAST, repository secrets, and IaC, save the documented JSON API collection:

| Finding family     | Collection                   | Raw occurrence identity |
| ------------------ | ---------------------------- | ----------------------- |
| SAST               | `data.sastFindings.nodes`    | `sast:<id>`             |
| Repository secrets | `data.secretInstances.nodes` | `secret:<id>`           |
| IaC                | `data.iacFindings.nodes`     | `iac:<id>`              |

The collection identifies the mapping. Bare arrays of these raw findings are
excluded because their overlapping fields do not identify a family. An export
may contain multiple named collections. GraphQL errors and unfinished pages stop
the import. Secret resources must have `type: "REPOSITORY_BRANCH"`; a workload's
relationship to source code does not make it a repository secret.

Each new finding needs a verified source repository URL. Supply `repository.url`
in the finding's repository metadata, or include the matching repository inventory
in `data.versionControlResources.nodes`. For secrets, repository metadata is under
`resource.typedProperties.repository`. The importer joins the inventory's
`repository.id` to that source ID and uses `repository.url`; inventory node IDs,
`providerID`, names, and Wiz UUIDs are not Cloud repository IDs. A supplied URL
must agree with the inventory and with the selected Cloud repository before any
finding is uploaded. Keep each inventory node's `platform` field: `GITHUB`
establishes case-insensitive repository matching on custom GitHub Enterprise
hosts. Fresh imports preserve the reported branch name literally. Duplicate
entries for one repository ID must agree on their platform and repository URL.
For example, this synthetic selection supplies the inventory alongside its SAST
collection:

```json
{
  "data": {
    "sastFindings": {
      "nodes": [
        {
          "id": "finding-42",
          "name": "Untrusted query construction",
          "severity": "HIGH",
          "repository": { "id": "source-repository-1" },
          "filePath": "src/query.ts",
          "startLine": 10,
          "endLine": 12
        }
      ]
    },
    "versionControlResources": {
      "nodes": [
        {
          "repository": {
            "id": "source-repository-1",
            "url": "https://github.com/example/project"
          }
        }
      ]
    }
  }
}
```

#### Preserved evidence

The adapters preserve each selected raw node exactly in `source_data`. Typed
`evidence.details` carries `kind`, verified `repository`, vendor `source_status`,
and family-specific evidence:

| Family             | Evidence retained in typed fields                                                                                                              |
| ------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| SAST               | CWE IDs, first location's end line and snippet, scanner origin and verdict, remediation instructions                                           |
| Repository secrets | Detector rule, type, confidence, vendor validation status, encryption/management flags, introduced commit when supplied                        |
| IaC                | Rule IDs and name, first location's range and matched content, platform, expected/actual content, separate file link, remediation instructions |

Vendor status and verdict remain separate from Codex assessment. A secret's
introduced commit is not its scanned revision. Missing source revisions and scan
IDs stay unknown. A logical IaC resource is retained in the original record and
does not establish that it is deployed. Precise original timestamps remain in
`source_data`; only an explicit record-update timestamp maps to the whole-second
`source_updated_at` field. SAST creation time and IaC last-seen time are not update
timestamps.

#### Convert CSV reports

Native SAST and secret report downloads can be CSV, including gzip-compressed
CSV. Those CSV profiles are not parsed directly. Convert a selected report with a reviewed mapping
for its actual column headers into normalized JSONL, preserving each original row
in `source_data`. Set `details.kind` and `details.repository.url` explicitly after
verifying the source repository. Use the same prefixed occurrence ID shown above
so API and report imports update the same finding; normalized IDs are accepted
exactly as supplied. Never substitute a rule ID, CWE, title, token, or file path
for a vendor occurrence ID. Missing IDs or severity must be corrected at the
source rather than invented.

For repository-secret reports, select `path` and `lineNumber` for source
navigation, detector fields under `rule`, and `vcsDetails.initialCommitHash` only
as the introduced commit. The standard secret metadata API does not supply a
path or line. For IaC reports, explicitly select `filePath`, `startLine`, `endLine`,
`rule.id`, `rule.shortId`, `expectedContent`, `foundContent`, `matchContent`, and
repository/branch metadata. Preserve the original fields; source locations must
be repository-relative, and an end line requires a start line. Keep credential
values out of the metadata selection; the importer does not retrieve or test
credentials or apply remediation instructions.

Inputs must be valid UTF-8. Integer-valued evidence outside JavaScript's safe
integer range is rejected; export those values as strings to preserve them
exactly. Invalid records appear in `excluded` with their source ID and reason.

#### Resume interrupted imports

Requests contain at most 100 findings and respect the Cloud payload limits.
Before uploading, the publisher saves request IDs and bodies privately under
the configured Codex Security state directory. After an uncertain response,
repeat the same command with unchanged input and Cloud API endpoint to resume those
requests. Different deployments have separate saved submissions, including when
their account and repository IDs match. The preview and result include
`cloudApiUrl` so scripts can verify which API received the findings; this is an
API endpoint, not a link to the Cloud UI. A reset
retires the old request without republishing; review and explicitly approve a
fresh invocation.

#### Results and exit codes

Results distinguish completion from partial or interrupted work:

| Status        | Exit code | Meaning                                                                                            |
| ------------- | --------- | -------------------------------------------------------------------------------------------------- |
| `complete`    | 0         | All selected records were acknowledged and their source records read back.                         |
| `partial`     | 1         | The import finished, but some records were excluded locally or rejected by Cloud.                  |
| `interrupted` | 2         | Upload, verification, or receipt persistence stopped; acknowledged work is included in the result. |
| `failed`      | 2         | Preparation failed before uploading; structured output includes the error.                         |

For finding imports, `--full-output` requires `--format json` or `--format jsonl`.
Failed and interrupted imports set the envelope's `ok` to `false`, with
`error.code: "IMPORT_FAILED"`, while retaining available results, receipts, and
counts under `data`. Other full-output format combinations are rejected before
reading the input or contacting Cloud; omit `--full-output` to use those formats.

Ctrl-C and SIGTERM retain exit codes 130 and 143. Interrupted JSON output preserves
`receipts`, `counts`, `failures` with vendor source IDs, `excluded`, `verified`, and
`unacknowledged`. A lost response can mean unacknowledged findings were accepted;
resume the saved submission rather than treating them as never uploaded. When
available, `savedSubmission` identifies the checkpoint to resume by repeating the
same command. Review `error` before retrying; a repository reset retires the old
submission and requires fresh approval. Correct local exclusions or final source
conflicts before preparing a new submission.

Counts are cumulative for the saved submission: a resumed result includes
batches acknowledged by earlier invocations, not just the latest upload attempt.

Terminal progress reports preparation, acknowledged uploads, and verification
on stderr; JSON results stay on stdout. Lookups and readback use at most four
concurrent requests, while uploads remain sequential. Successful receipts are
saved locally. Verification reads the imported source records and checks their
identities and evidence against the receipts. This does not establish a Codex
assessment or visibility in the shared Cloud Findings view.
When available, `cloudUrl` links to the destination repository in Cloud.

### Publish completed scans

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
successful issue IDs separately from sealed artifacts. The CLI and the plugin's
finding-tracking workflow share these records when using the same Codex Security
state directory. Accepted writes remain recorded even if a later issue read fails.
The shared-history migration preserves existing Linear receipts and replaces their
old table. Upgrade CLI and plugin installations together when they share state;
older publishers cannot write to the migrated database.

Republishing creates duplicates unless `--skip-existing` finds a recorded success
for that occurrence, team, and project, including issues created or reused through
the plugin. It does not check remote issues or cover
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

For repository-free canonical records, use `classify-severity --records` (optionally with `--runs N`).
The [records protocol](classify-severity-records.md) accepts immutable Markdown and
report snapshots and delegates model execution to the host.

For saved findings, use exactly one of `--scan` (ID, prefix, or `latest`) and `--scan-dir`.
Omitting `--rubric` runs classification with the [built-in severity rubric](https://github.com/openai/codex-security/blob/main/sdk/typescript/src/default-severity-rubric.ts).
It evaluates attacker access, boundary crossing, additional harm, and evidence for
Critical, High, Medium, Low, and Informational findings. Confidence remains separate
from severity; missing proof alone does not justify a downgrade. An explicit
`--rubric` replaces the default policy completely. Rubrics and repeatable
`--knowledge-base` context accept text, PDF, DOCX, and directories.
Each finding is classified three times by default. `--runs N` accepts
an integer from 1 through 10; SDK options use `classificationRuns` with the same
default and bounds. Each review runs in an independent read-only turn using the
same report, rubric, and supplied context, without tools or source inspection.
The most common normalized severity wins; the highest among tied top counts wins
(`critical` > `high` > `medium` > `low` > `informational`). Exclusion is a separate
vote: exclusions can win by count, but lose ties to assessed severities. The first answer matching the winner supplies its label, rationale,
confidence, and review trigger. All requested reviews must succeed; failures or invalid
answers fail that finding without saving a partial vote. This uses the requested number of model
calls per uncached finding (three by default), including when no custom rubric is supplied, and
requires the same Codex authentication and model access as custom classification.
Codex retains usage for each independent turn. There is no fallback to scanner
severity if classification fails.
`--model` and `--effort` override Codex's configured model and the default medium effort.

Assessments contain `decision` (`assessed` or `excluded`), normalized `level`,
the original `rubricLabel`, rationale, confidence, and a `reviewTrigger` for
missing facts that could change the result. Exclusions have a null level.
Finding/occurrence IDs and input hashes bind each assessment to its evidence.

Successful assessments checkpoint immediately in local SQLite. Retries reuse
matching evidence, rubric, context hashes, and classification run count; failed/canceled runs keep completed
work. Default-rubric assessments use `source: "rubric"` and a content hash; former
no-rubric inherited assessments have no rubric hash and are automatically
reclassified on the next classification run. Changes to the bundled policy or
switching between default and custom policies also invalidate matching checkpoints.
The result and checkpoint record `classificationRuns`; changing the count, or
reusing an older checkpoint with no recorded count, triggers fresh classification.
Older results remain readable; publication does not silently run a model.
Use `--reprocess` to replace assessments, including when changing only model
or effort. A successful
run also writes `severity-classification.json`, but publication reads the database. Original findings and sealed artifacts remain
unchanged.

Repeat `--finding-id ID` for a subset from the selected scan. Dedupe's
`uniqueFindingIds` can represent findings from another scan; replace an outside-scan
representative with a member of its `duplicateGroups` entry from this scan.
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
  type FindingsDocument,
} from "@openai/codex-security";
import { readFile } from "node:fs/promises";
import { join } from "node:path";

// Assess supplied reports in memory.
const classification = await classifySeverity(findings, {
  rubricPath: "/path/to/policy.md",
  knowledgeBasePaths: ["/path/to/context.md"],
});

// Save assessments for a scan ID or sealed directory.
await classifyScanSeverity("SCAN_ID", { rubricPath: "/path/to/policy.md" });
const scanFindings = (
  JSON.parse(
    await readFile(join(scanDirectory, "findings.json"), "utf8"),
  ) as FindingsDocument
).findings;
const scanFindingIds = new Set(
  scanFindings.map((finding) => finding.findingId),
);
// dedupeResult was produced by deduplicating this same scan.
const selectedIds = dedupeResult.uniqueFindingIds.map((representative) => {
  if (scanFindingIds.has(representative)) return representative;
  return dedupeResult.duplicateGroups
    .find((group) => group.includes(representative))!
    .find((member) => scanFindingIds.has(member))!;
});
await classifyScanDirectorySeverity(scanDirectory, {
  rubricPath: "/path/to/policy.md",
  findingIds: selectedIds,
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
evidence/metadata. Imported reports may lack severity or occurrence IDs; omitting
`rubricPath` uses the built-in policy even when a scanner severity is present.
Scan wrappers persist checkpoints (including for
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
source, CODEOWNERS, blame, and history; it does not read uncommitted source or assign tickets.
Finding location paths are relative to the Git worktree root, including when
`--source-root` points to a subdirectory. A location for `src/handler.ts` keeps
that prefix; a location of `handler.ts` refers to the root file. Rebase imported
subdirectory-relative locations to repository-relative paths before suggesting
owners.

Linked worktrees and bound separate Git directories are supported; borrowed
external object stores such as `git clone --shared` are rejected.

CODEOWNERS declarations take priority over Git history, following
[GitHub's CODEOWNERS rules](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners).
The last matching rule wins, and the command returns its first declared owner.
Git history is the fallback when no declared owner applies.

Results preserve IDs and report `identified`, `abstained`, or `error`. Identified
owners include a declared GitHub user, team, or email, or an observed Git
name/email, with a reason and checked citations.
Git identities do not establish current employment or tracker accounts; match
accounts before assigning. Use a checkout matching the findings.

An owner can be a Git name/email identity, a GitHub user or team handle,
an email-only identity, or `null`. Example JSON excerpt:

```json
{
  "schemaVersion": 2,
  "results": [
    {
      "owner": {
        "kind": "group",
        "provider": "github",
        "handle": "example/maintainers"
      }
    }
  ]
}
```

The command uses scan-default model/effort; override with `--model` and `--effort`.
The model receives collected evidence with tools/network disabled. Exit `0`
includes abstentions; `2` means invalid input or a failed recommendation, while
retaining other results. Cancellation uses `130` or `143`.

```ts
import { suggestOwners } from "@openai/codex-security";

const owners = await suggestOwners("/path/to/repo", result.findings.findings, {
  reasoningEffort: "high",
});
for (const { owner } of owners.results) {
  if (owner === null) continue;
  console.log("handle" in owner ? owner.handle : owner.email);
}
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
| `findings imported [REPOSITORY]`                      | Read locally imported, unassessed vendor evidence.         |
| `findings false-positive OCCURRENCE_ID --reason TEXT` | Dismiss a finding while the reason applies.                |

Without an ID, `scans show` selects the latest completed scan, while `scans logs`
selects the latest scan of any status. After a successful scan followed by a
failed or active scan, these defaults refer to different runs. Human output
identifies the selected run, labels its saved update time, and gives matching
commands with its full scan ID:

```bash
codex-security scans show SCAN_ID
codex-security scans logs SCAN_ID
```

Completion summaries include that ID and the saved results directory. Failure
summaries include the same navigation when the current run was registered, plus
the last observed phase when available. A failure before registration has no
scan ID. The handoff uses that run's registration receipt without querying scan
history. Inspect its saved status before choosing resume or rerun, and supply
the original custom prompt files for reruns. Structured history and log output
and command selection defaults are unchanged.

Recipes save settings and authentication choice, not credentials. Reruns use the
current checkout/context files and do not reload project files. Supply replacement
scan and custom-validation prompts when the original used them:

```bash
codex-security scans rerun SCAN_ID --scan-prompt-file instructions.md
```

Saved path scopes remain relative to the repository. Names such as `~` and
`~/source.ts` are replayed literally; they do not select the home directory.

A rerun creates a new scan. When the original has saved input identities, the
rerun reports changes to the scan instructions or knowledge base. `scans show`
includes the saved scope, runtime and Deep Scan settings, instruction digest,
and knowledge snapshot/document digests. JSON includes these identities under
`recipe.scanInputs`. The instruction digest covers the exact UTF-8 prompt text;
document digests cover the extracted text workers receive. These identities
describe supplied inputs, not proof that a model read or followed every passage.

History lives in `$CODEX_SECURITY_STATE_DIR/workbench.sqlite3`, or
`$CODEX_HOME/state/plugins/codex-security/workbench.sqlite3`. Keep it private,
writable, and outside the target repository. Session logs may contain sensitive
data even though scan recipes do not store credentials.

Codex may compress saved session logs to `.jsonl.zst`. Plain and compressed logs
work on all supported Node.js versions, including logs, feedback attachments,
usage accounting, and saved-session discovery for resume. A bundled decoder
reads concatenated frames and reports truncated streams as collection errors.

### Resuming an interrupted Deep Scan

```bash
codex-security scans list --scan-root /path/to/security-scans
codex-security scans resume SCAN_ID
```

The scan must still be `running`, with its original checkout, output directory,
and Codex session in the same state directory. Checkout identity, revision, and
contents must match. Completed, failed, and canceled scans need a rerun instead.

Resume retains scan ID, completed workers, artifacts, accumulated cost, and saved
settings/instructions. Knowledge-bearing scans save their extracted documents in
the private `.scan-knowledge.json` continuation file beside the scan artifacts.
Resume verifies and uses that snapshot even if the original files changed or were
deleted. Preserve it with the scan directory; canonical reports do not embed its
document text. Old individual scans without a saved knowledge snapshot require a
new scan when they used a knowledge base. Old scans without a knowledge base and
bulk campaigns with an already-bound snapshot retain their existing resume path.
New records save the authentication mode, explicit safety
identifier, and post-scan prompt; older records cannot reconstruct missing values.
A failed connection leaves the scan available for another resume attempt.
Compatible scans can resume after plugin updates; sealed results keep their
original producer version. Unsupported artifacts are rejected without rewriting them.

For bulk scans, use [bulk recovery](#recovering-failed-or-interrupted-bulk-scans)
to update campaign receipts. Individual resume does not update `results.jsonl`.

### Matching saved scans

Matching uses sealed artifacts and cached decisions unless `--force` is supplied.
Comparisons classify findings as new, persisting, reopened, not observed, resolved,
or unknown. An absent finding in the later scope is not observed; absence alone
does not verify remediation. A finding is resolved only after it was explicitly
closed as already fixed. Excluded paths and uncertain matches remain unknown.
One comparison ID is compared with the latest completed scan.

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

Export saved findings and threat models without rerunning a scan or signing in.

### Export findings

To save a completed scan's findings as SARIF, run:

```bash
codex-security export /path/to/scan-results --output results.sarif
```

Replace `/path/to/scan-results` with the results directory printed by `scan`.
The command writes `results.sarif` in the current directory. The output directory
must already exist.

SARIF is the default format, and `./results.sarif` is the default output path.
Use `--export-format json` or `--export-format csv` to choose another format.
To select a saved scan by its ID and export JSON, run:

```bash
codex-security export --scan SCAN_ID --export-format json --output findings.json
```

Replace `SCAN_ID` with the ID printed by `scan`. If you omit both the results
directory and `--scan`, `export` uses the current repository's latest completed
scan.

JSON preserves the saved findings. CSV marks them open, omits local triage state,
and retains distinct occurrence IDs. It escapes spreadsheet-formula prefixes and
leading apostrophes; import removes the escape. Use JSON to recover ambiguous
apostrophes from older CSV exports.

For SARIF, `--source-root` adds source-line fingerprints that help tools match
findings across scans. Before changing the scanned files or applying patches,
run the export from the scanned repository's root:

```bash
codex-security export /path/to/scan-results --source-root . --output results.sarif
```

The `.` selects the current directory as the source root. Its source files must
be unchanged since the scan. `--source-root` is supported only for SARIF.

If export fails, it exits with `2`. Fix the reported error and rerun the export;
the saved scan remains available, so you don't need to run another scan.

### Export a threat model

To save a scan's threat model as Markdown, run:

```bash
codex-security export --scan SCAN_ID --artifact threat-model --output threatmodel.md
```

Threat-model exports default to `./threatmodel.md`. Standard, Deep, Diff, and
policy workflows retain models when available; component/bulk runs save one per
child. With an explicit results directory, you can export a saved threat model
even if the workflow has not completed or later failed. Missing models return
an error rather than generating or substituting one. Historical models in sealed
scans need a matching manifest digest.

To print a policy workflow's saved threat model, pass its results directory and
`--output -`:

```bash
codex-security export /path/to/policy-results --artifact threat-model --output -
```

`--output -` emits only artifact content, with diagnostics on stderr. Markdown
and CSV stdout cannot combine with JSON command output. Exporting into a checkout
does not make the model scan input; pass it with `--knowledge-base`.

### Export with the SDK

Use `exportArtifact()` to export saved results from TypeScript:

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

`ScanResult.threatModel` and `threatModelPath` expose the retained model and
document, or null. Export still works if the document could not be written.

### Use exports in CI

Save each scan's results outside the checkout and set a severity threshold:

```bash
SCAN_ROOT="$(mktemp -d)"
codex-security scan . --diff origin/main \
  --output-dir "$SCAN_ROOT/results" --json --fail-on-severity high \
  > "$SCAN_ROOT/findings.json"
```

| Exit code     | Meaning                                                                  |
| ------------- | ------------------------------------------------------------------------ |
| `0`           | Complete report-only scan or passing severity policy.                    |
| `1`           | Severity policy violation.                                               |
| `2`           | Invalid input, runtime error, target change, or required-output failure. |
| `130` / `143` | Interrupt / termination.                                                 |

If the scan exits with `2`, `130`, or `143`, skip export and upload. After a scan
exits with `0` or `1`, use these steps:

1. Export from that run's results directory. Using the explicit directory keeps
   concurrent scans from changing which results are selected:

   ```bash
   codex-security export "$SCAN_ROOT/results" --source-root . \
     --output "$SCAN_ROOT/results.sarif"
   ```

2. If export succeeds, upload the SARIF file.
3. If the scan exited with `1`, keep the CI job failed so the severity threshold
   remains enforced.

JSON scans have no interactive controls. `validate`, `login`, and `logout` reject
`--json`. Use `validate --output-schema FILE` for a schema-checked JSON assessment.
For GitHub Actions setup, see the
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

## Import GitHub findings locally or to Cloud

Acquire code-scanning findings with the existing `import github` collector and
save its complete JSON output. In Codex, the official
[GitHub Codex plugin](https://github.com/openai/plugins/tree/main/plugins/github)
can help select the repository, alert numbers and ref through GitHub's MCP
server; pass that selection to the collector. This integration reads
code-scanning alerts and GHSA advisories. It does not import Dependabot or
secret-scanning alerts or write back to GitHub. Preview local storage with a
repository path:

```bash
codex-security import github example/project --format json > /path/outside/repository/alerts.json
codex-security publish findings /path/outside/repository/alerts.json \
  --to local --provider github --repository ./project \
  --source-key github.com/example/project/code-scanning --dry-run --format json
```

Or preview publication to a connected Cloud repository:

```bash
codex-security publish findings /path/outside/repository/alerts.json \
  --to cloud --provider github --repository https://github.com/example/project \
  --source-key github.com/example/project/code-scanning --dry-run --format json
```

The importer fetches every page, retrieves alert details, and retains the selected
ref's instance. It writes the saved input for publication; no website download or
hand-written JSON mapping is needed. Use `--github-alert NUMBER` repeatedly for
selected alerts or `--github-ref REF` for another ref. Defaults are open alerts on
the default branch. MCP list calls are paginated separately, and raw MCP/API
responses are not the saved import format accepted by `--provider github`.

The importer uses GitHub CLI authentication (`gh auth login`) and `GH_HOST`;
the plugin's connection does not sign in `gh`. Reading alerts requires
[code-scanning access](https://docs.github.com/en/rest/code-scanning/code-scanning#list-code-scanning-alerts-for-a-repository):
**Code scanning alerts: read** for a fine-grained token, or `security_events` for
a classic token (`public_repo` is sufficient for public repositories). The source
repository must have code scanning available. For Cloud publication, the
destination must be connected in the selected Cloud account. For local import,
the source repository must match a configured Git remote when remotes are
available; no Cloud login is required to store the acquired evidence.

Review the destination, source, exclusions and evidence in the preview. Repeat the
selected command without `--dry-run` and confirm it, or add `--yes` for a
previously reviewed input. Local persistence and readback follow the
[local import flow](#import-vendor-findings-locally); use
`codex-security findings imported ./project --format json` to read the records.
Cloud authentication, batching, saved receipts, partial results and
interrupted-upload recovery follow the [publication flow](#import-wiz-findings).
JSON, JSONL and gzip are supported. Save complete import output without field or
token filters or `--full-output`.

Use a stable source key for the GitHub host, repository and finding family.
Code-scanning identities include the selected ref, so branches retain separate
evidence. The original alert, rule, scanner, location, revision and source state
remain attached. An alert-wide dismissal takes precedence over the selected
instance's open/fixed state. Missing security severity stays `unknown`;
SARIF error/warning/note levels are not vulnerability ratings. Imported evidence
remains unassessed by Codex.

The SDK offers the same preview and publication boundary for Cloud:

```ts
import {
  importGitHubCodeScanningAlerts,
  normalizeGitHubCodeScanningAlerts,
  prepareNormalizedExternalPublication,
} from "@openai/codex-security";

const alerts = await importGitHubCodeScanningAlerts({
  repository: "example/project",
});
const prepared = await prepareNormalizedExternalPublication(
  normalizeGitHubCodeScanningAlerts(alerts),
  {
    provider: "github",
    repository: "https://github.com/example/project",
    sourceKey: "github.com/example/project/code-scanning",
  },
);
console.log(prepared.preview);
// After reviewing the preview:
const receipt = await prepared.publish();
```

For local storage, pass the same normalized evidence to
`prepareNormalizedLocalImport()` with `repository: "/path/to/project"`, inspect
its preview, and call `import()`. `prepareLocalExternalImport()` accepts the saved
import file directly. Read records with `listLocalExternalFindings({ repository })`.

### Import GHSA advisories separately

**Importing a GHSA advisory does not establish an installed dependency or
applicability to the destination repository.** Repository advisories are
disclosures maintained by a repository; global advisories describe affected
software in GitHub's public advisory database. Both are evidence for
investigation, not Dependabot alerts. Check the repository’s dependency versions
and applicability separately.

```bash
# Read only published advisories for this repository.
codex-security import github-advisories example/project --format json > /path/outside/repository/advisories.json

# Select individual public database records without enumerating the database.
codex-security import github-advisories example/project \
  --github-advisory-source global --github-advisory GHSA-2345-6789-cfgh \
  --format json > /path/outside/repository/advisories.json

codex-security publish findings /path/outside/repository/advisories.json \
  --to cloud --provider github --repository https://github.com/example/project \
  --source-key github.com/example/project/security-advisories --dry-run --format json
```

For local storage, use the same advisory file, provider and source key with
`--to local --repository ./project`. Follow the [local import flow](#import-vendor-findings-locally)
to review, confirm and read the stored evidence.

`--github-advisory-source` defaults to `repository`. Repeat `--github-advisory`
to select exact IDs from that API, regardless of advisory state. Repository
lists default to `--github-state published`; `draft`, `triage`, and `closed`
require explicit selection. A nondefault state cannot be combined with exact
IDs. Global selection requires at least one ID and never lists the advisory
database. Both readers use `GH_HOST` and GitHub CLI authentication by default;
the SDK also accepts `githubHost` and `githubToken`. Private or unpublished
[repository advisories](https://docs.github.com/en/rest/security-advisories/repository-advisories#list-repository-security-advisories)
require **Repository security advisories: read**, or the classic `repo` or
`repository_advisories:read` scope, plus access to the advisory. Public records
need no additional advisory permission.

Review the saved evidence before local import or Cloud publication, including any
selected private advisories. Acquisition failure returns no partial selection.
Both destinations report invalid records as exclusions. Cloud publication retains
acknowledged receipts if a later batch or readback fails.

Advisory evidence retains GHSA/CVE IDs, affected version ranges, available
patched versions, source status and original JSON. It does not infer an installed
version or source location. Global advisories omit a source repository; the
explicit local or Cloud destination binds the import for investigation. Repository
advisories retain their source repository and check it against the Cloud target
or configured local Git remotes when available. Withdrawal remains vendor
state, and all imported evidence remains not assessed by Codex. Use a separate
source key from code-scanning alerts; shared advisory IDs do not combine source
records from different providers.

In the SDK, call `importGitHubAdvisories()` and `normalizeGitHubAdvisories()`
with `prepareNormalizedExternalPublication()` for Cloud or
`prepareNormalizedLocalImport()` for local storage as described above.
`importGitHubAdvisories()` defaults to `{ source: "repository", state: "published" }`; use
`{ source: "global", advisoryIds: ["GHSA-2345-6789-cfgh"] }` for selected database
records. Both forms require `repository: "OWNER/REPO"` as source or target context.

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

Hosts that manage their own model execution can use `codex-security validate --records`.
This mode exchanges a review over JSON-RPC and checks the returned answer against a caller-provided schema.
See [host-provided standalone validation](validate-records.md) for the protocol and execution requirements.

`validate` assesses candidates from local source evidence without building the
target, executing application code, running tests or PoCs, or contacting services.
It uses a read-only sandbox. Standard, Deep, and diff scans retain their existing
validation, and `patch` still fixes and verifies findings. Both commands accept files
or literal text and work in the current directory. Saved finding/occurrence IDs
select their original repository for patching.

Basic patching also works in ordinary directories and Git worktrees before their
first commit. Directory change tracking excludes `.git` and `.svn` metadata.

```bash
codex-security validate "Possible SQL injection" --effort high
codex-security validate findings.json --knowledge-base ./context --context "Check the tenant boundary."
codex-security validate findings.json --context-file context.md --output-schema result.schema.json > assessment.json
codex-security patch OCCURRENCE_ID
codex-security patch --scan SCAN_ID --severity high --json
codex-security patch --scan SCAN_ID --assess-patch-risk --create-pr
```

Context inputs are optional and can be combined:

- `--context TEXT` adds inline security context or reviewer feedback.
- `--context-file PATH` reads a single UTF-8 file.
- Repeat `--knowledge-base PATH` to add files or directories. It uses the scan
  document loader: UTF-8 text (including JSON and YAML), PDF, and DOCX. Directories
  are searched recursively; binary files, symlinks, and Git metadata are skipped.

Inline and file context are included in the prompt. Knowledge-base documents are
prepared in a temporary directory for Codex to read during the assessment, then
removed. Context is separate from findings and checked against source evidence;
feedback alone does not dismiss a finding.

By default, `validate` prints a readable assessment without JSON-schema checking.
`--output-schema PATH` supplies the schema to Codex **before generation** using
native structured output. The CLI also checks the completed JSON before writing
stdout; it does not convert a prose assessment into JSON afterward. Invalid JSON
or a schema mismatch fails with exit code 2 and no assessment on stdout.

Use a self-contained schema in the subset supported by the selected Codex model
and provider. The local checker uses JSON Schema 2020-12, but accepting a schema
locally does not guarantee provider support. Keep the schema small and use it only
when the caller needs structured results. It checks the result's shape, not whether
the security conclusion is correct. Relative paths resolve from the current directory.

The validator no longer writes reports. Save the assessment by redirecting stdout:
`codex-security validate findings.json > assessment.md`. For runtime proof, run a
separate reproduction step. Missing facts are reported as proof gaps; a finding
supported by source evidence does not require runtime reproduction.

### Structured validation example

Save two synthetic candidates as `findings.json`:

```json
[
  {
    "id": "candidate-1",
    "title": "Missing tenant filter",
    "location": "src/invoices.ts:24"
  },
  {
    "id": "candidate-2",
    "title": "Anonymous access",
    "location": "src/routes.ts:18"
  }
]
```

Save this minimal schema as `result.schema.json`. Each `report` contains the
assessment's source evidence, counterevidence, confidence, context used, and proof
gaps; callers can instead define separate fields for those details.

```json
{
  "type": "object",
  "additionalProperties": false,
  "required": ["assessments"],
  "properties": {
    "assessments": {
      "type": "array",
      "items": {
        "type": "object",
        "additionalProperties": false,
        "required": ["id", "disposition", "report"],
        "properties": {
          "id": { "type": "string" },
          "disposition": {
            "type": "string",
            "enum": ["reportable", "suppressed", "not_applicable", "deferred"]
          },
          "report": { "type": "string" }
        }
      }
    }
  }
}
```

Run from the repository directory:

```bash
codex-security validate findings.json --output-schema result.schema.json > assessment.json
```

An illustrative result is below. Actual decisions depend on the repository;
this example assumes a tenant filter exists but deployment routing is unavailable.
Both candidate IDs remain in the output, including the unresolved claim.

```json
{
  "assessments": [
    {
      "id": "candidate-1",
      "disposition": "suppressed",
      "report": "Missing tenant filter: src/invoices.ts:24 filters by the authenticated tenant, defeating the claimed cross-tenant read. Static confidence: high. No material proof gap for this claim. No additional context supplied; no runtime checks performed."
    },
    {
      "id": "candidate-2",
      "disposition": "deferred",
      "report": "Anonymous access: src/routes.ts:18 has no local authentication guard. An upstream gateway may provide one, but its routing configuration was not supplied. Proof gap: whether unauthenticated traffic can reach this route. Static confidence: low. No additional context supplied; no runtime checks performed."
    }
  ]
}
```

### Patch existing findings

`--scan latest` uses the current repository's latest completed scan. Patching
supports JSON for saved findings, literal text, and files. Each finding gets a
saved Codex desktop task. `--model` and `--effort` control the model.
Saved-scan patching and fix verification use the complete sealed finding evidence
and exclude findings that are currently closed in triage.

`--validation-prompt-file PATH` supplies setup, authorized targets, expected
results, and cleanup for dynamic validation. It works with saved findings,
text/files, and Linear inputs. Paths resolve from the invocation directory, even
when the finding belongs to another repository. The file must be nonempty and
regular, is read before patching, and cannot combine with `--resume-pr`.

Use `--verification-mode static` to assess a patch from source and diff evidence
without installing dependencies or running builds, tests, reproducers, or the
application. Validation instructions become questions for that source review.
The default is `standard`, which retains the existing verification checks.
Static results identify the evidence and state that runtime checks were not
performed; material proof gaps can still block verification.

```bash
codex-security patch finding.md --verification-mode static
codex-security verify-fix finding.md --verification-mode static
```

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
GitLab merge requests stay within the origin project; a fork merge request with
the same branch name is not reused. GitLab descriptions display the report in a
blockquote so report text cannot execute quick actions. The report contents,
including code, HTML, and math, retain their original text.

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

`--verification-mode static` selects source-only assessment, as described above
for `patch`. Omit it or use `--verification-mode standard` for the default checks.

Results include evidence and `fixed`, `still_vulnerable`, or `inconclusive` status.
`--json` returns structured output. Exit codes are `0` when all findings are
fixed, `1` when any remain vulnerable, and `2` for inconclusive/failed checks.
Authentication and execution failures print diagnostics on stderr and return
`status: "failed"`, `code: "VERIFICATION_FAILED"`, and `message` with `--json`
or `--format jsonl`. With JSON/JSONL `--full-output`, failures use an `ok: false`
error envelope. Other formats retain stderr-only failures. Interruptions retain
exit codes `130` and `143` without a result.

## Command discovery and integrations

Use `--llms` for the command manifest, `scan --schema --format json` for its
schema, and `completions bash|zsh|fish` for shell completions. Scan output supports
`--format toon|json|yaml|jsonl` and `--full-output`.

`skills add` syncs generated CLI command guidance; it does not install the full
Codex Security plugin. `mcp add` registers the CLI as an MCP server, exposing
only read-only `info` because the transport cannot cancel scans. For the plugin's
scan, triage, patch, and verification workflows, see the
[agent workflow guide](https://github.com/openai/codex-security/blob/main/docs/agent-workflows.md).

For local findings storage, deduplication, and custom endpoints, see the
[findings guide](findings-service.md).

### Hosted Standard scan

`codex-security scan --host` runs one versioned JSON-RPC invocation with an explicit host executor. Use it alone; it never performs local inference. See [the hosted scan protocol](hosted-scans.md) for input, filesystem, artifact, usage, and cancellation requirements.

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
