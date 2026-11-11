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

## Find a workflow

- [Sign in or configure a provider](#authentication).
- [Scan a repository or selected paths](#scan-options-and-output),
  [configure a Deep Scan](#configure-deep-scans), or
  [save project settings](#project-files).
- [Review one system across repositories](#review-one-system-across-repositories)
  or [run independent bulk scans](#bulk-scans).
- [Choose an import command](#import-vendor-findings-locally) to save a scan,
  collect upstream alerts, or store vendor evidence locally or in Cloud.
- [Inspect saved scans and rerun them](#scan-history-and-reruns),
  [classify severity](#classify-finding-severity), or
  [suggest owners](#suggest-finding-owners).
- [Validate and patch findings](#validate-and-patch-findings) or
  [verify an existing fix](#verify-fixes).
- [Publish to Cloud](#publish-findings-to-cloud) or
  [Linear](#publish-completed-scans-to-linear), or [export results](#exports-and-ci).
- [Draft a security policy](#generate-a-security-policy).
- [Choose which checked-in credentials to report](#checked-in-credentials).
- [Use a hosted executor](#hosted-standard-scan) or
  [run bulk scans in containers](#containerized-bulk-scans).

## Updating the CLI

Run `cs --update` to update an npm global installation managed by the running
Node distribution. It uses Node’s bundled npm, the public npm registry, and
disabled lifecycle scripts. If you use a custom registry or proxy, run your
package manager’s update command directly.

For a project dependency, `cs --update` prints the package-manager command for
you to run in the declaring project. For other global installations it prints
the corresponding package-manager command and installation location. For npx,
use `npx @openai/codex-security@latest` on the next run. For a standalone
release, download and extract the latest release.

Interactive update notices use the same installation detection. Set
`CODEX_SECURITY_NO_UPDATE_NOTICE=1` to disable these notices. Explicit updates
are available with notifications disabled.

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
environment API key are available. A dedicated sign-in takes precedence. After
`codex-security logout`, the prompt skips the ambient sign-in until you log in
again. Noninteractive commands prefer
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

For a scan using a custom native provider, `auto` and `api-key` use the
environment variable declared by `model_providers.<id>.env_key`, including
when a Codex file profile selects that provider. Set that variable before
starting the scan. To use `--auth chatgpt`, select a provider configured for
account authentication. A custom provider that requires its own key cannot
honor that combination.

Stored OpenAI credentials live in
`$CODEX_SECURITY_STATE_DIR/codex-home`, or
`$CODEX_HOME/state/plugins/codex-security/codex-home`. Keep this private home
outside the target and every enclosing Git worktree. It also serves providers
with `requires_openai_auth = true`.

If you manually hard-linked the two homes’ `auth.json` files, keep both homes
accessible when running `codex-security logout`. When the CLI verifies the
two hard links, it removes the private link before invoking native logout.
If the ambient home is unavailable, the configured credential store handles
logout normally.

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

If you use file-based ChatGPT credentials with both Codex and Codex Security,
run `codex-security login` before your first scan or status check to give Codex
Security its own session. An imported sign-in shares a single-use refresh token.
When either client renews it, the other client's next refresh can fail even
while its login status reports that it is signed in.

If Codex Security reports that the refresh token was already used, run
`codex-security logout`, then `codex-security login`. If your Codex CLI or app
reports that error, sign out and sign back in there.

For other refresh errors, check `codex-security login status`. Retry if the
sign-in recently changed. Otherwise run `codex-security logout`, then
`codex-security login`.
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
discovery workers, and `scan --patch`. Standalone `validate`,
`patch`, and `verify-fix` accept the same `--codex daybreak=true` override.
Threads created by these commands retain the setting when resumed in Codex.
Scans use isolated configuration, so set it on the CLI, SDK client, or project
file even if it is enabled in your personal Codex configuration.

For the plugin inside Codex, use the desktop Daybreak toggle or `/daybreak` in
an interactive CLI session. For headless Codex, use `codex exec -c daybreak=true`
or set top-level `daybreak = true` in the configuration loaded by the runner.
Deep Scan inherits the active turn's effective access program from its saved
Codex session, including an explicit Standard selection. Discovery workers retain that selection when resumed. If the host does not supply a
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
explicitly. If you use `--max-cost` or the SDK's `maxCostUsd`, choose a model
with built-in pricing so the scan can enforce the limit.

```bash
codex-security scan /path/to/repository \
  --auth api-key --model "<model>" --cyber-access-program daybreak_blue
```

In the SDK, select your model through `codexOverrides.model` and pass
`auth: "api-key"` and `cyberAccessProgram: "daybreak_blue"` in the scan options.
Use `--mode deep` in the CLI or `mode: "deep"` in SDK scan options for Deep Scan.
The selection reaches discovery workers, including resumed workers. See [Select a Cyber access program](#select-a-cyber-access-program)
for configuration precedence and the API-key feature setting.

`access_programs.cyber` is a Responses API field. Use `--cyber-access-program`
instead of passing it as a `--codex` configuration key.

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

### Hugging Face compatibility

In compatibility testing, Codex 0.166.0 sent its scan-completion tool inside a
`namespace` and could request `web_search`. Hugging Face's published Responses
implementation accepts `function` and remote `mcp` tool declarations. A named
Hugging Face scan provider is deferred until the scanner and router can exchange
the tools a complete scan requires. [Hugging Face's implementation notes](https://huggingface.co/docs/inference-providers/en/guides/gpt-oss#responses-api)
and [request schema](https://github.com/huggingface/responses.js/blob/0e3e84c469a9f59ad16e2eb3a0d6f1c4de637a7b/src/schemas.ts#L219-L232).

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

### Google Cloud Vertex AI cost estimates

The SDK estimates Standard online inference costs for OpenAI models served by
Google Cloud's Model as a Service (MaaS). Rates are in USD per million tokens.
[Google Cloud partner model pricing](https://cloud.google.com/model-garden/partner-models/pricing)
and [OpenAI model locations](https://docs.cloud.google.com/gemini-enterprise-agent-platform/models/maas/openai).

| Managed model ID           | Location                | Input | Cached input | Output |
| -------------------------- | ----------------------- | ----: | -----------: | -----: |
| `openai/gpt-oss-120b-maas` | `global`                | $0.09 |        $0.09 |  $0.36 |
| `openai/gpt-oss-20b-maas`  | `us-central1` (retired) | $0.07 |       $0.007 |  $0.25 |

Google publishes a cache-hit discount only for 20B, so the estimator uses the
ordinary input rate for cached 120B tokens. Google retired the managed 20B
endpoint on October 21, 2026. The SDK retains its rates for historical usage.
[Google Cloud retirement schedule](https://docs.cloud.google.com/gemini-enterprise-agent-platform/models/deprecations/open-models).

To estimate recorded usage locally, pass the managed model ID and the GCP
provider to `estimateScanCost`.

```ts
import { estimateScanCost } from "@openai/codex-security";

const cost = estimateScanCost(
  "openai/gpt-oss-120b-maas",
  { input_tokens: 1_000_000, output_tokens: 500_000 },
  { provider: "gcp" },
);
// cost?.estimatedUsd is 0.27.
```

Google documents the managed GPT OSS IDs on its shared chat-completions API.
The bundled Codex `gcp` provider uses Google's Responses API with a separate
frontier model catalog. Google has published no Standard token rates for that
catalog, including GPT-6 Astra, GPT-6.1 Sol, GPT-6.1 Terra, and GPT-6 Luna.
Those scans record token usage and require a published price to use
`--max-cost`. Self-deployed Model Garden endpoints incur infrastructure charges.
[Google Cloud's preview announcement](https://cloud.google.com/blog/products/ai-machine-learning/google-cloud-brings-openai-models-to-customers).

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

### Checked-in credentials

Codex looks for credentials in the selected source, including tests and unused
code. It assesses exposure offline. Severity reflects who can read the value
and what access the evidence supports. Live status stays unknown unless the
issuer or credential owner provides evidence.

If another scanner handles known-format API keys and tokens, add one line to
the repository’s root `SECURITY.md`:

> Skip standalone findings for known-format API keys and tokens.

This rule guides reporting. Codex still looks for hardcoded passwords, custom
credentials, and bugs such as a server token sent to a browser. Remove the rule
to restore the default, or put “Report standalone findings for known-format API
keys and tokens” in a component’s `SECURITY.md` to opt that component back in.

For one scan, override repository policy with an instruction file. Project
configs use `scan.instructions_file`, and the SDK accepts `scanPrompt` or
`scanPromptFile`.

```bash
codex-security scan . --scan-prompt-file credential-policy.md
```

When a scan finds a credential, share its type and location with the owner.
Source snippets and diffs can contain the value.

- **If you own the code**, replace a committed literal with a lookup in the
  project’s secret store, or stop the runtime leak. For example, remove the
  token from a public status response.
- **If you own the credential**, a committed value is exposed to source readers.
  For a runtime leak, check which deployments and credentials were affected.
  Revoke an exposed credential immediately if you suspect misuse. Otherwise,
  deploy a replacement, verify consumers still work, and confirm the issuer
  has disabled the old credential. For signing keys, update the verifiers that
  trust the old key. Review issuer logs for the exposure window.

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

A dry run reports `stateDirectory`, the root for saved scan state. It checks the
storage location without creating a scan directory. Pass boolean scan options
as bare flags or use lowercase `=true` or `=false`.

When a cost limit is configured, `scan --dry-run` shows the resolved
`maxCostUsd` and a `costLimitNote` explaining how the scan measures usage
against the limit and why in-flight requests can exceed it.

Whole-codebase and path scans also accept ordinary directories, including SVN
working copies. Their source inventories exclude `.git` and `.svn` metadata.

`--diff` scans committed changes; `--working-tree` scans staged and unstaged
changes. Both require Git. Deep scans support whole repositories and path scopes.
Working-tree snapshots include untracked nested Git repositories. Initialized submodules must
be clean and at the commit recorded by the parent.

Committed-diff scans require a clean, full checkout at the requested head
revision, including when using `--validate`. A different checkout revision or
local changes are rejected before scanning; check out the requested head and
commit or stash local changes before retrying. The check also verifies tracked
files marked `assume-unchanged` and preserves their Git index flags.

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
must be empty and outside the scanned directory and enclosing Git worktree.
Existing directories keep their permissions. Newly created directories are
private to you by default. On Windows, the directory and its parents must be
owned by your account, Administrators, SYSTEM, or TrustedInstaller. Choose a
path where another user cannot replace the output directory or one of its
parents. A parent can allow other users to read it or create sibling directories.
For an empty write destination, grant content-writing permissions to children
through inheritance. Other users must not have permission to set reparse data
on the destination directory itself.
`--archive-existing` moves earlier output to a sibling directory with a unique
suffix, such as `results.previous-ab12cd34` for an output directory named
`results`. If adding the suffix exceeds the filesystem's filename limit on POSIX,
the archive uses a short sibling name starting with `.previous-` and a hash of the
original filename. Use `--dry-run` to preview the move.

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

With `--full-output`, JSON and JSONL failures put the error under `error` in an
`ok: false` envelope. YAML and TOON use the same failed envelope when retained
sealed scan results are available (including TOON selected by default).
If the scan target changed, the error explains that the results no longer
represent the current checkout. Retained sealed results remain available under
`data`, including their manifest, findings, review summary, scan directory, and report
path. Unsealed or invalid artifacts are not included. This also applies to
`scans rerun` and `scans resume`.
For `scans rerun` and `scans resume`, `--filter-output` applies to retained `data`;
selecting an unavailable field can return `null` or omit `data`.

Saved-scan setup failures use the same output shape with
`SCAN_REPLAY_UNAVAILABLE` for `scans rerun` (including when no completed scan is
available) or `SCAN_RESUME_UNAVAILABLE` for `scans resume`. Rerunning an imported
scan uses `SCAN_IMPORT_FAILED` if the import fails. YAML and TOON failures remain
on stderr without `--full-output`, or when retained results are unavailable.

Scan argument errors with `--full-output` and JSON or JSONL use an `ok: false`
envelope with `error.code` and `error.message`. Command schema validation errors
with JSON or JSONL retain their field details and name missing or invalid
options by their CLI flags. Diagnostics stay on stderr.
`scan --schema --format json` describes optional caller inputs before defaults
and the fields returned by preflight, completed scans, and execution failures,
including sealed results recovered after an interruption.
See [Exports and CI](#exports-and-ci) for exit codes and CI examples.

### Follow-up finding validation

Scans already validate findings against local source. Add `--validate` to run
the existing standalone validation workflow for each reported finding after
the scan, using the same selected Cyber access program. Validation sends each
finding to the configured model provider. Its review tools have read-only
filesystem access, with network access and web search disabled. Each assessment uses a
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
the saved files:

| File                 | What to check                                                                                                                                                                                            |
| -------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `scan-manifest.json` | `scan.status` and `scan.target` identify the outcome and snapshot. `scan.scope` lists requested inclusions and exclusions. `scan.review.excludedPaths` lists additional excluded paths in current scans. |
| `findings.json`      | Reported findings, source locations and supporting evidence.                                                                                                                                             |
| `report.md`          | A readable summary of the scope and findings.                                                                                                                                                            |

When a checkpoint is retained, `checkpoint-head.json` identifies the file in
`checkpoints/`. In a retained draft or checkpoint, `reviewState.deferred` lists
unfinished work and `reviewState.openQuestions` lists follow-up questions.
Older manifests with `scan.coverageRef` point to a separate `coverage.json`
with reviewed surfaces, explicit exclusions and deferred work. A saved source
inventory identifies inputs. Neither that inventory nor session logs establish
which files the scan reviewed in full.

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
codex-security info -c codex-security.yaml --json
codex-security scan . -c codex-security.yaml --dry-run --json
```

Select a YAML or JSON file with `-c`, or set `CODEX_SECURITY_PROJECT_CONFIG`.
Keep `-c` on both `info` and the scan preview to inspect the same target and
limits. Explicit `-c` wins. Without either, no file is discovered. `scan`, `bulk-scan`,
`scan-components`, and `info` accept project files. SDK calls and saved reruns
do not load them automatically.

JSON project files and component plans (`--components-file`) accept UTF-8 with
or without a leading byte-order mark.

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
archiving, and severity thresholds work normally. Use `scans show` to inspect a
mock scan. Mock scans have no Codex session logs. Reruns preserve mock mode.
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
The retry report covers only those components. Each registered component keeps its
scan ID in the summary, including when the scan fails.

`--max-cost` applies per component, excluding planning and matching. `--model`
and `--effort` also apply to matching; `--auth` applies throughout. Planning and
matching reject ambient command providers that conflict with explicit ChatGPT
or API-key auth. SDK-selected command providers retain their authentication.

From TypeScript, use `runComponentScans({ repository, outputDir, components })`.
Use `auto: true`, `planOnly: true`, and `scanOptions.auth` for the corresponding
planning and authentication choices. Custom `createSecurity` clients receive
absolute targets; saved plans and component receipts retain relative paths.

### Choose a severity rubric

Standalone Standard and Deep scans grade findings with the bundled rubric by
default. Set `CODEX_SECURITY_ENABLE_REMOTE_SEVERITY_RUBRIC=1` to fetch the
current default from Statsig once when starting a scan. If that lookup fails,
the scan uses the bundled rubric.

```bash
CODEX_SECURITY_ENABLE_REMOTE_SEVERITY_RUBRIC=1 codex-security scan .
codex-security scan . --mode deep --rubric ./severity.md
```

An explicit Markdown file takes precedence and skips the lookup, even when
opted in. The SDK accepts `rubricPath` or a `severityRubric` snapshot with
`markdown`, a positive integer `revision`, and the SHA-256 of the exact UTF-8
Markdown. A supplied snapshot takes precedence over a file.

The scan saves the rubric text in its local launch recipe. Retrying a Standard
scan with the same `--workflow-id`, resuming a Deep scan, or rerunning a scan
with a saved rubric reuses that copy even if the remote default or file changes.
Older scans without a saved rubric continue to resume using their existing workflow.

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

Deep Scan repeats Standard scans in batches of up to `--workers`, with
`--subagents` per scan. Workers can share what they are investigating, ask each
other to check a source location, and reply while their audits are running. Each
worker verifies the evidence it reports. Deep Scan merges each completed batch in launch order.
It uses source locations, cited code and weakness descriptions to match repeated
findings. Each group keeps its first description, all reported locations, and
the original observations. Later batches receive the titles and primary
locations of retained findings so workers can investigate other reachable paths.
`--stop-after-no-new` counts consecutive
completed scans that added no findings. `--max-discovery-runs` caps the total
number started, including failures. `--max-time` stops discovery and returns
the findings from completed scans.

For TypeScript, see the [SDK Deep Scan example](sdk.md#configure-deep-scans).

Use project-file `scan.deep` settings or legacy
`$CODEX_HOME/codex-security/config.toml` defaults. Counts must be positive except
that `subagents` can be zero. Discovery time accepts positive fractional minutes;
its default and maximum are 5760 minutes (96 hours). Unlike Standard's
advisory allowance, the Deep discovery limit is enforced. Resuming a
Deep scan keeps its original deadline; rerunning starts a new scan.
If the deadline expires before any source review completes, the saved report
and scan manifest record that limitation.
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

Repeat `--codex KEY=VALUE` for supported native settings. For example,
`--codex "model_reasoning_effort='high'"` passes the TOML string `high` in Bash,
Command Prompt, and PowerShell. Repeated or conflicting keys are rejected,
including a `--model` or `--effort` flag plus its native equivalent.

To select a Codex file profile, put its settings in
`$CODEX_HOME/review.config.toml` (or `~/.codex/review.config.toml` when
`CODEX_HOME` is unset), then run:

```bash
npx @openai/codex-security scan . --codex "profile='review'"
```

In the SDK, set `codexOverrides: { profile: "review" }`. In a project config,
set `codex.profile: review`. The profile file uses top-level Codex TOML keys.
Its settings override scanner defaults. Explicit scan settings take precedence.
Relative file paths, including `model_instructions_file`, resolve from the
profile directory. Saved launches retain the profile name and reload its settings.
Include custom provider definitions in the file so the scan
can use them from its isolated Codex home. An absent file contributes no
settings. Existing inline `profiles` tables still work.

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
  --codex "model_provider='gateway'" \
  --codex "model_providers.gateway.name='Gateway'" \
  --codex "model_providers.gateway.base_url='https://gateway.example.test/v1'" \
  --codex "model_providers.gateway.wire_api='responses'" \
  --codex "model_providers.gateway.env_key='GATEWAY_API_KEY'"
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
`--codex analytics.enabled=false`. The setting carries into `scan --patch`,
patch-risk assessment, and Deep Scan discovery workers, including
resumed workers. Selected-profile settings take precedence over root settings.
Explicit OpenTelemetry settings also carry into scan patches and Deep Scan
workers, including exporter choices and prompt-logging controls.
Model-request attribution metadata remains attached when analytics are disabled.
The setting does not control configured OpenTelemetry exporters, integrations,
authentication, or CLI update checks. Validation uses isolated configuration;
patching and verification preserve ambient project trust.

For scan outcomes, the workbench saves a separate, local `lifecycle` record
with the scan ID, launch surface, available release versions, mode, timestamps,
and committed status. A completed scan indicates whether it produced reportable
findings. Use `codex-security scans list --json` for the current repository.
To find an offline import, use `codex-security scans list --scan-root <DIR> --json`
with its output directory. Imported scans have lifecycle mode `import`. The SDK
exposes `onLifecycle`, and the CLI includes observations in verbose diagnostics.
Canceling a newly registered SDK scan through its abort signal, closing the
client during the scan, or receiving a canceled hosted execution records
`canceled`. A scan that has already completed keeps its committed outcome.
Applications can choose how to collect and export these observations.

For filesystem and approval behavior, see the
[local security model](sdk.md#local-security-model).

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
On POSIX, `CODEX_CLI_PATH` and `PYTHON` preserve trailing whitespace in an
explicit path that selects an executable. Use an absolute path or a `./`
prefix for filenames beginning or ending in whitespace. Bare command names
are trimmed before lookup.

### Troubleshooting

Use `--verbose` or `CODEX_SECURITY_LOG_LEVEL=debug` for lifecycle, configuration,
retry, and worker diagnostics on stderr. Direct Deep Scans include coordinator events
such as worker retries and duplicate-comparison failures. Diagnostic text is preserved in output,
saved failures, receipts, and patch-risk summaries. Review it for sensitive
information before sharing; upstream Codex output may already be redacted.

Keep state and reports when recovering authentication or locking problems.
Finish older-version operations before upgrading. Never remove
`.codex-security-scan.sqlite3` during an operation. Stop all operations using the
credential home before manually removing an old `.codex-security-scan.lock`.

If a scan reports that its state directory overlaps a protected root, choose a
private directory in a separate tree, such as a sibling of the protected root.
Set `CODEX_SECURITY_STATE_DIR` for local scans or `stateDirectory` on a hosted
scan request. SDK callers handling `OutputInsideProtectedRootError.pathKind`
can match `"state"` for this case.

If credential-home preparation fails, the error includes the underlying
filesystem diagnostic. For permission or read-only filesystem errors, check
the reported path or set `CODEX_SECURITY_STATE_DIR` to a private, writable
directory outside the repository. A new state directory has separate history
and does not migrate existing credentials or reports.

Sandbox startup errors include the native diagnostic followed by a command to
reproduce it. Linux namespace and AppArmor guidance appears only on Linux.

If Windows Application Control blocks `windows.node` while validating a scan
output directory, look for the module's block event in Event Viewer under
Applications and Services Logs → Microsoft → Windows → CodeIntegrity → Operational.
[Microsoft's App Control event reference](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/operations/event-id-explanations)

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

Interactive scans show full-screen progress. The dashboard title uses the resolved
directory name, so `scan .` shows the current directory's name. CI, redirected output,
`--headless`, and `--verbose` use plain status lines. Results go to stdout; progress and
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

Cost displays use Standard token rates for the model. OpenAI models use
[OpenAI API pricing](https://developers.openai.com/api/docs/pricing). OpenAI
models on Bedrock use [AWS pricing for the model, inference route, and region](https://github.com/openai/codex-security/blob/main/docs/bedrock.md#scan-cost-estimates).
For managed OpenAI models on Vertex AI, see [Google Cloud Vertex AI cost estimates](#google-cloud-vertex-ai-cost-estimates).
The short/long-context range estimates usage at published rates. Other service
tiers, account discounts, and ChatGPT subscription allowance are outside that
estimate. Models without known prices have no estimate.

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

A scan with a cost limit requires complete token usage for its recorded scan,
worker, and custom validation sessions before the SDK returns a completed result.
The workbench reads compressed `.jsonl.zst` sessions with `compression.zstd`
(Python 3.14+) or `backports.zstd` when available. Otherwise it uses the
Node.js decoder bundled with the plugin.
Missing or unreadable usage fails budget verification. Without a limit, usage
reporting remains best effort.

When Deep discovery has finished at a cost stop and usage is verified, the scan returns a sealed
report and retains unvalidated candidates as follow-up work. The saved report and
the manifest's `scan.scope.limitations` record that validation was deferred.
Reaching a configured limit with a valid finalized report returns `0` by default,
or `1` if findings meet a configured failure threshold.

When a worker turn fails with a known cybersecurity policy refusal or an
exhausted usage limit, Deep Scan stops retries and replacements, cancels active
siblings, and retains completed worker artifacts. A capability check can succeed
before a later request is refused. Use `scans show SCAN_ID` to inspect the failed
scan and its retained results. To run it again from a saved recipe, use
`scans rerun SCAN_ID`, which starts fresh discovery.

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
If an ordinary attempt finds its checkout path already occupied, it stops before
fetching. Use `--recover` to scan in a fresh checkout, or inspect and move the
existing checkout before an ordinary retry.
If checkout cleanup previously failed, the next invocation removes it only when
its marker still identifies the same directory and scan attempt. Older or
replacement checkouts without a matching marker are preserved.
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

Each nonempty committed line in `results.jsonl` must be valid JSON with a string
task ID and a positive safe integer attempt number. If a line fails these checks,
the command reports its line number and preserves the ledger. Restore a complete
ledger backup that includes every committed attempt, or start a separate campaign
in a new `--output-dir`. If a repository exhausts its attempt numbers, starting
a fresh attempt requires a new campaign.

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

Choose the command by what you want to keep. [Scanner guides](https://github.com/openai/codex-security/blob/main/docs/scanner-imports/README.md) list the accepted vendor formats.

| Input and goal                                               | Command                                                                        | Service contacted                 | Where to find the result                                                                                       |
| ------------------------------------------------------------ | ------------------------------------------------------------------------------ | --------------------------------- | -------------------------------------------------------------------------------------------------------------- |
| Save vendor evidence for a checkout                          | `publish findings FILE --to local`                                             | None                              | `findings imported PATH` lists unassessed local findings.                                                      |
| Publish a supported vendor report                            | [`publish findings FILE --to cloud`](#publish-findings-to-cloud)               | Codex Security Cloud              | The receipt identifies the private inbox job or repository records.                                            |
| Collect upstream records to a file                           | `import github`, `import github-advisories`, `import semgrep` or `import snyk` | Selected vendor                   | Redirect the complete `--format json` output to a private file, then preview it with `publish findings`.       |
| Collect live Sonar issues                                    | [`import sonar --dry-run`](#import-sonarqube-cloud-issues)                     | SonarQube Cloud during collection | The `capture` field gives a private file path. Replay it to save locally or save locally and publish to Cloud. |
| Save Codex Security findings CSV or JSON as a completed scan | [`scan import`](#import-findings-as-a-saved-scan)                              | None                              | `scans list --scan-root DIR --json` shows imports under the artifact root.                                     |

For `publish findings`, `--to` is required. With `--to local`, `--repository`
takes a checkout path. Select the reader with `--provider` and give the source a stable `--source-key`.
The reader detects the file format. `--format json` selects the output format. A local preview checks the file offline without
saving findings or calling a model. For example, preview a complete Endor
Finding export from the matching checkout, replacing the namespace, project
and branch in the source key.

```sh
codex-security publish findings /private/path/endor-findings.json --provider endor \
  --to local --repository . --source-key NAMESPACE/PROJECT/main --dry-run --format json
```

After reviewing the findings and exclusions, rerun the command without
`--dry-run` and confirm. [Save or publish and verify](https://github.com/openai/codex-security/blob/main/docs/scanner-imports/README.md#save-or-publish-and-verify).

For Tenable One Code Repository findings, use `--provider tenable --to local` and set `--source-repository-url` to the checkout’s verified HTTPS remote. [Tenable export and import guide](https://github.com/openai/codex-security/blob/main/docs/scanner-imports/tenable.md)

Local readback uses `findings imported [PATH]`. The path defaults to the current
directory. Each imported record starts as `not_assessed`. Unknown revisions and
locations stay unknown. Repository-scoped sources are checked against comparable
configured Git remotes as described in the provider guide. Reimporting the same
source key and finding ID reports created, updated, or unchanged records.
Records omitted from the new selection stay stored. Local imports can retain
evidence that exceeds Cloud's per-finding limits.

If a report contains both ready and excluded records, the local dry run exits
with status 0. After confirmation, the import stores the ready records and
exits with status 1. If all records are excluded, both commands exit with
status 2. A clean empty report exits with status 0 in either mode and stores
no findings.

Preview the same file and source key again for the intended destination before
publishing. Semgrep Guardian selections, Web API SAST selections and full
project collections support both destinations. Choose the [Semgrep import method](https://github.com/openai/codex-security/blob/main/docs/scanner-imports/semgrep.md) that matches your source.

## Import Trivy dependency findings

Use `--provider trivy` for language-package vulnerabilities in schema-v2
repository or filesystem JSON. The [Trivy guide](https://github.com/openai/codex-security/blob/main/docs/scanner-imports/trivy.md) explains how
to set the scan root and check manifest paths.

## Import Endor Labs findings

Use `--provider endor` for one Endor project and context. The
[Endor Labs guide](https://github.com/openai/codex-security/blob/main/docs/scanner-imports/endor.md) covers native Finding JSON,
SARIF compatibility, and the local preview.

## Import SonarQube Cloud issues

`import sonar --dry-run` writes a private capture and returns its path. Preview
that capture for the intended destination before confirming. A Cloud confirmation
saves the issues locally and publishes them. Use `--full-output` with
`--format json` or `--format jsonl` for a structured result.
[Collect and replay a Sonar capture](https://github.com/openai/codex-security/blob/main/docs/scanner-imports/sonar.md#import-and-verify).

## Import GitHub findings locally or to Cloud

Use `--provider github` with separate source keys for
[code scanning alerts](https://github.com/openai/codex-security/blob/main/docs/scanner-imports/github-code-scanning.md),
[Dependabot alerts](https://github.com/openai/codex-security/blob/main/docs/scanner-imports/github-dependabot.md) and
[security advisories](https://github.com/openai/codex-security/blob/main/docs/scanner-imports/github-security-advisories.md).
Sign in with `gh` for the CLI collectors. `GH_HOST` defaults to `github.com`.

### Import GHSA advisories separately

Use `import github-advisories OWNER/REPO` for published repository advisories
or add `--github-advisory-source global` and one or more `--github-advisory`
IDs to collect global advisories. Check the installed dependency against each
affected range. [Advisory selection and SDK examples](https://github.com/openai/codex-security/blob/main/docs/scanner-imports/github-security-advisories.md).

## Import alerts from the CLI

Collect open code-scanning alerts on the default branch and save the complete
array outside the checkout. Use a private temporary directory and run
validation from the matching checkout. Validation sends the evidence to your
configured model provider.

```sh
out=$(mktemp -d) &&
  codex-security import github OWNER/REPO --format json > "$out/alerts.json" &&
  codex-security validate "$out/alerts.json"
```

The collector reads alerts, including third-party SARIF uploads. It does not
start a scan. For filters, ref selection and SDK validation, see the
[code scanning guide](https://github.com/openai/codex-security/blob/main/docs/scanner-imports/github-code-scanning.md).

## Publish findings to Cloud

Use `publish findings FILE` for a [saved scanner report](https://github.com/openai/codex-security/blob/main/docs/scanner-imports/README.md).
If you're collecting live issues with `import sonar`, [publish from the Sonar preview's saved capture](https://github.com/openai/codex-security/blob/main/docs/scanner-imports/sonar.md#import-and-verify).

### Preview and publish

Set `--to cloud`. For `--repository`, use the connected GitHub or GitHub
Enterprise repository URL or its Cloud ID. Either works for retries. If
several connectors share the URL, use the ID. You can import before the
repository's first native scan.

Cloud requires a file-backed ChatGPT login. Codex Security signs in with the
`cli_auth_credentials_store` set in your Codex `config.toml`
(`~/.codex/config.toml`, or `$CODEX_HOME/config.toml`). Without it, the login
can be saved in the system keyring. To publish, set
`cli_auth_credentials_store = "file"` there, then run `codex-security login`
with the ChatGPT account you want to use. `codex-security login status`
checks the current sign-in without changing credential storage.

### Review the Cloud destination

Run the command with `--dry-run --format json`. Check `accountId`,
`cloudApiUrl`, `destination` and `source.source_key`. Compare `findings` and
`excluded` with the records you meant to import.

- **Private findings inbox.** If the preview includes `privateImport`, the
  report goes to your inbox. The repository and connector identify the
  suggested assessment target. Check `format`, `bytes` and `sha256` in
  `privateImport` to identify the upload. For an Endor Finding, an Endor
  `list.objects` response or a Wiz vulnerability JSON export, the CLI can
  send the original bytes when Cloud accepts the format and every record
  matches your selection. Other inputs, including arrays of selected Endor
  Findings, use `security.findings.v1`.
- **Repository publisher.** Check `repository.environment_id` in each entry
  of `requests`. The publisher checks the current source versions. Existing
  records keep their environment. New records use the repository's authorized
  default.

To import, run the same command without `--dry-run` and confirm. The terminal
shows the file, exclusions, severities and up to five finding IDs and titles.
The prompt defaults to No. For a noninteractive import, add `--yes` after
reviewing the full JSON preview.

### Configure an alternate Cloud deployment

Set `CODEX_SECURITY_CLOUD_BASE_URL` to the deployment's API root, such as
`https://cloud.example.test/backend-api/aardvark`. Use a login issued by that
deployment. Remote API roots require HTTPS. Loopback development also accepts
HTTP on `localhost`, `127.0.0.0/8`, or `::1`. An empty or invalid setting
stops preparation before authentication or network requests. Leaving it unset
selects production. For testing, use an isolated `CODEX_SECURITY_STATE_DIR`.

For a separately hosted Cloud UI, set `CODEX_SECURITY_CLOUD_WEB_URL` to the
full app URL. The preview and result can then supply a repository-specific
`cloudUrl`. With a custom API and no web URL, the CLI prints navigation
instructions. API requests always use the API root. The older
`CODEX_SECURITY_CLOUD_PUBLISH_URL` setting applies only to native scan publishing.

### Resume interrupted imports

If the result includes `savedSubmission`, keep that checkpoint. Rerun the
original command with `--dry-run --format json` using the same input, account,
destination, API endpoint and state directory. Check `cloudApiUrl`. If
`resumed` is true, confirm to continue the saved submission. If it's false,
review the new submission before confirming.

- **Private inbox.** The CLI checks the report digest and reuses its saved
  request IDs. It can read an accepted job even if the deployment has since
  disabled uploads. After an inbox reset, check the new report format, size
  and digest before confirming.
- **Repository publisher.** The CLI saves each request privately before
  sending up to 100 findings. Retries use the same publisher, request IDs and
  bodies. If the repository has been reset, preview and confirm a fresh
  submission.

[Retry a Cloud submission](https://github.com/openai/codex-security/blob/main/docs/scanner-imports/schema-guide.md#retry-a-cloud-submission)

### Results and exit codes

| Status        | Exit code | Meaning                                                                                |
| ------------- | --------- | -------------------------------------------------------------------------------------- |
| `empty`       | 0         | No records were available to upload.                                                   |
| `complete`    | 0         | The inbox job processed every record successfully, or the publisher verified each one. |
| `partial`     | 1         | The import had exclusions or record errors, or the inbox job failed or was cancelled.  |
| `interrupted` | 2         | The CLI stopped while uploading, checking the result or saving a receipt.              |
| `failed`      | 2         | Preparation failed before upload.                                                      |

A clean empty report needs no confirmation. Self-contained file imports can
finish before Cloud sign-in; Semgrep Platform and Snyk REST captures use the
Cloud catalog to verify their repository. Local imports still validate the
checkout and create no workbench database. Explicit scanner errors
and selections containing only excluded records fail; JSON output retains their
diagnostics and exclusion reasons. Existing findings stay open.

For automation, check the scanner's exit status as well as the import's. SARIF
can contain no runs or omit results in a rules-only export. `empty` describes
the selected report, not whether a scan completed successfully.

For a partial or interrupted import, check `excluded` and any `error` before
retrying. Some records may already have reached Cloud.

- **Private inbox.** In `privateJob`, check the job `status`, `counts.error`
  and `counts.unprocessed`. The receipt also identifies the job (`id`) and the
  uploaded file (`input.file_id`). The CLI reads the job receipt, so a
  successful import can show `verified: 0`. To share a finding, open it in
  your inbox, assess it against a pinned repository revision and publish the
  reportable assessment.
- **Repository publisher.** `verified` counts records whose identity the CLI
  confirmed by reading them back. If the version matches the receipt, the CLI
  also checks the evidence. A newer version can have different evidence and
  still count as verified. `unacknowledged` counts records awaiting a receipt,
  including records Cloud accepted if the response was lost. Use `client_id`
  to match a receipt item to its request and `source_finding_id` in `failures`
  to find a failed vendor record. Counts include earlier batches with receipts.
  When present, `cloudUrl` opens the repository. Assessment and sharing are
  separate steps.

With `--format json` or `--format jsonl`, add `--full-output` for an envelope.
Failed and interrupted imports set `ok` to `false` and `error.code` to
`IMPORT_FAILED`. Available results, receipts, and counts remain under `data`.
Other formats reject `--full-output` before reading the file or contacting
Cloud. Ctrl-C and SIGTERM retain exit codes 130 and 143.

Progress goes to stderr and JSON results to stdout. The repository publisher
uploads sequentially and uses up to four concurrent requests for lookups and
readback.

### Import Snyk findings

Use `--provider snyk` for native Open Source JSON, plugin exports, SARIF or
monitored Open Source and Code issues. The [Snyk guide](https://github.com/openai/codex-security/blob/main/docs/scanner-imports/snyk.md)
covers saved files, distinct source keys for each format, and collection with
`import snyk`.

### Import Wiz findings

<a id="select-findings-and-a-destination"></a>
<a id="package-vulnerability-inputs"></a>
<a id="sast-repository-secrets-and-iac-inputs"></a>
<a id="preserved-evidence"></a>
<a id="convert-csv-reports"></a>

Use `--provider wiz` for a [saved Wiz report](https://github.com/openai/codex-security/blob/main/docs/scanner-imports/wiz.md#quick-start).
The provider guide describes [package JSON and CSV](https://github.com/openai/codex-security/blob/main/docs/scanner-imports/wiz.md#package-vulnerability-inputs),
[named SAST, secret and IaC collections](https://github.com/openai/codex-security/blob/main/docs/scanner-imports/wiz.md#sast-repository-secrets-and-iac-inputs),
[retained evidence](https://github.com/openai/codex-security/blob/main/docs/scanner-imports/wiz.md#preserved-evidence) and
[conversion to normalized JSONL](https://github.com/openai/codex-security/blob/main/docs/scanner-imports/wiz.md#convert-csv-reports).

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
`cli_auth_credentials_store = "file"` in Codex `config.toml`, then run
`codex-security login` again. Login, scans and other commands use that setting
for the Codex Security sign-in.
A dedicated login using automatic storage can publish if Codex Security
recorded the native file fallback. An unverified file can belong to another
account, so Cloud publication requires an explicit file store for an ambient login.

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

`--linear-project PROJECT_ID` selects a project. Existing scripts using the deprecated
`--project PROJECT_ID` spelling continue to work. Flags override
`CODEX_SECURITY_LINEAR_TEAM` and `CODEX_SECURITY_LINEAR_PROJECT`. `--dry-run`
previews titles offline; `--json` returns structured output.

Sign in to Codex and connect Linear, or set `CODEX_SECURITY_LINEAR_API_KEY` to
use its API directly. Direct API publication leaves issues unassigned unless
`--linear-assignee` gives a user ID or email. Prefer the environment variable
over `--linear-api-key`, which exposes the key in shell history/process listings.
Keys are omitted from saved results; diagnostic messages remain unchanged.

```bash
codex-security publish check /path/to/completed-scan \
  --linear-team TEAM_ID --json
```

`publish check` defaults to `--to linear`. It verifies artifacts and recorded publications. With an API key,
it also checks authentication and destination access. It does not test issue
creation; connected-app access is reported as `not-checked`.

Each finding becomes an issue with severity, source, evidence, and remediation.
Choose a destination authorized to receive that content. Local history records
successful issue IDs separately from sealed artifacts. The CLI and the plugin's
finding-tracking workflow share these records when using the same Codex Security
state directory. Accepted writes remain recorded even if a later issue read fails.

By default, publishing the same scan again creates new issues. With
`--skip-existing`, the CLI skips occurrences with a recorded success for the
same team and project. This includes issues the plugin created or reused.
The CLI checks local history only. After an interrupted or concurrent run,
check Linear for an existing issue before retrying.

If the CLI and plugin share a database from an older installation, upgrade
both together. The shared history preserves existing Linear receipts, but
publishers that require the old table can no longer record new ones.

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
By default, saved findings are classified with the [built-in severity rubric](https://github.com/openai/codex-security/blob/main/plugins/codex-security/references/default-severity-rubric.md).
It evaluates attacker access, boundary crossing, additional harm, and evidence for
Critical, High, Medium, Low, and Informational findings. Confidence remains separate
from severity; missing proof alone does not justify a downgrade.

Set `CODEX_SECURITY_ENABLE_REMOTE_SEVERITY_RUBRIC=1` to fetch the current default
from Statsig once per reclassification. Only the exact value `1` enables the
request. It sends the config name without findings or account identifiers.
If the request fails, times out, or returns an invalid rubric, the built-in
rubric is used. An explicit `--rubric` (SDK `rubricPath`) skips the lookup and
uses your policy for every review. Rubrics and repeatable `--knowledge-base`
context accept text, PDF, DOCX, and directories.

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

For a single rubric document, the classification result reports the SHA-256 of
the exact UTF-8 text supplied to the reviewer in `rubricSha256`. For multiple
documents it reports the digest of the ordered text collection. A bundled or
remote default also records its `rubricRevision`. Older saved results retain
their original digest and may omit the revision.

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

Repeat `--finding-id ID` for a subset from the selected scan. Dedupe returns
`scanRepresentativeFindingIds` for this selection, in the same order as its
corpus-wide `uniqueFindingIds`.
Linear publication defaults to saved classification selection, omits exclusions,
and uses assessed severity for title and priority. Descriptions retain original
severity and add the classification rationale. Publication rejects incomplete or
stale assessments. It never reclassifies or rereads the rubric at publication time.

```bash
# List the IDs you can pass to --finding-id.
codex-security dedupe --scan SCAN_ID --json | jq -r '.scanRepresentativeFindingIds[]'
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
  deduplicateScanDirectory,
  publishScan,
} from "@openai/codex-security";

// Assess supplied reports in memory.
await classifySeverity(findings, {
  rubricPath: "/path/to/policy.md",
  knowledgeBasePaths: ["/path/to/context.md"],
});

// Save assessments for a scan ID or sealed directory.
await classifyScanSeverity("SCAN_ID", { rubricPath: "/path/to/policy.md" });
const dedupeResult = await deduplicateScanDirectory(scanDirectory, {
  repository: "/path/to/repository",
});
const classification = await classifyScanDirectorySeverity(scanDirectory, {
  rubricPath: "/path/to/policy.md",
  findingIds: dedupeResult.scanRepresentativeFindingIds,
});

// Preview Linear publication for those same findings using their assessments.
await publishScan(scanDirectory, {
  destination: "linear",
  teamId: "TEAM_ID",
  classification,
  findingIds: dedupeResult.scanRepresentativeFindingIds,
  dryRun: true,
});
```

`classifySeverity()` accepts `findingId`, `title`, `summary`, and available
evidence/metadata. Imported reports may lack severity or occurrence IDs; omitting
`rubricPath` uses the selected default policy even when a scanner severity is present.
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

In the terminal, `findings list` shows the occurrence ID for each open finding.
Copy that ID into `findings false-positive` with your reason. Subsequent scans can
use the explanation while it applies. In `scans show SCAN_ID --json`, each
displayed occurrence has its saved rationale in `triage.note` after dismissal. The list identifies
a repository with no saved scan history separately from one with zero open findings.

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

Reruns use the current checkout/context files and do not reload project files.
The readable scan recipe records your authentication choice. A separate private
replay profile stores explicit `openai_base_url`, `chatgpt_base_url`, and custom
`model_providers` settings, including any credentials written directly in
`http_headers`. If you use `env_key` or `env_http_headers`, the profile stores
the variable names. Set those variables when you rerun or resume. Settings
inherited from a named file profile are reloaded from that file. If an older
scan omitted your endpoint, start a new scan with the original `--codex` override.

When routing through environment variables, set them for each launch, including
rerun and resume. Deep workers inherit `CODEX_OSS_BASE_URL` and `CODEX_OSS_PORT`
for Ollama and LM Studio, and `GOOGLE_CLOUD_PROJECT`, `GOOGLE_CLOUD_LOCATION`,
and `GOOGLE_APPLICATION_CREDENTIALS` for Vertex AI.

Supply replacement scan and custom-validation prompts when the original used them:

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

Saved scan logs retain the finishing turn, including its final response, and
exclude later turns once the scan records a completion boundary. Older scans
retain the full history of their attributed sessions and keep their existing
worker-selection boundaries. This also applies to logs attached with
`feedback --include-logs`.

Codex may compress saved session logs to `.jsonl.zst`. Plain and compressed logs
work on all supported Node.js versions, including logs, feedback attachments,
usage accounting, and saved-session discovery for resume. A bundled decoder
reads concatenated frames and reports truncated streams as collection errors.

### Resuming an interrupted Deep Scan

```bash
codex-security scans list --scan-root /path/to/security-scans
codex-security scans resume SCAN_ID
```

The terminal list shows the full scan ID and labels the last activity of a
`running` scan after 24 hours without an update. For a Deep Scan with a saved
launch recipe and its original session, it also shows the resume command to use after interruption.

The scan must still be `running`, with its original checkout, output directory,
and Codex session in the same state directory. Checkout identity, revision, and
contents must match. Completed, failed, and canceled scans need a rerun instead.

On Windows, keep the protected `.codex-security-resume` directory in the scan
output. It lets the workbench verify the original output even before the first
checkpoint. If an older scan stopped with an empty output, start a new scan with
`codex-security scans rerun SCAN_ID`.

New Windows Deep Scans also record the checkout's native volume and file ID
when the filesystem supplies them. Validation and remediation verify the same
checkout identity. An older scan can resume across Python
versions when its saved checkout identity can be verified. If the workbench
cannot verify it, resume with the Python runtime that started the scan or use
`codex-security scans rerun SCAN_ID` to start a new scan.

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

When a saved Standard scan and a Deep scan have the same recorded target,
revision, and snapshot digest, matching flags findings that have different
anchors but share a unique rule, first displayed source range, and optional
instance. Matching preserves the case of saved paths. Codex can request the
saved evidence to distinguish separate causes at that site. Automatic matching
under a cost limit keeps its single comparison call.

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

### Export findings for ServiceNow

Use `servicenow-avit` to prepare a CSV for ServiceNow Application Vulnerability
Response. In ServiceNow, open **All > Manual AVIT Ingestion > Upload File UI**
and download the CSV template. Keep the headers and a single row per template
file. Fill in the exact ServiceNow application name, requester, assignee, and
assignment group. Supply the application team, purpose, sensitive data types,
compliance programs, technology stack, and URLs to test. Leave the finding
columns blank and reuse this file for future exports of the same application. See the
[example template](https://github.com/openai/codex-security/blob/main/examples/servicenow-avit-template.csv).

```bash
codex-security export --scan latest --export-format servicenow-avit \
  --avit-template invoice-desk.csv --output findings-avit.csv
```

The command writes one row per saved finding. It fills the risk rating and uses
the first CWE when available, otherwise the Codex finding ID. Technical details
include that ID, the primary file and line, the summary, and remediation. For
**Steps to reproduce**, review any recorded attack-path steps and complete blank
cells before uploading. Both text fields have a 1,000-character limit. An ellipsis
marks shortened text. Other template columns keep their original values.

The output defaults to `servicenow-avit.csv`. Upload the completed file in the
same ServiceNow screen. Each upload creates a new penetration-test form for the
application. If the submission result is unclear, check its status and log notes
on the Vulnerability Integration Push Queues page before uploading again. See [ServiceNow's upload instructions](https://www.servicenow.com/docs/r/security-management/application-vulnerability-response/ingest-vulnerabilities-manually-avr.html).

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
For ServiceNow, use `format: "servicenow-avit"` and set `avitTemplate` to the
path of the application's populated CSV template.
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

The generated hook runs a `--working-tree` scan and blocks the commit on scan
failure or findings at or above its threshold (`high` by default). It uses the
checkout's normal index for staged and unstaged changes, so it can include changes
outside a partial commit and miss content staged only in a separate index.
Use required CI for enforcement because local hooks are optional.

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
this repository and contains only the generated commands. Rerun `install-hook`
with `--fail-on-severity` set to its original threshold. It recognizes the legacy
`npx` hook and supported earlier templates with matching absolute Node and CLI
paths. If it refuses to overwrite the verified hook, back it up, remove it and
reinstall with the same threshold. Restore the backup if installation fails.
On POSIX, reinstalling a recognized hook restores its owner execute bit if Git
could not execute it. The installer checks that the resulting hook is executable.
The installer uses host Git for the selected repository and respects
`core.hooksPath`.

## Validate and patch findings

Hosts that manage their own model execution can use `codex-security validate --records`.
This mode exchanges a review over JSON-RPC and checks the returned answer against a caller-provided schema.
See [host-provided standalone validation](validate-records.md) for the protocol and execution requirements.

`validate` sends the finding to your configured model provider. Its review
tools can read the checkout, with network access and web search disabled.
The assessment uses source evidence and skips builds, tests, PoCs and application
execution. Both `validate` and `patch` accept files or literal text in the
current directory. Patching by saved finding or occurrence ID selects the
original repository.

For a checked-in credential, `patch` can leave a verified source change in
your working tree and report `blocked` pending confirmation of revocation.
Review the diff and follow the [credential owner steps](#checked-in-credentials).
Saved-finding `--create-pr` stops when a finding is blocked.

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

For `validate`, `patch`, and `verify-fix`, an explicit local file URL such as
`file:///home/reviewer/finding.md` (Windows: `file:///C:/reviews/finding.md`)
requires the file to exist. A missing file stops the command before the model
runs. Use `pathToFileURL(absolutePath).href` in Node to encode spaces and
special characters correctly. Existing plain paths and inline finding text
keep their original behavior.

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

Save the output schema as UTF-8 without a byte-order mark so both the CLI and
Codex can read it.

Use a self-contained schema in the subset supported by the selected Codex model
and provider. The local checker uses JSON Schema 2020-12, but accepting a schema
locally does not guarantee provider support. Keep the schema small and use it only
when the caller needs structured results. It checks the result's shape, not whether
the security conclusion is correct. Relative paths resolve from the current directory.

Save the assessment by redirecting stdout:
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
Before updating finding records, [check that each input ID appears exactly
once](validate-records.md#check-the-returned-ids), including unresolved
candidates.

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
and add instructions. The interactive finding browser lists critical, high,
medium, then low findings, preserving scan order within each severity.
Patch results are `verified`, `no_change`, `blocked`, or
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

Both providers return `pullRequest: { branch, url }`. Saved-finding publication
includes files changed and verified in the same patch turn. If a selected file
already had local edits, the CLI keeps the patch in the working tree for review.
The risk assessment and commit use the same verified tree. If staging changed
during the run and Git cannot update the index, the CLI reports it and keeps
the existing staging.
Supplied-issue patching requires a clean tree. If publication fails, run the printed
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

The CLI selects findings from the workbench and loads their evidence from the
saved scan artifacts. It measures the verification request with that evidence
included. Large selections use multiple requests without splitting or further
truncating any selected finding. The CLI prints verdicts in selection order
after every request returns valid results. For these selections the CLI omits
per-event progress and update notices so stderr cannot delay the verdicts.

If a finding would exceed the input limit, `validate`, `patch`, and `verify-fix`
put the complete finding data in a temporary file for Codex to search alongside
the checkout. A single input file keeps its original text and line breaks.
The file remains available until the task finishes and is then removed. The
SDK's local `validate()` and `patch()` methods use the same fallback.

`--verification-mode static` selects source-only assessment, as described above
for `patch`. Omit it or use `--verification-mode standard` for the default checks.

Results include evidence and `fixed`, `still_vulnerable`, or `inconclusive` status.
For a checked-in credential, verified source cleanup with unknown retirement
returns `inconclusive`. To verify again, put the original finding, source location,
and issuer or owner confirmation in one file, omitting the credential value.
Run `codex-security verify-fix finding.md` from the affected checkout.

Without output options, each finding prints a verdict and its evidence.
Explicit output formats, field selection and token controls operate on the
structured result containing `repository`, optional `scanId`, and `results`.
Exit codes are `0` when all findings are
fixed, `1` when any remain vulnerable, and `2` for inconclusive/failed checks.
With `--json` or `--format jsonl`, authentication and execution failures return
`status: "failed"`, `code: "VERIFICATION_FAILED"`, and `message`. With
`--full-output`, these failures use an `ok: false` error envelope. If a saved
selection exceeds one request, the CLI sends the failure message only to the
structured output. With `--token-count`, `--token-limit`, or `--token-offset`,
stderr also carries the diagnostic so it remains available alongside a count
or a partial result. Other formats report failures on stderr. Interruptions
retain exit codes `130` and `143` without a result.

## Command discovery and integrations

Use `--llms` for the command manifest, `scan --schema --format json` for its
schema, and `completions bash|zsh|fish` for shell completions. Scan output supports
`--format toon|json|yaml|jsonl` and `--full-output`. The existing `--format`,
`--filter-output`, `--token-limit`, and `--token-offset` options accept either
`--option value` or `--option=value`.

`skills add` syncs generated CLI command guidance; it does not install the full
Codex Security plugin. `mcp add` registers the CLI as an MCP server, exposing
only read-only `info` because the transport cannot cancel scans. For the plugin's
scan, triage, patch, and verification workflows, see the
[agent workflow guide](https://github.com/openai/codex-security/blob/main/docs/agent-workflows.md).

Use `skills add --no-global` to write generated guidance to the current project.
`--depth 0` creates a single skill; the default depth of 1 groups guidance by
top-level command. `skills list` checks installation status at depth 1 by
default. To inspect a different grouping, pass the installation depth, for
example `skills list --depth 0 --json`. Installation status uses the paths
recorded by the most recent `skills add` for this user, including project installs.
For both installers, `--help`, `--schema`, and `--version` can be inspected
before writing any configuration.

`mcp add` registers in the user profile by default. `mcp add --no-global`
selects project-capable clients. Registration uses the client adapters installed
with the SDK. Selecting a user-only client in project scope fails before the
CLI writes configuration. For example, use
`mcp add --no-global --agent cursor` to target Cursor. The built-in Amp
registration supports only user settings. `mcp doctor` checks the current CLI's
server startup and tool catalog. To verify a registered launcher, connect from
the client where it was registered.

For local findings storage, deduplication, and custom endpoints, see the
[findings guide](findings-service.md).

### Hosted Standard scan

`codex-security scan --host` runs one versioned JSON-RPC invocation with an explicit host executor. Use it alone; it never performs local inference. See [the hosted scan protocol](hosted-scans.md) for input, filesystem, artifact, usage, and cancellation requirements.

## Containerized bulk scans

Create `repositories.csv` as described under [Bulk scans](#bulk-scans), then run
from the repository root with the published image:

```bash
mkdir -p results state
chmod 700 state
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
