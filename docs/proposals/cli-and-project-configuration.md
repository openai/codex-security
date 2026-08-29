# Proposal: project configuration and a consistent CLI

**Status: proposal with a local prototype of the first increment.** The
[prototype guide](../project-configuration.md) describes implemented behavior and
limits. Discovery, initialization, other new commands, and broader restructuring
remain proposals. The prototype has not been released.

Codex Security should let a team save its normal scan settings in
`codex-security.yaml`, inspect those settings, and run a scan without reconstructing
a long command. CLI arguments should select a target or override individual
settings. The CLI and SDK should resolve those settings through shared code and
continue using the existing Codex runtime and security plugin.

YAML is the primary authoring format; an explicit JSON file should represent the
same settings and use the same input schema. The
[Promptfoo alignment and JSON Schema design](configuration-schema.md) describes
the shared workflow, deliberate differences, and a
[generated schema](../../sdk/typescript/schemas/project-config.schema.json) for review.

The first increment is an explicitly selected project file for `scan`, shared
configuration resolution, the existing dry run, and recording the resolved scan
settings. Automatic discovery, initialization, and new inspection commands can
follow. Batch/component adoption, command renaming, and complete replay snapshots
are separate increments. The [implementation review](cli-and-project-configuration-review.md)
explains this narrower scope and the Promptfoo behaviors behind it.

Today, configuration is spread across several inputs:

| Input                                | Current responsibility                                                | Problem to address                                                                                           |
| ------------------------------------ | --------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------ |
| `scan` arguments                     | Repository, scope, model, prompts, limits, output, and finding policy | Repeated commands are difficult to maintain and review.                                                      |
| `--codex KEY=VALUE`                  | Native Codex configuration overrides                                  | Shell quoting and alias/profile precedence make common settings harder to inspect.                           |
| User `[deep_scan]` TOML              | Deep discovery defaults                                               | These settings need to participate in project configuration without becoming a competing source of defaults. |
| `bulk-scan` CSV and arguments        | Repository inventory, revisions, retries, and outer concurrency       | Supported settings differ from single scans.                                                                 |
| `scan-components` JSON and arguments | Component planning, standard scans, and combined results              | Its orchestration settings overlap with other commands but have different scope.                             |

For example, `--workers` controls discovery workers on a deep scan, repositories on
a bulk scan, and components on a component scan. `--max-cost` is a per-scan or
per-attempt limit; it is not a total budget for a batch. Component planning and
matching are outside the component scan limit. The current
[CLI documentation](../../sdk/typescript/README.md#cli) and
[deep-scan configuration](../../sdk/typescript/README.md#configure-deep-scans)
remain the reference for supported behavior.

Promptfoo provides a useful workflow precedent: a discoverable project file,
initialization, configuration validation, an editor schema, and CLI overrides. Its
[configuration reference](https://www.promptfoo.dev/docs/configuration/reference/)
and [CLI guide](https://www.promptfoo.dev/docs/usage/command-line/) describe that
workflow. Its eval, red-team, and code-scan implementations have different loading
and override paths, so they are not a single reference architecture. Codex Security
should give each setting one canonical location. It does not need both `commandLineOptions` and
`evaluateOptions`, executable configuration files, or Promptfoo's provider
abstraction.

Keep three concepts separate throughout the design:

| Concept       | Choices                                                    | Existing constraints to preserve                                             |
| ------------- | ---------------------------------------------------------- | ---------------------------------------------------------------------------- |
| Scope         | Whole repository, paths, committed diff, working-tree diff | These select alternative targets.                                            |
| Analysis mode | Standard or deep                                           | Deep supports repository/path scopes and built-in validation.                |
| Orchestration | One scan, components, repository batch                     | Components currently run standard scans. Batch retries apply per repository. |

`bulk` and `components` should not become additional values of `scan.mode`. A list
of scoped paths should not silently turn into independent component scans.

The first proposed workflow is:

```sh
# Prototype commands using a locally built package; not yet released.
codex-security scan -c codex-security.yaml --dry-run --json
codex-security scan -c codex-security.yaml
codex-security scan . -c security/ci.yaml --model gpt-5.6-terra --effort high
```

The only initial new CLI option is `scan [repository] -c FILE` / `--config FILE`.
It selects one YAML or JSON file; the flag is absent by default. Without it,
existing commands do not load project files and retain their scan defaults. A missing or
invalid selected file exits with code `2`. The repository still comes from the
existing positional argument, defaulting to the invocation directory. The file
does not select a repository in this first format.

The existing `scan ... --dry-run` inspects that invocation, including file values,
explicit CLI overrides, their sources, and local target checks. Keep existing
output fields and formats; document any additive fields for resolved deep settings
and project-file provenance. Configuration checks do not prove that authentication,
a provider, a model, or a Codex runtime will work. Checks that only Codex can perform
remain runtime checks.

Initially, `--config` applies only to `scan`.
`bulk-scan` and `scan-components` should not advertise it until their adapters
implement the same resolution behavior. No project configuration is loaded by
finding, publication, authentication, or service commands as a side effect of this
increment.

A project file could contain the following. Paths describe an illustrative project
with the file at its root; the cost limit is an example, not an estimate of scan
cost.

```yaml
# Proposed codex-security.yaml

scan:
  mode: standard
  scope:
    paths: [src, packages]
  knowledgeBase:
    - SECURITY.md
    - docs/architecture.md
  instructionsFile: security/scan.md

codex:
  model: gpt-5.6-sol
  model_reasoning_effort: xhigh

limits:
  maxCostUsdPerScan: 10

policy:
  failOnSeverity: high
```

A file contains only the settings a team wants to change; `{}` uses the existing defaults.
Omitting the output directory preserves the existing private artifact location.
`SECURITY.md` continues to describe security expectations; YAML holds execution
settings and the machine-readable exit policy.

The optional root `$schema` key is editor metadata. YAML may instead use a
`yaml-language-server` comment, as in Promptfoo. The installed CLI uses its bundled
schema; it does not fetch or trust a validator named by the file. See the equivalent
[YAML](examples/codex-security.yaml) and
[JSON](examples/codex-security.json) examples with local generated-schema references.

| Proposed field             | Meaning                                                                                     | Default                                                                    |
| -------------------------- | ------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------- |
| `$schema`                  | Optional editor schema URI or relative path; not a runtime validator selector               | Unset                                                                      |
| `auth`                     | Existing `auto`, `chatgpt`, or `api-key` credential-source choice; never a credential value | `auto`                                                                     |
| `scan.mode`                | Existing standard/deep mode                                                                 | `standard`                                                                 |
| `scan.scope`               | One scope variant, described below                                                          | Whole repository                                                           |
| `scan.knowledgeBase`       | Context files or directories                                                                | Empty list                                                                 |
| `scan.instructionsFile`    | Additional scan instructions, equivalent to `--scan-prompt-file`                            | Unset                                                                      |
| `scan.validationFile`      | Custom validation, equivalent to `--validation-prompt-file`                                 | Built-in validation; custom validation remains incompatible with deep mode |
| `scan.deep`                | Deep discovery defaults                                                                     | Existing deep defaults                                                     |
| `codex`                    | Native Codex configuration keys                                                             | Existing isolated Codex Security defaults                                  |
| `limits.maxCostUsdPerScan` | Estimated USD limit for one launched scan attempt                                           | No limit                                                                   |
| `policy.failOnSeverity`    | Exit threshold: `critical`, `high`, `medium`, or `low`                                      | Report-only                                                                |
| `output.directory`         | Artifact directory outside the scanned Git worktree                                         | Existing private state/artifact location                                   |

`scan.scope` accepts exactly one of these alternatives:

```yaml
# Scope example: repository-relative paths, not glob patterns.
paths: [src, packages]
```

```yaml
# Scope example: committed changes. A base is required; head defaults to HEAD.
diff:
  base: origin/main
  head: HEAD
```

```yaml
# Scope example: staged and unstaged changes. Base defaults to HEAD.
workingTree:
  base: HEAD
```

Omit `scan.scope` to select the whole repository. Reuse existing target validation
and Git comparison semantics. This proposal does not add glob expansion, exclusion
patterns, or support for deep diff scans.

The `codex` object uses the existing native vocabulary. `--model` maps to
`codex.model`, `--effort` to `codex.model_reasoning_effort`, and `--provider` to the
existing native provider selection/presets. Do not add another top-level YAML
`model` or `provider` field. Existing plugin ownership, multi-agent requirements,
credential handling, and permission restrictions continue to apply. YAML does not
make previously unsupported native overrides valid. Wrapper path rules below do
not reinterpret paths inside native configuration.

Native profile selection remains a separate step from merging the same key across
layers. Today, a selected profile's model or effort can supersede a root value set
with `--model` or `--effort`. Preserve that behavior initially and show the effective
selection in dry-run output. Repairing convenience-flag/profile conflicts and the
special handling of `--provider openai` is a separate compatibility change; do not
promise universal CLI precedence before it is implemented and tested. The examples
use root native settings without profiles.

A deep-scan file could instead include:

```yaml
# Proposed codex-security.deep.yaml

scan:
  mode: deep
  scope:
    paths: [src]
  deep:
    workers: 4
    subagentsPerWorker: 3
    stopAfterNoNew: 4
    stopAfterConsecutiveErrors: 3
    maxDiscoveryRuns: 40
    maxTimeHours: 96

limits:
  maxCostUsdPerScan: 25
```

The values under `scan.deep` are the current deep defaults; the USD limit is
illustrative. `subagentsPerWorker` permits zero; worker and run counts retain their
positive-integer requirements. `maxTimeHours` retains the existing positive-number
and 96-hour maximum constraints. It limits discovery time, not all work in a larger
workflow.

A file may retain deep defaults while selecting standard mode. Validate that block
when loading the file, but omit it from the active standard scan. Explicit
deep-only CLI options with standard mode should continue to fail. A selected custom
validation file with deep mode also remains an error.

`limits.maxCostUsdPerScan` preserves the meaning of the existing per-scan limit.
In-flight requests can finish above the estimate-based threshold. It does not
promise a cap on component planning, cross-scan matching, retries across an entire
batch, or subsequent patching and publication commands. A total-run limit should
be a separate feature with accounting for every included model operation.

The resolution rules should be part of the public contract:

1. For a new scan, apply built-in defaults, applicable legacy user deep settings,
   the selected project file, and explicitly supplied CLI values, in that order.
   This precedence applies to the same setting/key; native profile selection keeps
   its existing semantics. Credentials, executable discovery, state paths, and
   integration environment defaults retain their independent rules.
2. Route commands and handle help/schema requests before reading project files.
   Load exactly the file selected by `-c`, supporting `.yaml`, `.yml`, and `.json`
   as the same input contract. Do not discover another file first or interpret the
   path as a glob. Parsing a file must
   not initialize authentication, providers, scan history, or the Codex runtime.
3. Resolve the CLI repository relative to the invocation directory, as today. Keep
   repository selection out of the initial project schema. A file in another
   directory does not change the selected repository.
4. Resolve project-file context, instruction, validation, and output paths relative to the
   config file. Resolve CLI file paths relative to the invocation directory. Scope
   paths remain relative to the selected repository. Normalize these wrapper-owned
   paths while their origin is known; do not recursively rewrite native Codex
   values. Preserve existing protected-root, output, and credential checks.
5. Keep absent CLI values absent through both argument parsing and schema parsing.
   Making a default-bearing schema partial is not sufficient. Merge explicit
   values using presence information or an input schema without defaults. Preserve
   false, valid zero values, and supported empty lists; do not merge by truthiness.
6. Merge wrapper settings by field and replace lists. Repeated CLI `--path` or
   `--knowledge-base` arguments replace the corresponding file list. A CLI scope
   selector replaces the whole file variant: `--diff REF` must not inherit file
   paths. Dependent flags such as `--head` refine the selected compatible scope
   after merging; `--base` keeps its working-tree meaning. Contradictory explicit
   scope selectors remain errors.
7. Map convenience flags to their existing native keys and retain duplicate/alias
   checks within the CLI layer. Overriding a file value is not a duplicate argument.
   Merge native objects using existing native configuration code. Do not flatten
   selected profiles or silently change native resolution as part of adding a file
   loader.
8. Reject unknown wrapper keys and invalid field types when parsing the file.
   Validate cross-field combinations on the resolved active
   scan, so CLI overrides can change the mode or scope. Reuse current checks inside
   `codex`; leave validation that requires Codex to the runtime.

For example, from a project root, `scan . -c security/codex-security.yaml` keeps
that project as the target. YAML instruction files resolve relative to `security/`;
`scan.scope.paths` resolves relative to the project root. CLI file overrides retain
their invocation-relative behavior. Verify these rules on Windows as well.

Replacement is not the same as clearing. The existing CLI has no general reset for a configured severity policy, cost
limit, context list, or whole-repository scope. Its existing `--no-working-tree`
can disable a configured working-tree scope, but cannot clear another scope kind. Initially, edit the file or select an alternative file that omits those
settings; omitting `-c` skips all project settings. Do not claim that every YAML
setting has an expressible CLI reset. An empty context list is an empty list;
`null` is not a general reset operator for wrapper fields. A later discovery
increment can add the project-only bypass described below.

Keep the first format limited to settings. Do not add embedded credentials,
executable JS/TS config files, wrapper shell hooks, environment templating, remote
includes, `extends`, multiple-file merging, or a second project-profile hierarchy.
Native Codex settings, including profiles and tool configuration, retain their
existing capabilities and checks; they are not made inert by being written in
YAML. Separate files selected with `-c` are sufficient for initial CI and deep-scan
workflows. Use existing environment-based credential mechanisms rather than
creating a new YAML environment loader.

Patching, PR creation, publication, hook installation, archival, and post-scan
workflows remain explicit commands/options. Do not add automatic `patch: true` or
`publish: true` behavior to discovered YAML. Machine-specific `--python` and
`--plugin-path` overrides retain their existing explicit CLI/SDK/environment paths
rather than becoming project defaults. These choices keep the first increment
focused and preserve the distinction between repository data and authorization.

The legacy deep TOML file needs a compatibility adapter, not an automatic rewrite:

| Existing `[deep_scan]` key      | Proposed project key                   |
| ------------------------------- | -------------------------------------- |
| `workers`                       | `scan.deep.workers`                    |
| `subagents`                     | `scan.deep.subagentsPerWorker`         |
| `stop_after_no_new`             | `scan.deep.stopAfterNoNew`             |
| `stop_after_consecutive_errors` | `scan.deep.stopAfterConsecutiveErrors` |
| `max_discovery_runs`            | `scan.deep.maxDiscoveryRuns`           |
| `max_time_hours`                | `scan.deep.maxTimeHours`               |

Continue accepting legacy `workers = "auto"` while reading old TOML and normalize it
to the existing value of four. Do not add that legacy value to the new format.
Project settings and explicit flags override user deep defaults. Reuse or generate
from the existing [deep configuration definitions](../../plugins/codex-security/scripts/deep_scan_config.py)
so the YAML loader does not introduce another hand-maintained set of defaults.

Before the prototype, preflight and recipe construction selected explicit
TypeScript options, while runtime preparation separately read the legacy TOML. The Python resolver also supported
`stop_after_consecutive_errors`, which the TypeScript adapter did not expose.
Resolve all six effective settings once, validate them with the existing rules,
and pass that result to dry run, execution, and recipe persistence. The runtime
must consume those resolved values instead of rereading user/project configuration.
The prototype adds the YAML adapter; it does not require a new public CLI flag.
Resolving legacy deep settings earlier also changes deep dry runs without `-c`:
they can show those defaults and reject invalid legacy settings before execution.
Document that validation/output change explicitly; it does not change the actual
deep-scan defaults.

The CLI should parse project input into typed settings, then resolve those settings
to the existing `CodexSecurityConfig` and scan inputs. Keep file parsing, field
resolution, local preflight, and runtime preparation separate. Do not build a
general configuration framework or consolidate all command metadata before the
single-scan path works. The relevant current implementation is in
[CLI registration](../../sdk/typescript/src/cli.ts),
[native configuration](../../sdk/typescript/src/config.ts),
[scan APIs and saved recipes](../../sdk/typescript/src/api.ts), and
[target resolution](../../sdk/typescript/src/targets.ts).

Generate and package an editor JSON Schema with the first file-loader increment,
using a canonical serializable Zod input definition and explicit input-mode
conversion. Use Draft-07 for this project contract, matching Promptfoo; leave
existing Draft 2020-12 artifact contracts unchanged. Check the same valid and
invalid inputs against Zod and Ajv without inserting defaults, coercing types, or
stripping unknown wrapper keys. File loading uses the generated schema with the
existing Ajv engine, avoiding Zod's cloning behavior for reserved object keys.
The [schema design](configuration-schema.md)
defines the boundary between structural input checks and active-scan validation.

Incur's command schemas and help remain available. `scan --schema --json` describes
CLI arguments/options, not the project-file schema. Native Codex configuration,
scan results, and recipes retain their separate contracts. There is no parser
replacement or new orchestration runtime in this proposal.

SDK users should explicitly request file loading. Existing `CodexSecurity.run()`
calls must not start discovering YAML in the caller's current directory. Share
schemas and resolution logic between CLI and SDK while preserving explicit library
inputs and the current plugin configuration format.

The initial recipe change should record resolved active settings, including values
that came from project files or legacy deep defaults, using existing private artifact
storage and credential exclusions. Build it from the resolved scan, not the raw
CLI options. Preserve existing revision and plugin metadata. `scans rerun` should
consume these saved settings without rediscovering current project files or changing the
recorded deep defaults. Older recipes need an explicit compatibility path.

This does not promise complete input replay. Preserve existing requirements to
re-supply prompts that recipes do not retain; referenced context can still use
current file contents. State that limitation when rerunning. Recording a source
revision also does not make rerun restore that checkout. Report the source actually
scanned. A separate replay design should cover retaining prompt/context contents,
missing-input errors, source restoration, and runtime/plugin version pinning. A
path or hash alone is insufficient to reproduce an edited or deleted input.

After the explicit-file path is proven, a separate increment can add the following
workflow conveniences:

| Proposed syntax or behavior                     | Contract                                                                                                                                    | Compatibility                                                                                                                  |
| ----------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| Discover `codex-security.yaml` for `scan`       | Look only in the invocation directory. No parent walk, cloned-repository discovery, or implicit file merging.                               | Deliberate new behavior when that file exists; never applied to unrelated commands. An explicit `-c` skips discovery entirely. |
| `scan [repository] --no-config`                 | Skip project YAML only. Keep legacy deep defaults, credentials, managed policy, and environment-based runtime/state settings.               | Reject combination with `--config`. This is not a clean-room run or a bypass for existing user configuration.                  |
| `init [directory]`                              | Write a small commented YAML file; default to the invocation directory and leave existing files unchanged.                                  | No login, dependency installation, inference, or scan.                                                                         |
| `config validate [-c FILE]`                     | Validate the file's wrapper schema and combinations without loading runtime providers. Exit `0` when valid and `2` when invalid or missing. | Separate from the existing finding-validation command. Does not certify runtime availability.                                  |
| `config show [-c FILE \| --no-config] [--json]` | Show file/default settings and their sources, even when no project file exists.                                                             | No inference or raw credential-bearing config dump. The existing scan dry run remains the invocation-specific preview.         |

Keep help, version, and schema output independent of file validity. These commands
should use the same parser/resolver, not instantiate a scan to inspect settings.
Discovery also needs an explicit review of native tool/profile settings in
repository-owned YAML; its introduction should not be hidden in the initial loader
change. No new bypass for the legacy deep TOML is proposed here.

Once configuration resolution is shared, a later increment can let
`scan -c FILE` describe a monorepo component plan or an explicitly selected repository
portfolio. Use a single `repository` with explicit `components`, or a mutually
exclusive `repositories` list. Preserve full revision pinning for portfolio inputs,
component report aggregation, retry receipts, and separate repository histories.
Keep the current CSV and JSON inputs as adapters to the same internal plan.

That increment should introduce an outer `execution.concurrency` and
`execution.maxAttempts`, separate from `scan.deep.workers` and
`scan.deep.subagentsPerWorker`. It must preserve the current standard-only
component behavior until another change adds deep component support. Automatic
component planning remains explicit model work; `init`, config inspection, and
local dry-run checks should not silently perform it.

The following CLI changes are candidates for that later compatibility discussion,
not prerequisites for the first YAML increment:

| Current surface                   | Possible preferred surface                                    | Compatibility requirement                                                                |
| --------------------------------- | ------------------------------------------------------------- | ---------------------------------------------------------------------------------------- |
| `bulk-scan` and `scan-components` | `scan -c FILE` with explicit orchestration input              | Retain CSV/JSON and old-command adapters; do not infer components from ordinary paths.   |
| `--workers` on bulk/components    | `--concurrency`                                               | Preserve the old outer-concurrency meaning as an alias.                                  |
| `--workers` on deep scans         | `--deep-workers`                                              | Preserve the old discovery-worker meaning as an alias.                                   |
| `--subagents`                     | `--subagents-per-worker`                                      | Preserve zero and per-worker semantics.                                                  |
| `--max-cost`                      | `--max-scan-cost`                                             | Never silently reinterpret an existing per-attempt limit as a total-run limit.           |
| `--diff BASE`                     | Also accept `--base BASE [--head HEAD]` for committed changes | Retain `--working-tree --base REF`, alias checks, and existing Git comparison semantics. |
| `login`, `login status`, `logout` | `auth login`, `auth status`, `auth logout`                    | Keep existing entrypoints as compatibility aliases.                                      |
| `install-hook`                    | `hooks install`                                               | Preserve hook installation behavior.                                                     |
| `dedupe`                          | `findings dedupe`                                             | Make its model and findings-API work explicit.                                           |

Keep `scan [repository]` short and retain useful direct finding-action commands.
Keep `--to` as the only generic integration selector, with destination-specific
fields such as `--linear-team` and `--linear-project`. Do not generalize integration
fields whose meanings differ.

Output cleanup should proceed separately from command renaming. Help should list
only formats and filters that a command supports, including accepted JSON aliases.
Keep result serialization distinct from `--export-format`, `--output`, and
`--output-dir`. Do not repurpose the existing `--format` flag or silently change
structured output as part of adding YAML. Matching, comparison, and deduplication
should state when they invoke models or persist results.

Preserve scan exit behavior during the rollout: `0` for completed work without a
policy breach, `1` for a finding-policy breach, `2` for invalid, failed, or incomplete
work, and existing cancellation codes. YAML must not make a partial scan pass.
`policy.failOnSeverity` changes the exit decision, not which findings are retained.
When batch/components adopt the policy, operational failures take precedence over
a clean severity result. The sample threshold of `high` does not change the
report-only default.

The implementation should be delivered in focused increments:

1. Add explicit `scan -c FILE` for equivalent YAML/JSON input, its generated and
   packaged editor schema, shared resolution, and integration with existing dry
   run and scan execution. Resolve effective deep
   settings once and persist those values in recipes. Preserve scan defaults without
   `-c` and document earlier deep validation; do not block on CLI renaming or a
   general metadata refactor.
2. Add agreed discovery, project-only bypass, initialization, and config inspection
   using that same resolver. Test malformed discovered files and explicit-file
   selection through the real CLI.
3. Adapt batch/component inputs and CI policy to shared settings while preserving
   orchestration, inventories, retry behavior, and capability limits. The proposed
   portfolio/component schema needs its own review before accepting new shapes.

Review alias/profile precedence repairs, output/help cleanup, command renaming,
complete input replay, and total-run cost accounting independently. They address
real concerns but are not all prerequisites for loading one project file. Any
accepted behavior change needs its own compatibility notes and validation.

Acceptance checks should cover observable behavior:

- Equivalent supported CLI and YAML input resolves to the same effective options.
  Exercise the actual argument parser and action schema, not just a hand-built
  option object passed to a resolver.
- Equivalent YAML and JSON input passes the same input contract. Editor metadata
  does not select another runtime validator, and the packaged schema works offline.
  The file loader and generated schema agree on structural input fixtures without
  modifying them, including reserved unknown wrapper keys.
- Absent arguments remain absent through both parser layers. Explicit false/zero
  and supported list values survive; scope selection replaces the file variant,
  and dependent scope flags are checked after merging.
- Explicit selection reads only the selected file. Legacy deep settings and native
  profiles follow the documented rules, including from another working directory.
- Dry run, execution, and new recipes consume the same resolved deep defaults,
  including the error-stop setting previously missing from the TypeScript adapter.
- Repository-relative and config-relative paths remain distinct and work on
  Windows; current output and protected-path rules remain enforced.
- Invalid wrapper keys, types, and active combinations fail before
  inference. Help/schema output and local dry runs do not launch models, publish
  results, or initialize live scan history just to inspect settings.
- New recipes do not absorb edited YAML or changed deep defaults. Reruns identify
  their current-file/source limitations and retain explicit prompt requirements.
  Exact input replay remains outside the initial acceptance claim.
- Existing credential exclusions apply to configuration inspection and recipes.
  Existing machine output and scan exit codes remain compatible.

The first implementation review should settle the field names, native pass-through
boundary, and effective deep-settings adapter. The later discovery increment adds
checks for project-only bypass, invalid ambient files, and inspection without
runtime initialization. Broader command restructuring and portfolio shape should
remain separate from proving the single-scan configuration contract.
