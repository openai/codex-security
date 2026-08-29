# Project configuration

Use `scan [repository] -c FILE` or `scan [repository] --config FILE` to load one
YAML or JSON file:

```sh
codex-security scan . -c codex-security.yaml --dry-run --json
codex-security scan . -c codex-security.json --model gpt-5.6-terra
```

The supported extensions are `.yaml`, `.yml`, and `.json`. Without `-c`, no file
is loaded, even if `codex-security.yaml` exists. Other commands and SDK `run()`
calls do not discover project files. The repository comes from the positional
argument or invocation directory; the file cannot select a different target.

For a project with a `src` directory:

```yaml
scan:
  scope:
    paths: [src]
  knowledgeBase: [SECURITY.md, docs/architecture.md]
codex:
  model: gpt-5.6-sol
  model_reasoning_effort: xhigh
policy:
  failOnSeverity: high
```

All settings are optional; `{}` uses the existing defaults. No `version` field
is needed. Unknown wrapper keys and invalid types are errors. Values are literal:
there is no executable configuration, environment interpolation, remote include,
or multiple-file merge. Wrapper `null` values do not reset settings.

The [YAML example](examples/codex-security.yaml) and equivalent
[JSON example](examples/codex-security.json) select this repository's TypeScript
source. After [setting up the source checkout](../sdk/typescript/TESTING.md), try:

```sh
cd sdk/typescript
pnpm run build:plugin
pnpm run build
cd ../..
node sdk/typescript/bin/codex-security.mjs scan . -c docs/examples/codex-security.yaml --dry-run --json
```

## Settings

| Field                      | Meaning                                                                      | Default                            |
| -------------------------- | ---------------------------------------------------------------------------- | ---------------------------------- |
| `auth`                     | Credential source: `auto`, `chatgpt`, or `api-key`; never a credential value | `auto`                             |
| `scan.mode`                | `standard` or `deep`                                                         | `standard`                         |
| `scan.scope`               | Exactly one of `paths: [src]`, `diff: {base: HEAD}`, or `workingTree: {}`    | Whole repository                   |
| `scan.knowledgeBase`       | Context files or directories                                                 | Empty list                         |
| `scan.instructionsFile`    | Additional scan instructions                                                 | Unset                              |
| `scan.validationFile`      | Custom validation instructions; incompatible with active deep mode           | Built-in validation                |
| `scan.deep`                | Deep discovery settings shown below                                          | Existing deep defaults             |
| `codex`                    | Native Codex settings and profiles                                           | Existing isolated configuration    |
| `limits.maxCostUsdPerScan` | Estimated USD limit for one scan attempt                                     | No limit                           |
| `policy.failOnSeverity`    | Exit threshold: `critical`, `high`, `medium`, or `low`                       | Report-only                        |
| `output.directory`         | Artifact directory outside the scanned Git worktree                          | Existing private artifact location |

The file configures scan settings. Patching, PR creation, publication, post-scan
actions, and machine-specific plugin or Python selection remain explicit CLI/SDK
inputs.

## Overrides and paths

Settings apply in this order: built-in defaults, applicable legacy deep settings,
the project file, then explicitly supplied CLI values. Schema defaults are editor
hints; parsing does not insert them. Lists are replaced, not concatenated.

| Path                                                    | Relative to                    |
| ------------------------------------------------------- | ------------------------------ |
| Repository positional argument                          | Invocation directory           |
| File `scan.scope.paths`                                 | Selected repository            |
| File context, instruction, validation, and output paths | Configuration file's directory |
| CLI context, prompt, and output paths                   | Invocation directory           |
| Native values under `codex`                             | Existing native Codex rules    |

For example, `--knowledge-base context.md` replaces the file's entire context list
and resolves from the invocation directory. Existing regular-file, protected-path,
credential, and outside-worktree output checks still apply.

A CLI scope selector replaces the file's scope variant: `--diff HEAD` discards
configured paths, and `--path src` discards a configured diff. `--head` can refine a
file diff; `--base` can refine a file working-tree scope. Contradictory explicit
selectors fail. `--no-working-tree` disables a configured working-tree scope but
does not clear a path or committed-diff scope.

There is no general CLI reset for configured context, policy, cost limit, or scope.
Edit the file, select another file, or omit `-c`. An empty context list is valid.

Native objects merge using the existing configuration code. Duplicate native CLI
assignments remain errors; overriding a file value is valid. Selected native
profiles can still override root model/effort values, including convenience flags.
`--provider openai` retains its existing behavior and does not clear a native
provider selected by the file.

## Deep settings and limits

```yaml
scan:
  mode: deep
  deep:
    workers: 4
    subagentsPerWorker: 3
    stopAfterNoNew: 4
    stopAfterConsecutiveErrors: 3
    maxDiscoveryRuns: 40
    maxTimeHours: 96
limits:
  maxCostUsdPerScan: 10
```

These deep settings show the existing defaults, shared with the Python plugin.
The cost limit is illustrative. Legacy user `[deep_scan]` TOML remains supported,
including `workers = "auto"`. File and CLI values override individual settings.
All six effective values are resolved before runtime preparation and saved in new
recipes.

A valid deep block can stay inactive in standard mode. Explicit deep CLI options
still require deep mode. Deep diff scans and custom validation remain unsupported.
Counts retain their existing bounds; zero subagents is valid, and discovery time
cannot exceed 96 hours.

`maxCostUsdPerScan` has the same meaning as `--max-cost`: an estimated limit for one
scan attempt. In-flight work may exceed it. It is not a total budget for a batch or
follow-up actions. `failOnSeverity` changes the exit status without filtering the
retained findings.

## Dry run and editor support

`scan ... --dry-run --json` checks local inputs without starting Codex, verifying
credentials, or establishing model availability. Removing `--dry-run` starts a
scan and may incur model charges. Deep preflight shows all six effective settings
and `deepScanSources`, including when no project file was selected; invalid
applicable legacy settings now fail before runtime startup.

With `-c`, the output also includes `projectConfig.path`, per-setting sources,
selected instruction/validation file paths, and the finding policy. Native sources
identify which layer supplied a key; profile selection still determines the
effective model and effort. Raw native configuration and credentials are not dumped.

Help, version, and command schema output do not load project files. Missing,
malformed, or invalid selected files exit `2`. Scan exit codes remain `0` for
completion without a policy failure, `1` for the finding threshold, and `2` for
failed, invalid, incomplete, or interrupted scans.

The generated [project schema](../sdk/typescript/schemas/project-config.schema.json)
is self-contained Draft-07 and ships in the npm package. A project-root YAML file
can use:

```yaml
# yaml-language-server: $schema=./node_modules/@openai/codex-security/schemas/project-config.schema.json
{}
```

JSON files can use a root `$schema` string with the same relative path. The CLI
uses its bundled schema and never fetches the hint. Validation does not coerce
values, insert defaults, or discard unknown wrapper keys. Completion inside
`codex` covers common model/provider fields; other native JSON settings retain
existing checks. CLI `scan --schema --json` and result artifact schemas remain
separate contracts.

## Saved reruns

New recipes retain resolved native configuration, scope, auth choice, finding
policy, cost limit, context paths, and all active deep settings. Reruns do not load
the project file again. Complete saved deep settings do not use the current legacy
file; older partial recipes continue using applicable defaults for missing values.

Recipes do not snapshot source or context contents. Reruns use the current checkout
and current context files. Additional scan instructions are not retained: a new
recipe records that requirement, and `scans rerun` refuses to omit them silently.
Start a new `scan -c FILE` or `scan --scan-prompt-file FILE` to supply them again.
Custom validation keeps its existing `scans rerun --validation-prompt-file FILE`
requirement.
