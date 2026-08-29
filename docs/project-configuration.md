# Project configuration prototype

This working tree implements the first increment of the
[configuration proposal](proposals/cli-and-project-configuration.md). It is not a
released CLI feature. Build the local package before trying it:

```sh
cd sdk/typescript
pnpm run build:plugin
pnpm run build
cd ../..
node sdk/typescript/bin/codex-security.mjs scan . -c docs/examples/codex-security.yaml --dry-run --json
```

The [YAML example](examples/codex-security.yaml) and equivalent
[JSON example](examples/codex-security.json) select this repository's TypeScript
source. A dry run checks local inputs; it does not start Codex, verify credentials,
or establish that a model is available. Removing `--dry-run` starts a scan and may
incur model charges.

The [QA report](project-configuration-qa.md) records the checks, fixes, and limits
of the local prototype.

## Select a file

`scan [repository] -c FILE`, also spelled `--config FILE`, loads one `.yaml`, `.yml`,
or `.json` file. Without that option, no project file is loaded, even when a
`codex-security.yaml` exists. Other commands and direct SDK `run()` calls do not
discover project files. There are no new initialization, discovery, or inspection
commands in this increment.

The repository comes from the positional argument or the invocation directory.
Moving the configuration file does not change the target. The initial format
does not accept `repository` or `repositories` keys.

For an ordinary project with a `src` directory, a minimal configuration is:

```yaml
scan:
  scope:
    paths: [src]
codex:
  model: gpt-5.6-sol
  model_reasoning_effort: xhigh
policy:
  failOnSeverity: high
```

All settings are optional; `{}` uses the existing defaults. The file configures
settings, not automatic actions:
patching, PR creation, publication, post-scan actions, and machine-specific plugin
or Python selection remain explicit CLI/SDK inputs.

## Overrides and paths

Built-in defaults and applicable legacy deep settings are followed by the project
file, then explicitly supplied CLI values. Parsing preserves absent values; schema
defaults are documentation hints. Lists are replaced, not concatenated.

| Path or setting                                                                     | Resolution                      |
| ----------------------------------------------------------------------------------- | ------------------------------- |
| Repository positional argument                                                      | Invocation directory            |
| File `scan.scope.paths`                                                             | Selected repository             |
| File `scan.knowledgeBase`, `instructionsFile`, `validationFile`, `output.directory` | Configuration file's directory  |
| CLI context, prompt, and output paths                                               | Invocation directory            |
| Native values under `codex`                                                         | Existing native Codex semantics |

For example, `--knowledge-base context.md` replaces the file's entire context list
and resolves `context.md` from the invocation directory. Existing regular-file,
protected-path, credential, and outside-worktree output checks still apply.

A scope selector replaces the file's scope variant. `--diff HEAD` discards file
paths; `--path src` discards a configured diff. A dependent `--head` can refine a
file diff, and `--base` can refine a file working-tree scope. Contradictory explicit
scope selectors fail. The existing `--no-working-tree` disables a configured
working-tree scope; it does not clear a file's path or committed-diff scope.

There is no general CLI reset for file context, severity policy, cost limit, or
scope. Edit the file, select a different file, or omit `-c`. An empty context list
is valid; `null` is not a wrapper reset operator.

Native objects merge using the existing configuration code. Duplicate native
assignments within the CLI layer remain errors; overriding a file value is valid.
A selected native profile can still take precedence over root model/effort values,
including convenience flags. `--provider openai` retains its existing behavior;
it does not clear a file's native provider selection. This prototype does not
change those compatibility rules.

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

The deep values above are the existing defaults, now shared with the Python
plugin. The cost limit is illustrative, not an estimate. Legacy user
`[deep_scan]` TOML remains supported, including `workers = "auto"`. The file and
CLI can override individual values. All six effective values are resolved before
runtime preparation, written to the runtime configuration, and recorded in new
recipes. A complete saved set does not depend on the current legacy file.

A valid deep block can stay in a standard-mode file; it is inactive in the
standard scan. Explicit deep CLI options still require deep mode. Deep diff scans
and custom validation remain unsupported. Counts retain their existing bounds,
zero subagents is valid, and discovery time cannot exceed 96 hours.

`maxCostUsdPerScan` has the same meaning as `--max-cost`: an estimated limit for one
scan attempt. In-flight work may exceed it. It does not cover a whole batch,
planning, matching, patching, or publication. `failOnSeverity` controls exit status
without removing findings from the result.

## Inspect the effective invocation

Use the existing `scan ... --dry-run --json`. Existing output fields remain, with
these additions:

- Deep preflight reports all six effective deep values and `deepScanSources`
  (`default`, `legacy`, or `override`). This also applies without `-c` and can
  reject invalid applicable legacy settings earlier than before.
- With `-c`, `projectConfig.path` identifies the selected file and
  `projectConfig.sources` identifies the origin of merged settings. Native entries
  describe origins of native keys; native profile selection still determines the
  effective model/effort shown at the top level.
- Selected instruction/validation file paths and the severity policy are included
  when configured. Raw native configuration and credential values are not dumped.

Help, version, and CLI schema inspection do not load project files. A selected
missing, malformed, or invalid file exits `2`. Scan exit codes remain `0` for
completion without a policy failure, `1` for the configured finding threshold,
and `2` for failed, invalid, incomplete, or interrupted scans.

## JSON Schema and editors

The generated [project schema](../sdk/typescript/schemas/project-config.schema.json)
comes from [one Zod input definition](../sdk/typescript/src/project-config-schema.ts)
and ships at `@openai/codex-security/schemas/project-config.schema.json`.
It is self-contained and uses Draft-07. The loader uses the SDK's existing Ajv
validator against that generated schema and retains the parsed input unchanged.
This avoids Zod's cloning behavior for reserved object keys. `pnpm build`
regenerates the schema; tests check the artifact, ordinary Zod/schema agreement,
and file validation at that reserved-key boundary.

For a local package installation, a file at the project root can use:

```yaml
# yaml-language-server: $schema=./node_modules/@openai/codex-security/schemas/project-config.schema.json
{}
```

JSON files can use a root `$schema` string with the same relative path. The CLI
treats it as editor metadata and uses the schema bundled with the installed
package; it never fetches a validator from the hint. No hosted schema URL is
required.

The schema rejects unknown wrapper keys and invalid structural inputs without
coercion or inserted defaults. Checks requiring CLI overrides, files, Git, native
configuration, or runtime availability happen separately. Completion and typo
detection inside `codex` cover common model/provider fields only; other native
JSON settings retain existing checks. CLI `scan --schema --json` and result
artifact schemas remain separate contracts.

## Saved reruns

New recipes retain the resolved native configuration, scope, auth choice, finding
policy, cost limit, context paths, and all active deep settings. Reruns do not load
the project file again. Older partial deep recipes continue using applicable
legacy defaults for missing settings.

Recipes do not snapshot source or context contents. Reruns use the current checkout
and current context files, subject to existing target checks. Additional scan
instructions are not retained: new recipes mark that requirement, and `scans
rerun` refuses to silently omit them. Start a new `scan -c FILE` or `scan
--scan-prompt-file FILE` to supply those instructions again. Custom validation
keeps its existing `scans rerun --validation-prompt-file FILE` requirement.

Complete input replay, automatic discovery, SDK file-loading convenience APIs,
batch/component adoption, and full native-schema completion remain separate work.
