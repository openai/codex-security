# Review: CLI and project configuration proposal

The project-file direction is useful, but the first draft combined too many
changes and treated Promptfoo's configuration behavior as more uniform than it
is. The first implementation should prove that one explicitly selected file
resolves to the right scan. Initialization, automatic discovery, new inspection
commands, broader CLI restructuring, and complete input snapshots can follow.

This review informs the revised
[proposal](cli-and-project-configuration.md). It records the pre-prototype audit
and does not change Promptfoo. The later [prototype](../project-configuration.md)
implements the explicit-file increment.

The follow-up [alignment and JSON Schema design](configuration-schema.md) adds a
concrete draft schema and examines its relationship to runtime input validation,
native Codex settings, command introspection, and existing result schemas.

The implementation review used Promptfoo **0.121.19** at
[ce4c59d](https://github.com/promptfoo/promptfoo/tree/ce4c59d93f055c9dfbbb66d841f681909089ddf0)
and Codex Security **0.1.23** at `0474146`. The Promptfoo source files cited below
matched that commit. Verification included 14 direct loader/parser probes and nine
source-CLI invocations under Node 24.18.0, including two built-in `echo` evaluations
with exported JSON. State, logs, fixtures, and outputs were isolated in temporary
directories. No live model calls, red-team generation, code scans, or publication
were performed. These are observations about the inspected source snapshot, not a
claim about every released build or platform.

The most consequential changes to the first draft are:

| Priority | Weakness in the first draft                                                                                                         | Revision                                                                                                                                                                      |
| -------- | ----------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| High     | A broad option-metadata refactor, precedence repair, five new CLI entrypoints/options, and stronger replay were bundled together.   | Start with `scan -c FILE`, its schema and resolver, and the existing `scan --dry-run`. Do not make unrelated command cleanup a prerequisite.                                  |
| High     | “CLI overrides win” also promised to flatten native profiles, while the compatibility section promised unchanged argument behavior. | Distinguish merging the same configuration key from native profile selection. Preserve existing native semantics initially; review profile/alias behavior changes separately. |
| High     | The planned dry run and recipe were described as fully resolved before checking the separate deep-settings runtime path.            | Resolve legacy deep settings once and pass the same effective values to inspection, execution, and recipe persistence.                                                        |
| High     | A saved configuration was treated as a reproducible scan.                                                                           | Record resolved settings without rereading project YAML on rerun. Treat prompt/context snapshots, source restoration, and runtime pinning as additional work.                 |
| Medium   | Repository selection, discovery, and two different kinds of configuration bypass complicated a settings file.                       | Keep the initial repository selection in `scan [repository]`. Add discovery later; a future `--no-config` should skip project YAML only.                                      |
| Medium   | The override contract mentioned empty lists and false values without explaining what existing flags can express.                    | Document replacement and clearing separately. Do not invent a flag for every reset operation.                                                                                 |

Promptfoo's documented workflow remains a useful product reference: a project
file contains reusable settings, and explicit CLI arguments override defaults.
That is the contract described in its
[configuration reference](https://www.promptfoo.dev/docs/configuration/reference/).
The implementation needs a more qualified reading.

| Promptfoo path | What the implementation does                                                                                                                                                                              | Lesson for this proposal                                                                         |
| -------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| Evaluation     | Startup loads a discovered config before registering Commander options. Execution later reads explicit files, combines them, resolves resources, and applies runtime options.                             | Preserve the distinction between absent arguments and parser-generated defaults.                 |
| Red-team run   | Generates a `redteam.yaml`, then evaluates it through another adapter. The evaluation call explicitly supplies `cache: true` and `write: true`; generation and evaluation have their own option handling. | Shared configuration does not mean every orchestration phase has identical controls.             |
| Code scanning  | Uses a separate small YAML schema, loader, and CLI merge. With no config path, its loader returns defaults without discovering a file.                                                                    | This narrower adapter is a closer starting point for a thin wrapper than the entire eval loader. |

Sources: [CLI startup](https://github.com/promptfoo/promptfoo/blob/ce4c59d93f055c9dfbbb66d841f681909089ddf0/src/main.ts#L54-L80),
[red-team orchestration](https://github.com/promptfoo/promptfoo/blob/ce4c59d93f055c9dfbbb66d841f681909089ddf0/src/redteam/shared.ts#L95-L160),
and [code-scan loader](https://github.com/promptfoo/promptfoo/blob/ce4c59d93f055c9dfbbb66d841f681909089ddf0/src/codeScan/config/loader.ts#L80-L138).
The red-team behavior was traced, not executed.

**Precedence needs to survive both the parser and the schema.** The eval command
uses discovered values as Commander defaults for options such as cache and table
output. Its action then parses those options through a Zod schema. The inherited
delay schema supplies zero even when the user did not pass `--delay`. Later
nullish-coalescing expressions cannot tell those generated values from explicit
arguments. See [command registration](https://github.com/promptfoo/promptfoo/blob/ce4c59d93f055c9dfbbb66d841f681909089ddf0/src/commands/eval.ts#L93-L150),
[command schema](https://github.com/promptfoo/promptfoo/blob/ce4c59d93f055c9dfbbb66d841f681909089ddf0/src/types/index.ts#L93-L121),
[action schema](https://github.com/promptfoo/promptfoo/blob/ce4c59d93f055c9dfbbb66d841f681909089ddf0/src/node/doEval.ts#L76-L90),
and [runtime selection](https://github.com/promptfoo/promptfoo/blob/ce4c59d93f055c9dfbbb66d841f681909089ddf0/src/node/doEval.ts#L527-L558).

The probes used a synthetic file containing:

```yaml
prompts: ["{{value}}"]
providers: [echo]
tests:
  - vars:
      value: synthetic
sharing: false
commandLineOptions:
  cache: false
  table: false
  delay: 17
  maxConcurrency: 2
```

| Probe                                                                                           | Observed result                                                                                                                                |
| ----------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| Parse an explicit `eval -c FILE` with no runtime flags and no discovered config                 | Commander supplies `cache: true` and `table: true`; schema parsing adds `delay: 0`. The loaded file still contains false/false/17.             |
| Discover false cache/table defaults, then select another file containing true values with `-c`  | The resolved file is the explicit file, but the earlier false parser defaults survive.                                                         |
| Run the real source CLI with file table=false/delay=17, plus `--no-cache --no-write --no-share` | A table is printed. Exported runtime options omit delay and retain concurrency 2.                                                              |
| Add explicit `--no-table --delay 17` to that run                                                | The table disappears; exported runtime options contain delay 17 and concurrency 1. Both echo evaluations succeed with no errors or model cost. |

The cache observations above are parser/resolver probes; actual evaluations
explicitly disabled caching. This distinction matters when interpreting the
evidence.

Existing [evaluate-option tests](https://github.com/promptfoo/promptfoo/blob/ce4c59d93f055c9dfbbb66d841f681909089ddf0/test/commands/eval/evaluateOptions.test.ts#L83-L99)
call `doEval` directly with constructed option objects. They provide useful coverage
of runtime precedence, but that path does not exercise Commander defaults or the
action's schema parsing. Our acceptance checks need both resolver tests and a real
CLI invocation. Codex Security already has schema defaults for mode, auth, paths,
and other settings, so this is a concrete integration concern in
[its scan registration](../../sdk/typescript/src/cli.ts).

**Loading must happen after command routing and explicit selection.** Promptfoo's
startup reads default configuration before parsing most commands. A malformed
`promptfooconfig.yaml` made `eval --help` fail and also prevented `validate config
-c VALID_FILE` from reaching the selected file. `code-scans run --help` succeeded
because that command family has an explicit
[default-loading exception](https://github.com/promptfoo/promptfoo/blob/ce4c59d93f055c9dfbbb66d841f681909089ddf0/src/mainUtils.ts#L104-L132).

The proposal should avoid loading a file merely to build help or register
defaults. First route the command; then select the one file it actually uses.
An explicit `-c` must not read the discoverable file first. Loading should not
initialize scan history, authentication, a provider, or a runtime. This also keeps
unrelated commands usable when project YAML is invalid.

**Schema validation and execution preparation are different operations.**
Promptfoo's [reader](https://github.com/promptfoo/promptfoo/blob/ce4c59d93f055c9dfbbb66d841f681909089ddf0/src/util/config/load.ts#L328-L414)
dereferences configuration references and renders environment templates before
validation. It normalizes `commandLineOptions` with a failing validation path, but other schema
errors can be warnings while the original object is returned. A string
`evaluateOptions.maxConcurrency: many` was returned by `readConfig`; the full
validation command subsequently rejected it. A misspelled option was discarded,
and `validate config` reported success. The two namespaces also have different
numeric constraints: negative concurrency was accepted under `evaluateOptions`
and rejected under `commandLineOptions`. These probes do not establish how an
evaluation with negative concurrency would behave.

The [validation command](https://github.com/promptfoo/promptfoo/blob/ce4c59d93f055c9dfbbb66d841f681909089ddf0/src/commands/validate.ts#L470-L511)
calls the full resolver, which
[loads providers](https://github.com/promptfoo/promptfoo/blob/ce4c59d93f055c9dfbbb66d841f681909089ddf0/src/util/config/load.ts#L937-L960).
A local provider fixture wrote a marker from its constructor during validation;
its inference method was never called. This is an execution-boundary observation,
not a claim that loading a trusted local provider is itself a security defect.

For Codex Security, reject invalid wrapper keys and types in the file parser,
merge explicit overrides, and then validate the active scan's combinations.
Keep runtime/model availability checks separate. Generate editor JSON Schema from
the serializable input schema and test the same examples against both validators.
Promptfoo's [schema generator](https://github.com/promptfoo/promptfoo/blob/ce4c59d93f055c9dfbbb66d841f681909089ddf0/scripts/generateJsonSchema.ts#L88-L130)
requires special handling for transforms and runtime-only values; generating a
schema does not automatically prove complete runtime parity.

**Multiple files need field-specific semantics and origin tracking.**
Promptfoo's [combiner](https://github.com/promptfoo/promptfoo/blob/ce4c59d93f055c9dfbbb66d841f681909089ddf0/src/util/config/load.ts#L521-L753)
does not perform one generic deep merge. It combines tests and extensions,
deduplicates providers, merges option objects, treats sharing=false specially, and
rebases some prompt references. The later
[resolver](https://github.com/promptfoo/promptfoo/blob/ce4c59d93f055c9dfbbb66d841f681909089ddf0/src/util/config/load.ts#L815-L849)
still uses the first config's directory as a shared base.

In a two-directory probe, each config's prompt loaded from its own directory, but
a `defaultTest` reference supplied by the second file loaded from the first
directory. A single glob expanding to both config files also raised a path-type
error in this fixture. The relevant lesson is to keep the first Codex Security
format to one file, without `extends`, globs for configuration selection, or
overlays. Normalize each wrapper-owned path while its origin is known. Native
Codex path values need their existing native rules, not a recursive path rewrite.

**Persisted settings are useful, but they are not an immutable dependency set.**
Promptfoo saves configuration and resolved
[runtime options](https://github.com/promptfoo/promptfoo/blob/ce4c59d93f055c9dfbbb66d841f681909089ddf0/src/node/doEval.ts#L773-L786).
Resume prefers those persisted runtime values and
[re-resolves the saved config](https://github.com/promptfoo/promptfoo/blob/ce4c59d93f055c9dfbbb66d841f681909089ddf0/src/node/doEval.ts#L103-L132).
In a direct probe of that resolution primitive, saving a config, editing its
referenced prompt, and resolving the saved config again loaded the edited prompt.
This was not a full pause/resume test. It establishes why a saved file reference
alone cannot promise input replay.

Codex Security has a more immediate gap: its
[preflight and recipe construction](../../sdk/typescript/src/api.ts) select explicit
deep options, while runtime preparation separately reads the legacy TOML. The
Python [deep-settings resolver](../../plugins/codex-security/scripts/deep_scan_config.py)
also supports `stop_after_consecutive_errors`, which is absent from the current
TypeScript `DEEP_SCAN_SETTINGS` adapter. Adding YAML above these paths does not
make them agree automatically.

The first implementation should resolve the active settings once, including all
deep defaults, and retain those values in the recipe. Runtime preparation must
consume them instead of rediscovering configuration. Full prompt/context capture,
source restoration, and runtime-version pinning should have a separate retention
and compatibility design. Do not advertise deterministic reruns before that work.

**Native Codex configuration needs an explicit compatibility boundary.** Current
[model/profile resolution](../../sdk/typescript/src/config.ts) lets a selected
profile's model and effort take precedence over root values. Current CLI alias
handling also rejects duplicate `--model`/`--codex model` values, and an explicit
`--provider openai` does not populate the native provider key in the same way as
the other provider choices. Earlier CLI preflight probes reproduced both behaviors;
they did not run native inference.

The first draft's proposed profile flattening changes those semantics. It should
be reviewed and tested as a compatibility change, not hidden inside YAML merging.
A native `codex` block can also contain paths and tool configuration; calling the
wrapper file declarative does not make every native setting inert. Start with
explicit selection and preserve existing protections. Do not implement another
native profile engine or claim exhaustive validation of future Codex options.

The resulting implementation boundary is small enough to describe precisely:

```text
route command and handle help
  -> select one explicit project file
  -> parse file fields and preserve explicitly supplied CLI fields
  -> resolve wrapper-owned paths and merge settings
  -> apply existing native semantics and validate the active scan
  -> share resolved settings with dry run, execution, and saved recipe
```

No generic configuration framework or complete CLI metadata rewrite is required.
SDK callers should opt into project-file loading. A follow-up can add discovery
and initialization once their absence does not block normal CLI use, and another
can adapt existing batch/component orchestration. Keep command renaming and full
replay separate from those increments.
