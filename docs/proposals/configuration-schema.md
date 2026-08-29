# Promptfoo alignment and JSON Schema design

**Status: design implemented in the local CLI prototype.** This supplements the
[project configuration proposal](cli-and-project-configuration.md) and its
[implementation review](cli-and-project-configuration-review.md). The
[generated JSON Schema](../../sdk/typescript/schemas/project-config.schema.json) and equivalent
[YAML](examples/codex-security.yaml) / [JSON](examples/codex-security.json) examples
use the prototype input contract. See the [prototype guide](../project-configuration.md)
for commands and limits; this feature has not been released.

The proposal aligns closely with Promptfoo's workflow and schema-generation
pattern. Its configuration vocabulary is specific to repository security scans;
the files are not interchangeable with Promptfoo configurations. The first
increment also delivers less convenience than Promptfoo because discovery and
initialization are deferred. Editor schema support should ship with the first
usable file loader, even if those commands follow later.

| Area                         | Promptfoo                                                                       | Proposed Codex Security behavior                                                    | Alignment                                                                    |
| ---------------------------- | ------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------- | ---------------------------------------------------------------------------- |
| Normal invocation            | `eval -c FILE` with file defaults and CLI overrides                             | `scan -c FILE` with file defaults and explicit CLI overrides                        | Close workflow match; native profile semantics remain separately documented. |
| File formats                 | YAML, JSON, and executable JS/TS variants                                       | YAML and JSON as two encodings of one input object                                  | Match the common data formats; omit executable configuration.                |
| Discovery and initialization | Discoverable `promptfooconfig` and `init`                                       | Explicit selection first; discovery and `init` in a follow-up                       | A staged product difference, not a different long-term goal.                 |
| Editor support               | Zod-derived JSON Schema, schema comments, generated assets checked in CI        | Generated JSON Schema and matching examples in the first increment                  | Adopt directly, with input/runtime agreement checks.                         |
| Configuration vocabulary     | Prompts, providers/targets, tests, red-team settings                            | Scan scope, deep discovery, native Codex settings, scan limits, finding exit policy | Different domains; do not copy field names without matching meaning.         |
| Runtime controls             | Both `commandLineOptions` and `evaluateOptions`                                 | One canonical location per setting                                                  | Intentional simplification.                                                  |
| Composition                  | Multiple files, globs, field-specific merges, references, environment templates | One explicit file; ordinary literal values and documented path rules                | Smaller initial contract.                                                    |
| Validation behavior          | Some coercion, unknown-key stripping, warning paths, and later resource loading | Strict wrapper input types/keys, then active-scan checks after merging              | Deliberate behavior difference.                                              |
| Native configuration         | Promptfoo provider abstractions                                                 | Existing native Codex vocabulary under `codex`                                      | Preserve the thin-wrapper architecture.                                      |
| Versioning                   | The inspected project schema has no required format-version field               | No project format-version field; schema ships with the package                      | Same minimal configuration shape.                                            |

This comparison is based on Promptfoo 0.121.19 at
[ce4c59d](https://github.com/promptfoo/promptfoo/tree/ce4c59d93f055c9dfbbb66d841f681909089ddf0),
including its [file reader](https://github.com/promptfoo/promptfoo/blob/ce4c59d93f055c9dfbbb66d841f681909089ddf0/src/util/config/load.ts#L328-L414),
[schema generator](https://github.com/promptfoo/promptfoo/blob/ce4c59d93f055c9dfbbb66d841f681909089ddf0/scripts/generateJsonSchema.ts#L88-L155),
and [generated-asset CI check](https://github.com/promptfoo/promptfoo/blob/ce4c59d93f055c9dfbbb66d841f681909089ddf0/.github/workflows/main.yml#L321-L335).

There are several different schema contracts here. They should not become one
large schema merely because they all use JSON Schema:

| Contract                      | Owner and purpose                                                  | Proposed treatment                                                                                                 |
| ----------------------------- | ------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------ |
| Project input                 | Wrapper-owned settings in YAML/JSON                                | Add one canonical serializable input definition and generate its editor schema.                                    |
| Native `codex` configuration  | Codex's own settings and profiles                                  | Retain native validation; do not hand-maintain a second exhaustive native schema.                                  |
| CLI introspection             | Incur's `scan --schema --json` describes arguments and options     | Preserve it. It is not the project-file schema and includes action-specific flags excluded from project defaults.  |
| Scan artifacts                | Findings, coverage, manifests, and other existing plugin contracts | Leave their schemas and versioning unchanged. They describe results, not user configuration.                       |
| Resolved settings and recipes | Internal effective inputs and saved rerun metadata                 | Keep separate types and compatibility checks. Do not invent another public file format until a consumer needs one. |

The existing [CLI schema tests](../../sdk/typescript/tests-ts/cli.test.ts) and
[artifact validator](../../sdk/typescript/src/contract.ts) already establish those
separate responsibilities. Artifact schemas use Draft 2020-12 and the SDK already
depends on Ajv 8.20.0. No new JSON Schema engine is needed.

For project input, use a small Zod definition containing serializable values only,
and generate JSON Schema from that definition. This follows Promptfoo's approach
and fits the existing Zod-based CLI. Infer the TypeScript input type from the same
definition. Keep callbacks, abort signals, runtime objects, path resolution, and
default application outside it. The prototype uses the generated schema with the
SDK's existing Ajv engine for file validation. Direct probes found that Zod's
cloned output silently omits reserved object keys, even in strict wrapper objects;
Ajv rejects unknown wrapper keys and retains native input for the existing
override checks. Existing artifact schemas remain authoritative for their own
contracts; this is not a migration of all schemas to Zod.

The proposed generation settings are:

```ts
z.toJSONSchema(ProjectConfigInputSchema, {
  target: "draft-07",
  io: "input",
  unrepresentable: "throw",
});
```

Draft-07 matches Promptfoo's project schema and Codex's published native schema.
It supports the needed objects, enums, unions, and numeric constraints. There is
no need to change existing Draft 2020-12 artifact schemas. Current
[YAML Language Server documentation](https://github.com/redhat-developer/yaml-language-server#yaml-language-server)
supports both dialects; this choice does not claim that editors require Draft-07.

Zod's default conversion describes parsed output, while `io: "input"` describes
what authors supply. Use strict objects for wrapper-owned sections so the generated
schema rejects unknown keys. Keep unsupported runtime values out of the schema rather than
converting them to an unconstrained placeholder. These options and their limits
are documented in [Zod's JSON Schema guide](https://zod.dev/json-schema).

The generator is only part of the contract. Direct probes against Promptfoo's
runtime `UnifiedConfigSchema` and checked-in JSON Schema produced these results:

| Input                                    | Runtime Zod schema            | Generated JSON Schema           |
| ---------------------------------------- | ----------------------------- | ------------------------------- |
| Ordinary prompt plus `providers: [echo]` | Accept                        | Accept                          |
| Neither `providers` nor `targets`        | Reject                        | Accept                          |
| Both `providers` and `targets`           | Reject                        | Accept                          |
| Unknown root key                         | Accept and strip              | Reject                          |
| Root `$schema` metadata                  | Accept and strip              | Reject in direct Ajv validation |
| `commandLineOptions.maxConcurrency: "2"` | Accept and coerce to a number | Reject                          |
| Object-valued transform                  | Reject                        | Reject                          |

These were direct schema comparisons, not fresh evaluations or editor tests. The
runtime's [provider/target refinement](https://github.com/promptfoo/promptfoo/blob/ce4c59d93f055c9dfbbb66d841f681909089ddf0/src/types/index.ts#L1320-L1348)
is absent from the inspected generated root schema. Its output-oriented numeric
schema also does not describe every coerced input. Promptfoo has useful
[Ajv regression tests](https://github.com/promptfoo/promptfoo/blob/ce4c59d93f055c9dfbbb66d841f681909089ddf0/test/config-schema.test.ts#L30-L60),
but generation and a valid metaschema do not by themselves establish agreement.

For the proposed wrapper schema, use normal structural unions where possible.
The input scope is an `anyOf` of three strict objects: one requires `paths`, one
`diff`, and one `workingTree`. Because each branch rejects the other branches'
keys, this permits exactly one variant. Avoid encoding the rule only in a custom
refinement that an editor schema might lose.

**Defaults belong to resolution.** A JSON Schema `default` is an annotation, not
an instruction to populate a missing property during validation. The schema includes
built-in defaults as documentation hints; a legacy user setting may still supply a
different effective value. Keep Ajv's `useDefaults`, `coerceTypes`, and
`removeAdditional` disabled. Keep Zod input fields optional without `.default()`
or `.prefault()`. Apply defaults once, after retaining which values each layer
actually supplied. See [JSON Schema annotations](https://json-schema.org/understanding-json-schema/reference/annotations)
and [Ajv's data-modification options](https://ajv.js.org/options.html#options-to-modify-validated-data).

**Input validity and executable scan validity are separate.** The input schema
checks wrapper keys, field types, the scope union, and current
numeric bounds. It deliberately does not reject every combination of individually
valid settings before CLI overrides. For example, a file containing deep mode and
a diff scope is structurally valid input, but cannot execute unless an override
changes the incompatible mode or scope. The existing scan checks must reject an
incompatible resolved combination before inference. The same applies to a custom
validation file with active deep mode. A future `config validate` command should
validate the resolved file/default invocation as well as its structure.

Filesystem existence, Git refs, protected output paths, authentication, model
availability, and cost estimation are not certified by JSON Schema. Nor does the
schema resolve file-relative paths. These remain existing local/native checks;
do not add custom schema keywords that secretly perform I/O.

**The native block needs a narrower promise.** Official OpenAI documentation links
a [native Codex configuration schema](https://learn.chatgpt.com/docs/config-file/config-reference#configtoml).
The currently published schema accepted this checkout's default native settings in
a local Ajv probe. However, it is not identical to the wrapper's contract: it
rejects unknown native keys that the wrapper currently passes through, while it
permits plugin-loading configuration that the wrapper owns and rejects.

The prototype therefore checks common model/provider key types and permits other
JSON-valued native keys, with existing native and wrapper checks still required.
This means typo detection and completion are intentionally incomplete inside
`codex`. Do not claim that the project schema validates every native option.

If full native editor completion is added, reuse an upstream schema matched to the
packaged Codex version. Bundle its references and apply existing wrapper rules
without forking its vocabulary by hand. Do not use the changing latest-schema URL
as a mandatory runtime validation gate. Matching one current default object is
not enough to establish complete version compatibility.

**Editor metadata does not select runtime validation.**

| Location        | Field     | Meaning                                                                                                               |
| --------------- | --------- | --------------------------------------------------------------------------------------------------------------------- |
| Schema document | `$schema` | JSON Schema dialect, such as Draft-07.                                                                                |
| Schema document | `$id`     | Optional identity of that schema document. The prototype omits it; editors resolve references from the file location. |
| Project file    | `$schema` | Optional editor hint pointing to the project schema; not a request for the CLI to fetch or trust another validator.   |

The YAML example uses Promptfoo's familiar language-server comment, with a
relative path to the generated package schema. The JSON example uses a root `$schema`
property explicitly allowed by the input definition. After removing that metadata,
both examples describe exactly the same settings. Runtime validation uses the
schema bundled with the installed package. There is no project format-version field.

The prototype includes the generated schema in the npm package at
`@openai/codex-security/schemas/project-config.schema.json`. The
[package manifest](../../sdk/typescript/package.json) exports that path, and the
package check requires the file. Editors and CI can use the matching package
copy offline. A hosted schema URL can follow once it is actually available.
Keep an exact package-version copy for clients that need to match an older CLI;
a floating latest schema can describe fields that an installed CLI does not accept.
Do not add or repurpose a CLI flag merely to print a schema already shipped as a
file. In particular, preserve the existing command-introspection `--schema` output.

The first implementation's verification should cover:

- Metaschema validity and deterministic generation, with a CI check for changes in
  the generated artifact, following Promptfoo's generated-asset check.
- The same positive and negative input fixtures through Zod and Ajv, including
  unknown keys, literal numeric types, zero subagents, scope exclusivity, metadata,
  empty configurations, and absence of inserted defaults.
- YAML and JSON examples resolving to the same settings after editor metadata is
  removed, plus real CLI tests for file/flag precedence and active-scan validation.
- Schema references resolving from the packed package without a network request,
  and at least one actual YAML/JSON language-service completion/diagnostic check.
- Existing result schemas, command introspection, credential exclusions, and
  native runtime checks remaining unchanged unless separately reviewed.

For this proposal, positive/negative draft fixtures agreed between Zod 4.4.3
and Ajv 8.20.0, and accepted inputs were neither default-filled nor stripped.
Eight Promptfoo comparisons and three native-schema probes informed the boundaries
above. Those initial comparisons predated implementation. The prototype now
keeps 26 cases in [regression tests](../../sdk/typescript/tests-ts/project-config.test.ts),
with separate [CLI tests](../../sdk/typescript/tests-ts/cli-project-config.test.ts).
