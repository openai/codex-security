# Contributing

Thanks for helping improve Codex Security. We welcome bug reports, feature
requests, documentation corrections, and feedback from open-source
maintainers.

## How this repository works

`plugins/codex-security/` is the canonical source for the Codex Security
plugin. Make plugin changes there.

The npm runtime under `sdk/typescript/_bundled_plugin/` is generated from the
plugin source by `pnpm run build:plugin` and automatically during `prepack` for
packages and releases. Do not edit or commit files in that directory. See the
[SDK testing guide](sdk/typescript/TESTING.md) for the generation and validation
commands.

Compact artifact contracts are authored in `plugins/codex-security/mcp-app/src/artifact-contracts.ts`, with shared finding and threat-model definitions in `finding-detail-schemas.ts` and `threat-model-schema.ts`.
Canonical findings, scan-manifest, and coverage exports are defined in `mcp-app/scripts/canonical-schemas.mts`; patch-risk exports and their static type are defined in `mcp-app/src/patch-risk-schema.ts`.
The corresponding JSON schemas are generated compatibility resources. Canonical runtime validation continues to use the selected plugin's JSON schemas.
Model-facing MCP schemas are projected by [`artifact-schema-loader.ts`](plugins/codex-security/mcp-app/src/artifact-schema-loader.ts).
After editing the contracts, run `node plugins/codex-security/mcp-app/scripts/generate-artifact-schemas.mjs`.
The MCP `typecheck` command checks that the generated resources are current. SDK model generation remains based on the canonical JSON exports.

`pnpm --dir sdk/typescript run generate:models` also copies workbench argument
encoding and executable path handling from the plugin source into the SDK. Edit the
plugin helper, then regenerate its SDK copy. Historical finding normalization is
maintained in the SDK.
`pnpm --dir sdk/typescript run types` checks freshness.

Model-based evaluations live in [`evals/`](evals/README.md), outside the plugin
source. Deterministic triage checks and the MCP reducer IPC regression remain
part of normal CI.

See the [CI guide](docs/ci.md) for check selection, platform/version coverage,
required status checks, and test-runner qualification.

## Where to make a change

Start with the owner of the behavior, then follow its callers when the change
crosses a process, persistence, or package boundary.

| Change                                          | Source to start with                                                                                                                                                                                                                   | Relevant checks                                                                                                                                                                                                              |
| ----------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Plugin instructions                             | [Skills](plugins/codex-security/skills/) and shared [references](plugins/codex-security/references/)                                                                                                                                   | [Portable plugin source checks](AGENTS.md#keep-it-simple)                                                                                                                                                                    |
| Artifact contracts and generated SDK models     | [Contract definitions](plugins/codex-security/mcp-app/src/artifact-contracts.ts), [canonical exports](plugins/codex-security/mcp-app/scripts/canonical-schemas.mts), and [model generator](sdk/typescript/scripts/generate-models.cjs) | [Canonical contract tests](plugins/codex-security/mcp-app/tests/test_canonical_artifact_contracts.ts), [MCP wire tests](plugins/codex-security/mcp-app/tests/test_compact_artifact_wire.ts), and the generation checks above |
| Deep Scan scheduling and workers                | Shared [engine, coordinator, and executor](plugins/codex-security/mcp-app/src/deep-scan/), used by the MCP server and SDK launcher                                                                                                     | [MCP tests](plugins/codex-security/mcp-app/tests/) and [direct SDK integration](sdk/typescript/tests-ts/direct-deep-scan.test.ts)                                                                                            |
| Durable scan state, checkpoints, and completion | [Python workbench](plugins/codex-security/scripts/workbench_db.py) and [Deep Scan persistence](plugins/codex-security/scripts/deep_scan_workbench.py)                                                                                  | [Python tests](plugins/codex-security/tests/) and [SDK workbench integration](sdk/typescript/tests-ts/deep-scan-workbench.test.ts)                                                                                           |
| Helper routing and stored-finding operations    | SDK [runtime routing](sdk/typescript/src/runtime.ts), plugin [helper entrypoint](plugins/codex-security/mcp-app/helpers-main.ts), and [Node workbench commands](plugins/codex-security/mcp-app/src/workbench/commands.ts)              | [SDK runtime tests](sdk/typescript/tests-ts/runtime.test.ts) and [MCP workbench tests](plugins/codex-security/mcp-app/tests/)                                                                                                |
| Public CLI and SDK behavior                     | [CLI adapter](sdk/typescript/src/cli.ts), [SDK API](sdk/typescript/src/api.ts), and adjacent modules                                                                                                                                   | [SDK tests](sdk/typescript/tests-ts/) and the [installed-package checks](sdk/typescript/TESTING.md)                                                                                                                          |
| Markdown report rendering                       | [Scan report projection](plugins/codex-security/scripts/report_projection.py) and [threat-model projection](plugins/codex-security/scripts/threat_model_projection.py)                                                                 | [Report tests](plugins/codex-security/tests/test_report_projection.py) and [threat-model tests](plugins/codex-security/tests/test_threat_model_projection.py)                                                                |
| Native filesystem and process operations        | [Native bindings and adapters](plugins/codex-security/native/README.md)                                                                                                                                                                | The native guide's platform proofs and package checks                                                                                                                                                                        |
| Packaged plugin contents                        | [Plugin manifest](plugins/codex-security/plugin-files.json) and [SDK plugin builder](sdk/typescript/scripts/build-plugin.mjs)                                                                                                          | [Package inspection and installed consumers](sdk/typescript/TESTING.md)                                                                                                                                                      |

The SDK routes selected stored-finding and classification commands to the Node
helper; scan lifecycle commands still use the Python workbench. Trace the
specific command before changing either implementation. Shared Deep Scan
behavior belongs in the plugin engine, with adapter changes in the MCP server
or SDK only when their entrypoint behavior differs.

Search [existing issues](https://github.com/openai/codex-security/issues)
before opening a new one.

## Support for open-source projects

If you maintain an open-source project,
[open an issue](https://github.com/openai/codex-security/issues/new) with the
repository, your role, and what you need. Support is best effort. Scan only
repositories you trust and either own or have permission to assess.

## Report a bug

Include your CLI or SDK version, operating system, reproduction steps, and
the expected and observed behavior. Remove credentials, private code,
customer data, and security findings before posting.

## Suggest a feature or improve the documentation

Open an issue describing the problem and the workflow you want to support.
Documentation corrections and safe examples are welcome.
Use synthetic examples when documenting expected behavior.
Keep example values fictional and safe to share.
Do not include credentials or private information in examples.

## Report a security issue

Report Codex Security vulnerabilities privately as described in
[SECURITY.md](SECURITY.md). Do not post vulnerabilities, exploit details,
credentials, or sensitive scan results publicly.

If a scan finds a vulnerability in another project, report it to that
project's maintainers through their security policy.

## Pull request labels

Keep pull request labels focused on release behavior and material platform
impact. Do not apply `area:*` labels to pull requests; describe the affected
surface in the title and description. Issues retain their existing area,
priority, and status labels. Existing maintainer triage labels can remain on
pull requests while they identify actionable, unresolved work.

Preserve the release labels `bug`, `enhancement`, `documentation`,
`breaking-change`, and `skip-release-notes`, including maintainer overrides.
Follow their [release-note and version semantics](RELEASING.md). Do not replace
manual `breaking-change` or `skip-release-notes` labels based only on the title.

Use `platform:windows` only when Windows-specific behavior is material to the
change. Dependabot uses `dependencies` across all package ecosystems. Labels
are not required to open, test, review, or merge a pull request.

## Investigate a CI failure

Open the `node-ci` run for the PR revision that failed. The `ci` job reports
the overall result. Open the failing build, test shard, or validation job to
find the original error. If a later attempt passed, use the run's attempt
selector to inspect the first failure. From the command line,
`gh run view RUN_ID --attempt 1 --log-failed` shows that attempt's failed steps.

For a transient infrastructure failure, rerun the failed jobs after checking
the original logs. For a failed assertion, reproduce it on the reported
platform with the logged seed when available. See the [CI guide](docs/ci.md)
for check selection and the [SDK testing guide](sdk/typescript/TESTING.md)
for local reproduction.

## Dependency and release maintenance

Maintainers update package dependencies and committed lockfiles with the
affected source. The public release workflow installs those locked graphs,
tests the package, and publishes a verified artifact with npm provenance.
GitHub Actions dependencies are maintained separately in this repository.

Workflow and composite-action changes run `workflow-quality` through
`node-ci`. actionlint validates workflow syntax, and ShellCheck
checks shell scripts in workflow `run` steps for warnings and errors. zizmor's
offline checks at medium severity and above cover workflows and composite
actions. The pinned tool versions are in `.github/workflows/workflow-quality.yml`;
run these checks locally with:

```bash
SHELLCHECK_OPTS=--severity=warning actionlint
zizmor --offline --strict-collection --min-severity medium --config .github/zizmor.yml .github
```

The actionlint configuration preserves GitHub's supported release queue and
job-level cache syntax until the linter supports them. The zizmor configuration
records reviewed privileged triggers and their trust boundaries. Review these
exceptions when changing the affected workflows.

CI and npm release validation audit both production lockfiles. To reproduce
an audit, run its command from the project directory:

| Project                          | Command                                                        |
| -------------------------------- | -------------------------------------------------------------- |
| `sdk/typescript`                 | `pnpm run audit:prod --config.lockfile-dir=.`                  |
| `plugins/codex-security/mcp-app` | `pnpm audit --prod --audit-level high --config.lockfile-dir=.` |

Resolve high or critical advisories, or audit service failures, before retrying.

[GitHub Releases](https://github.com/openai/codex-security/releases) is the
canonical changelog. Maintainers should follow [RELEASING.md](RELEASING.md) to
prepare, publish, verify, or repair a release.

See the [SDK testing guide](sdk/typescript/TESTING.md) for local checks,
test conventions, and the required and experimental CI jobs.
