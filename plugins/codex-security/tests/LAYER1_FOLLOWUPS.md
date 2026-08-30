# Layer 1 Deterministic CI Coverage

This file is the source of truth for portable deterministic, no-model Codex Security plugin CI coverage. Future pull requests that extend Layer 1 should update this checklist and link back here in their PR description.

## Covered

- **Python utilities:** unit and CLI tests cover capability preflight, scan contract finalization, rank-input generation and selection, and report format validation.
- **Schema validation:** Draft 2020-12 validators and checked-in completed-scan examples are validated with `jsonschema`, including RFC 3339 formats.
- **Plugin metadata:** the plugin manifest, referenced assets, skill frontmatter, and agent interface YAML are parsed and checked for required fields and file consistency.
- **Prompt linting:** agent default prompts are required to be non-empty.
- **CLI and harness dry runs:** every Python script supports `--help`; major command paths run against temporary repositories and scan bundles without a model call.
- **Static checks:** Ruff and Python bytecode compilation/import smoke checks cover the plugin scripts and tests.
- **Golden files:** deterministic repository ranking JSONL output is compared against a checked-in golden file.
- **MCP dependency lockfile:** required CI installs the MCP app with `bun install --frozen-lockfile`, checking its package metadata against the committed `bun.lock`.

## Deferred

- **Strict mypy hard gate:** the current scripts and tests have pre-existing strict-mypy errors. Enable the gate after reducing that baseline to zero; completion means `mypy scripts tests --strict` passes without suppressing real contract errors.
- **Full documentation reference validation:** add a checker for internal file paths, Markdown anchors, and documented command invocations. Completion means every plugin-local reference resolves and every documented command has a deterministic smoke test.
- **Expanded report and SARIF snapshots:** add larger artifact snapshots and platform-specific path portability fixtures. Completion means representative Windows, macOS, and Linux path cases are covered without platform-dependent golden churn.
- **Automated runtime budget enforcement:** the suite does not track its own historical runtime. Completion means CI records the Layer 1 duration and fails a stable regression threshold before its hard timeout.
- **Canonical plugin manifest schema:** replace the local manifest contract assertions when a centrally maintained Codex plugin manifest schema becomes available. Completion means this project validates against that schema and only keeps local assertions for Codex Security-specific invariants.
- **Eval lockfile consistency in CI:** the eval directory has its own `bun.lock`, but required CI runs its dependency-free deterministic checks without installing Promptfoo. The eval `setup` command checks that lockfile with a frozen install; adding that install to CI remains deferred.

## Not Applicable

- **Model-backed evaluation execution:** deterministic dataset, generator, hydration, and scorer tests belong in Layer 1, but model-backed evaluation execution remains outside Layer 1.
- **Model prompt compilation:** current skill and agent prompts have no runtime placeholder expansion. Structural metadata and non-empty prompt checks are sufficient until parameterized prompt templates are introduced.
