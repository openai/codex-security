# triage-finding eval

This Promptfoo suite verifies that `$codex-security:triage-finding` accepts the current supported input source types and returns the expected `triage-finding/v0`
JSON result shape. It also covers bare skill invocation with no supplied finding,
which should prompt the user for a finding in a supported format instead of returning triage JSON. GitHub REST intake cases cover the repository-source control flow, endpoint selection, and connector auth-only rule without querying live GitHub during the eval.

The suite uses the Promptfoo Codex SDK provider because it only needs final assistant output and deterministic assertions. The eval directory owns a small pinned Bun environment so new cases can be added and run without a separate scratch setup.

Run these commands from the repository root.

The eval directory has its own `package.json`, `bun.lock`, and `bunfig.toml` so it remains a standalone workspace when imported into another repository. Use Bun 1.3.14 and a supported Node.js version. Installs preserve the seven-day minimum release age and allow only `better-sqlite3` to run dependency lifecycle scripts, including its native build.

Install the local eval runner:

```bash
bun run --cwd plugins/codex-security/skills/triage-finding/evals setup
```

Validate the config:

```bash
bun run --cwd plugins/codex-security/skills/triage-finding/evals validate
```

Run the full eval:

```bash
bun run --cwd plugins/codex-security/skills/triage-finding/evals eval
```

Run the first case as a quick smoke test:

```bash
bun run --cwd plugins/codex-security/skills/triage-finding/evals eval:smoke
```

Run one case while iterating:

```bash
bun run --cwd plugins/codex-security/skills/triage-finding/evals eval --filter-metadata case_id=sarif-redirects
```

The eval target is `fixtures/repo`, a small synthetic Express app with both true positive and false positive/review cases. Assertions are deterministic:

- `contains-json` validates the fenced `triage-finding/v0` JSON block against `schemas/triage-result-v0.schema.json`.
- `assertions/triage-io.js` checks input order, `input_id`, `source_type`,
  verdicts, array fields, and `$fix-finding` handoff behavior.
- `tests/invocation-behavior.yaml` opts out of those default JSON assertions for the no-finding case with `options.disableDefaultAsserts: true`.
- `assertions/missing-input.js` checks that bare invocation asks for a finding,
  names supported input formats, and does not emit triage result JSON.
- `tests/github-rest-intake.yaml` opts out of default JSON assertions for GitHub repository-source routing cases.
- `assertions/github-rest-intake.js` checks GitHub source selection, REST endpoint selection, Codex project repository inference, advisory/private-report handling, connector auth-only behavior, and explicit-only GitHub Issue handling.

## Calibration Dataset

`datasets/triage-calibration-seed.json` is the first OSS-only calibration dataset for scaling beyond the synthetic fixture app. It contains public OSS vulnerable/fixed commit pairs. Each dataset variant becomes one Promptfoo test case in `tests/calibration-oss.yaml`, and each test points Codex at a pinned local checkout under `artifacts/calibration-repos/`.

ELI5: the dataset says "this exact old commit should be affected" and "this exact fixed commit should not be affected." The generator turns those rows into Promptfoo test prompts. The hydrator downloads the exact repo commits so Codex can inspect real code instead of synthetic snippets.

Validate the dataset structure:

```bash
bun run --cwd plugins/codex-security/skills/triage-finding/evals test:dataset
```

Run all deterministic calibration checks:

```bash
bun run --cwd plugins/codex-security/skills/triage-finding/evals test:calibration
```

Regenerate the Promptfoo calibration tests:

```bash
bun run --cwd plugins/codex-security/skills/triage-finding/evals calibration:generate
```

Hydrate the local OSS checkouts:

```bash
bun run --cwd plugins/codex-security/skills/triage-finding/evals calibration:hydrate
```

Validate the calibration Promptfoo config:

```bash
bun run --cwd plugins/codex-security/skills/triage-finding/evals validate:calibration
```

Run one OSS variant as a smoke eval:

```bash
bun run --cwd plugins/codex-security/skills/triage-finding/evals eval:calibration:smoke
```

Run the full OSS calibration eval:

```bash
bun run --cwd plugins/codex-security/skills/triage-finding/evals eval:calibration
```

The calibration config is separate from the default synthetic eval:

- `promptfooconfig.yaml` covers the small fixture app and GitHub intake routing.
- `promptfooconfig.calibration.yaml` covers the OSS vulnerable/fixed commit pairs and adds `assertions/calibration-evidence.js` to check that required paths or fix commits are cited in the response.
- `promptfooconfig.calibration-smoke.yaml` covers a generated one-row smoke file under `artifacts/calibration-smoke.yaml`.

The calibration eval uses the Codex SDK provider, which shells out to `codex exec`. Run it from a normal shell or an unsandboxed command runner so the Codex CLI can write its normal `$CODEX_HOME` state.

Generated local state is ignored:

- `node_modules/` contains the pinned Promptfoo/Codex SDK runner.
- `.promptfoo/` contains Promptfoo's local state.
- `artifacts/` contains hydrated OSS checkouts and eval result exports such as `artifacts/triage-finding-calibration-eval.json`.

## SastBench

The complete SastBench harness, documentation, tests, prompt, assertion, and Promptfoo configuration live under [`sastbench/`](./sastbench/README.md).
