# triage-finding eval

This Promptfoo suite verifies that `$codex-security:triage-finding` accepts the current supported input source types and returns the expected `triage-finding/v0`
JSON result shape. It also covers bare skill invocation with no supplied finding,
which should prompt the user for a finding in a supported format instead of returning triage JSON. GitHub intake cases cover repository-source selection, REST endpoints, and explicit Connector requests without querying live GitHub during the eval.

The suite uses the Promptfoo Codex SDK provider because it only needs final assistant output and deterministic assertions. Codex runs from the checkout's plugin directory and reads its triage skill directly, with ambient plugins and memory disabled. The default suite can also read the synthetic fixtures; calibration cases can read their own hydrated checkout. Dataset labels, assertions, and calibration Git history stay outside those readable roots. The eval directory owns a small pinned pnpm environment so new cases can be added and run without a separate scratch setup.

Use Node.js 22.22.0 or newer for the eval runner. Run these commands from the repository root to install dependencies under this eval directory.

The eval directory has its own `pnpm-workspace.yaml` for its Promptfoo dependencies. Tooling type checks use the SDK’s TypeScript dependencies.

Install the SDK and MCP app dependencies using the repository’s normal setup, then install the local eval runner and check the TypeScript tooling:

```bash
pnpm --dir evals/triage-finding run setup
```

After editing the tooling, rerun `pnpm --dir sdk/typescript run build:evals`. It prepares the SDK and type-checks the eval sources. Node and Promptfoo execute the TypeScript sources directly; package commands enable type stripping for Node 22.13.

Before running model evals, build the checkout's policy helper (requires the [native build prerequisites](../../plugins/codex-security/native/README.md)):

```bash
pnpm --dir plugins/codex-security/mcp-app install --frozen-lockfile
node plugins/codex-security/mcp-app/scripts/build_native.mjs
node plugins/codex-security/mcp-app/scripts/build_mcp_app.mjs --output plugins/codex-security/mcp --native host
```

Config validation and deterministic tests do not need this helper build.

Validate the config:

```bash
pnpm --dir evals/triage-finding run validate
```

Run the full eval:

```bash
pnpm --dir evals/triage-finding run eval
```

Run the first case as a quick smoke test:

```bash
pnpm --dir evals/triage-finding run eval:smoke
```

Run one case while iterating:

```bash
pnpm --dir evals/triage-finding run eval --filter-metadata case_id=sarif-redirects
```

The eval target is `fixtures/repo`, a small synthetic Express app with both true positive and false positive/review cases. Assertions are deterministic:

- `contains-json` validates the fenced `triage-finding/v0` JSON block against `schemas/triage-result-v0.schema.json`.
- `assertions/triage-io.mts` checks input order, `input_id`, `source_type`,
  verdicts, array fields, and `$fix-finding` handoff behavior.
- `tests/invocation-behavior.yaml` opts out of those default JSON assertions for the no-finding case with `options.disableDefaultAsserts: true`.
- `assertions/missing-input.mts` checks that bare invocation asks for a finding,
  names supported input formats, and does not emit triage result JSON.
- `tests/github-rest-intake.yaml` opts out of default JSON assertions for GitHub repository-source routing cases.
- `assertions/github-rest-intake.mts` checks GitHub source selection, REST endpoint selection, Codex project repository inference, advisory/private-report handling, explicit Connector requests and approved REST fallback, and explicit-only GitHub Issue handling.

The explicit Connector case returns a three-field JSON decision for transport,
fallback, and account/repository scope. The code-scanning case returns request
paths and query parameters as JSON. Other intake cases use freeform answers.

## Calibration Dataset

`datasets/triage-calibration-seed.json` is the first OSS-only calibration dataset for scaling beyond the synthetic fixture app. It contains public OSS vulnerable/fixed commit pairs. Each dataset variant becomes one Promptfoo test case in `tests/calibration-oss.yaml`, and each test points Codex at a pinned local checkout under `artifacts/calibration-repos/`. Case IDs, finding IDs, and checkout directories use stable opaque names. Variant labels, fix references, and checkout commit IDs remain in harness metadata rather than the model prompt. Hydration keeps Git metadata in opaque sibling directories outside the model-readable checkout. Re-run `calibration:hydrate` to update older checkout layouts.

ELI5: the dataset says "this exact old commit should be affected" and "this exact fixed commit should not be affected." The generator turns those rows into Promptfoo test prompts. The hydrator downloads the exact repo commits so Codex can inspect real code instead of synthetic snippets.

Validate the dataset structure:

```bash
pnpm --dir evals/triage-finding run test:dataset
```

Run all deterministic calibration checks:

```bash
pnpm --dir evals/triage-finding run test:calibration
```

Regenerate the Promptfoo calibration tests:

```bash
pnpm --dir evals/triage-finding run calibration:generate
```

Hydrate the local OSS checkouts:

```bash
pnpm --dir evals/triage-finding run calibration:hydrate
```

Validate the calibration Promptfoo config:

```bash
pnpm --dir evals/triage-finding run validate:calibration
```

Run one OSS variant as a smoke eval:

```bash
pnpm --dir evals/triage-finding run eval:calibration:smoke
```

Run the full OSS calibration eval:

```bash
pnpm --dir evals/triage-finding run eval:calibration
```

The calibration config is separate from the default synthetic eval:

- `promptfooconfig.yaml` covers the small fixture app and GitHub intake routing.
- `promptfooconfig.calibration.yaml` covers the OSS vulnerable/fixed commit pairs and adds `assertions/calibration-evidence.mts` to check that required paths or fix commits are cited in the response.
- `promptfooconfig.calibration-smoke.yaml` covers a generated one-row smoke file under `artifacts/calibration-smoke.yaml`.

The calibration eval uses the Codex SDK provider, which shells out to `codex exec`. Run it from a normal shell or an unsandboxed command runner so the Codex CLI can write its normal `$CODEX_HOME` state.

Generated local state is ignored:

- `node_modules/` contains the pinned Promptfoo/Codex SDK runner.
- `.promptfoo/` contains Promptfoo's local state.
- `artifacts/` contains hydrated OSS checkouts and eval result exports such as `artifacts/triage-finding-calibration-eval.json`.

## SastBench

The complete SastBench harness, documentation, tests, prompt, assertion, and Promptfoo configuration live under [`sastbench/`](./sastbench/README.md).
