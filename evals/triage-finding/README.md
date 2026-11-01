# triage-finding eval

This Promptfoo suite verifies that `$codex-security:triage-finding` accepts the current supported input source types and returns the expected `triage-finding/v0`
JSON result shape. It also covers bare skill invocation with no supplied finding,
which should prompt the user for a finding in a supported format instead of returning triage JSON. GitHub intake cases cover repository-source selection, REST endpoints, and explicit Connector requests without querying live GitHub during the eval.

The suite uses the Promptfoo Codex SDK provider because it only needs final assistant output and deterministic assertions. The common runner stages the checkout's triage skill and policy helper in a throwaway directory, with ambient plugins and memory disabled. The default suite can also read the synthetic fixtures; calibration cases can read their own hydrated checkout. Dataset labels, assertions, and calibration Git history stay outside those readable roots. The eval directory owns a small pinned pnpm environment so new cases can be added and run without a separate scratch setup.

Use Node.js 22.22.0 or newer and install the [native build prerequisites](../../plugins/codex-security/native/README.md). From the repository root, install the SDK dependencies and set up the eval. Setup installs the eval and MCP app dependencies, type-checks the eval sources, and builds the host policy helper.

```bash
pnpm --dir sdk/typescript install --frozen-lockfile
pnpm --dir evals/triage-finding run setup
```

To reproduce the deterministic triage checks that CI runs, execute this command from the repository root. It covers intake assertions, calibration, SastBench, and the Promptfoo provider using fixtures without making model calls.

```bash
(cd evals/triage-finding && node --run test:deterministic)
```

After editing the tooling, rerun `pnpm --dir sdk/typescript run build:evals` to prepare the SDK and type-check the eval sources. Node and Promptfoo execute the TypeScript sources directly.

The common runner builds the staged helper for validation, evaluation, and replay, then removes its temporary runtime after Promptfoo exits. Separate YAML files under `providers/` retain the native Codex provider IDs and each suite's settings. The suite's `$ref` entries expand these settings into saved evaluation snapshots, so later edits to the provider files do not change an existing run's retry, resume, or replay settings. The runner uses Node's `--import` to preload the runtime adapter into the Promptfoo child process, so it can bind the staged runtime during evaluation, retry, resume, and viewer replay without a Promptfoo patch. Native provider loading preserves authentication precedence.

The adapter depends on bundled Codex classes and internal methods in the pinned Promptfoo provider. The provider tests cover those methods, executable selection, authentication, and per-case settings. Replay does not restore grading metadata, so grading hooks remain disabled.

Saved runs whose provider ID is `file://.../triage-provider.mts` need to be rerun with the current configuration before retry, resume, or replay. Their saved results remain intact. Native Codex provider IDs are unchanged.

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
  verdicts, array fields, and `$fix-finding` handoff behavior. Its shared triage parser accepts complete JSON or multiline JSON code fences, including indented and CRLF fences. Inline fences and JSON embedded in prose are not accepted.
- `tests/invocation-behavior.yaml` opts out of those default JSON assertions for the no-finding case with `options.disableDefaultAsserts: true`.
- `assertions/missing-input.mts` checks that bare invocation asks for a finding,
  names supported input formats, and does not emit triage result JSON.
- `tests/github-rest-intake.yaml` opts out of default JSON assertions for GitHub repository-source routing cases.
- `assertions/github-rest-intake.mts` checks GitHub source selection, REST endpoint selection, Codex project repository inference, advisory/private-report handling, explicit Connector requests and approved REST fallback, and explicit-only GitHub Issue handling.

The explicit Connector case returns a three-field JSON decision for transport,
fallback, and account/repository scope. The code-scanning case returns request
paths and query parameters as JSON. A separate default-transport case checks
that intake selects REST without an explicit Connector request. Other intake
cases use freeform answers.

## Calibration Dataset

`datasets/triage-calibration-seed.json` is the first OSS-only calibration dataset for scaling beyond the synthetic fixture app. It contains public OSS vulnerable/fixed commit pairs. Promptfoo calls `scripts/generate-calibration-tests.mts:generateTests` to load each dataset variant as a test case, and each test points Codex at a pinned local checkout under `artifacts/calibration-repos/`. Case IDs, finding IDs, and checkout directories use stable opaque names. Variant labels, fix references, and checkout commit IDs remain in harness metadata rather than the model prompt. Hydration keeps Git metadata in opaque sibling directories outside the model-readable checkout. Re-run `calibration:hydrate` to update older checkout layouts.

ELI5: the dataset says "this exact old commit should be affected" and "this exact fixed commit should not be affected." The generator turns those rows into Promptfoo test prompts. The hydrator downloads the exact repo commits so Codex can inspect real code instead of synthetic snippets.

Validate the dataset structure:

```bash
pnpm --dir evals/triage-finding run test:dataset
```

Run all deterministic calibration checks:

```bash
pnpm --dir evals/triage-finding run test:calibration
```

Validation and evaluation load calibration tests directly from the dataset. To export a YAML copy for inspection:

```bash
pnpm --dir evals/triage-finding run calibration:generate --output artifacts/calibration-oss.yaml
```

The optional exporter retains `--dataset`, `--output`, `--repo-root`, `--case`, and `--variant`. Its default output remains `tests/calibration-oss.yaml`; generated YAML is not needed to run the suite.

The exporter and hydrator accept UTF-8 JSON datasets with or without a leading byte-order mark.

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
- `promptfooconfig.calibration-smoke.yaml` passes case and variant filters to the native generator to load one smoke case.

The calibration eval uses the Codex SDK provider, which shells out to `codex exec`. Run it from a normal shell or an unsandboxed command runner so the Codex CLI can write its normal `$CODEX_HOME` state.

Generated local state is ignored:

- `node_modules/` contains the pinned Promptfoo/Codex SDK runner.
- `.promptfoo/` contains Promptfoo's local state.
- `artifacts/` contains hydrated OSS checkouts and eval result exports such as `artifacts/triage-finding-calibration-eval.json`.

## SastBench

The complete SastBench harness, documentation, tests, prompt, assertion, and Promptfoo configuration live under [`sastbench/`](./sastbench/README.md).
