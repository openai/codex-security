# Evaluations

Start with the [deterministic triage checks](triage-finding/README.md#check-the-harness) or the harness tests linked below. These run locally without model calls. Model evaluations are opt-in and consume usage on the account you configure.

- [Triage finding](triage-finding/README.md): Promptfoo input contracts, OSS
  calibration, and SastBench. This suite owns its private package and lockfile.
- [Secret discovery](secret-discovery/README.md): checks whether the production
  core audit finds synthetic credentials in source and keeps them in its final
  findings, with deterministic grading and harness checks.
- [Completed-report merge](../sdk/typescript/scripts/merge-eval/README.md):
  synthetic grouping quality checks and negative controls.
- [Standard time budget](standard-time-budget/README.md): paired comparison of
  production Standard scans with and without an advisory time allowance on
  synthetic vulnerabilities and safe controls, with source-evidence grading.
- [Workflow routing](workflow-routing/README.md): checks whether repository-installed
  production skills route natural-language requests to the appropriate workflow,
  stopping before workflow execution.
- The [skill review fixtures](check-skills/README.md) cover pre-install decisions
  for individual skill files and bundles, including cross-file behavior.

CI runs the deterministic triage, [secret-discovery](secret-discovery/README.md#deterministic-checks), [time-budget](standard-time-budget/README.md#interpretation-and-checks), and [workflow-routing](workflow-routing/README.md#deterministic-checks) checks. The [SDK composition tests](../sdk/typescript/tests-ts/deep-scan-composition.test.ts) cover Deep Scan batches and recovery.

## Build the evaluation tools

For the secret-discovery, Standard time-budget and workflow-routing suites, [install the SDK and MCP dependencies](../sdk/typescript/TESTING.md#install-dependencies), then run these commands from the repository root. The eval type-check includes the triage sources, so it needs the triage package’s dependencies too.

```sh
pnpm --dir evals/triage-finding install --frozen-lockfile
pnpm --dir sdk/typescript run build:evals
```

For Promptfoo triage and SastBench runs, use the [triage setup](triage-finding/README.md#set-up-the-runner), which also builds the native policy helper for your platform.
