# Evaluations

Model-based evaluations live here so they can evolve with the plugin without
being embedded in its source tree or shipped npm runtime.

- [Triage finding](triage-finding/README.md): Promptfoo input contracts, OSS
  calibration, and SastBench. This suite owns its private package and lockfile.
- [Secret discovery](secret-discovery/README.md): checks whether the production
  core audit finds synthetic credentials in source and keeps them in its final
  findings, with deterministic grading and harness checks.
- [Completed-report merge](../sdk/typescript/scripts/merge-eval/README.md):
  synthetic grouping quality checks and negative controls.
- [Workflow routing](workflow-routing/README.md): checks whether repository-installed
  production skills route natural-language requests to the appropriate workflow,
  stopping before workflow execution.

Model runs are opt-in. CI runs the deterministic triage, secret-discovery, and
workflow-routing helper checks. The SDK test suite includes the completed-report
merge oracle and its negative controls.
