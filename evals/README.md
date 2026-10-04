# Evaluations

Model-based evaluations live here so they can evolve with the plugin without
being embedded in its source tree or shipped npm runtime.

- [Triage finding](triage-finding/README.md): Promptfoo input contracts, OSS
  calibration, and SastBench. This suite owns its private package and lockfile.

- [Completed-report merge](../sdk/typescript/scripts/merge-eval/README.md):
  synthetic grouping quality checks and negative controls.

Model runs are opt-in. CI runs the deterministic triage and secret-discovery
helper checks and the real-IPC reducer regression through the normal MCP test
suite.
