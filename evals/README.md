# Evaluations

Model-based evaluations live here so they can evolve with the plugin without
being embedded in its source tree or shipped npm runtime.

- [Triage finding](triage-finding/README.md): Promptfoo input contracts, OSS
  calibration, and SastBench. This suite owns its private package and lockfile.
- [Deep reducer](deep-reducer/README.md): optional model evaluation of real IPC
  size-limit recovery, pagination, and finding retention. It reuses the MCP
  test helpers and dependencies.

Model runs are opt-in. CI still runs the deterministic triage helper checks and
the real-IPC reducer regression through the normal MCP test suite.
