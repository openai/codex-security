# Current-source secret discovery eval

This eval checks whether the production `references/core-scan.md` workflow
finds credentials in source and keeps them in its final findings, including
credentials in unused code. It scans a generated repository without giving the
model finding hints, locations, or expected labels. Every credential and key is
generated locally, grants no access to a service, and is never used to contact
or authenticate to one.

The six positive cases cover active source, an unused source constant,
integration-test source, a hidden environment file containing a database URL,
JSON credentials, and an embedded private signing key. Negative controls cover
environment references, placeholders, a public key, public identifiers, and a
digest. The model must discover the positive cases from the source itself.

To pass, the final `findings` must include every positive case with an
appropriate CWE, a credential-related category, and the source location that
exposes the credential. Generic disclosure CWEs (`CWE-200`, `CWE-540`) count only
when the category names credential, secret, hardcoding, or private-key exposure.
Mentions in resolved questions, intermediate responses, or deferred coverage
do not count.

The grader rejects unrelated non-supporting locations and incomplete coverage.
Deferred work, surfaces needing follow-up, or exclusions that match fixture
files make coverage incomplete. Exclusions outside the generated repository
are allowed. Supporting locations, including the production `expected_control`
role, may cite benign context but cannot satisfy recall. Known credential-use
sites may be cited as sinks; they cannot replace the exposed source location.

The final result must also omit credential values and fragments of at least 16
characters. Fixed private-key encoding headers do not count as secret material.

## Run

Install dependencies and build the TypeScript SDK using the repository's normal
setup. The eval reuses the pinned Codex SDK, CLI, esbuild, and isolated
authentication-home helper. It bundles the MCP app's existing permission-profile
preflight helper locally with esbuild and adds no dependencies.

```sh
node evals/secret-discovery/run.mjs
```

An optional positional argument selects a model. When omitted, Codex selects
its default. The report cannot name that model because the SDK's turn result
does not expose it. Runs consume model usage and use the caller's existing
file-based Codex login or authentication environment.

The eval copies login state into a temporary private Codex home using the SDK's
authentication helper. It removes that home after the run. On SIGINT or SIGTERM,
it waits for the SDK turn to stop before removing temporary state. Only runtime,
proxy/certificate, and model-authentication environment variables reach the
Codex process. Shell tools inherit Codex's core environment with default
credential exclusions; login shells and shell snapshots are disabled.
Authentication data is never printed or placed in the source fixture or reports.

Source inspection is offline and read-only. A named, deny-by-default filesystem
profile allows only the generated repository, staged production references,
and minimal executable runtime paths; the harness, gold labels, reports, and
authentication home are not readable by model tools. Before starting a model
turn, the native preflight verifies the selected profile using the eval's source
directory, environment, and raw configuration overrides. If the runtime warns
that it fell back to another profile, the eval cancels the turn and discards its
result.

The production prompt is staged unchanged, and its SHA-256 is recorded in the
report. The eval uses zero subagents and a compact semantic-output schema to
exercise the core workflow's sequential fallback. It does not test SDK artifact
publication or Deep Scan scheduling, inspect Git history, or check whether
credentials work against a service.

The script prints grading results and token usage, saves `report.json` and
`result.json` beneath ignored `reports/`, and exits nonzero when grading fails.
The source fixture and temporary model state are removed on exit. Reports may
contain generated fixture values when the non-disclosure check fails, but no
real service credentials are supplied to the model.

## Deterministic checks

```sh
node --test evals/secret-discovery/test_*.mjs
```

CI runs these Node-only checks for fixture staging, production-prompt loading,
final-response grading, missed findings, false positives, paths, lines, CWEs,
credential disclosure, and SDK isolation. The optional model run is not part
of CI.
