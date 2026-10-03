# Current-source secret discovery eval

This eval checks whether the production `references/core-scan.md` workflow
finds credentials in source and keeps them in its final findings, including
credentials in unused code. It scans a generated repository without giving the
model finding hints, locations, or expected labels. Every fixture credential and
key is generated locally, grants no access to a service, and is never used to contact
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

Every location must cite a fixture file and an in-bounds line range. Each
non-supporting location must match an exposure classified by that finding's
taxonomy. The grader rejects unrelated locations and incomplete coverage.
Deferred work, surfaces needing follow-up, or exclusions that match fixture
files make coverage incomplete. Exclusions outside the generated repository
are allowed. Supporting locations, including the production `expected_control`
role, may cite benign context but cannot satisfy recall. Known credential-use
sites may be cited as sinks; they cannot replace the exposed source location.

Each finding must also include nonempty `codeEvidence`. Every snippet must cite
a fixture file and stay within its line bounds. For each exposure reported in a
finding, at least one snippet must cover the credential declaration or a known
use site. Additional snippets may show benign context. Snippet text must match
the cited source lines, allowing CRLF or LF line endings and a trailing newline.
Credential values remain part of the source evidence.

## Run

Install dependencies and build the TypeScript SDK using the repository's normal
setup. The eval reuses the pinned Codex SDK, CLI, esbuild, and SDK helper for
creating private homes. It bundles the MCP app's permission-profile preflight
locally with esbuild and adds no dependencies.

```sh
node evals/secret-discovery/run.mjs
```

An optional positional argument selects a model. When omitted, Codex selects
its default. The report cannot name that model because the SDK's turn result
does not expose it. Runs consume model usage and use the caller's existing
file-based Codex login or authentication environment.

The eval creates a temporary private Codex home without importing the caller's
configuration. For a saved file login, it creates the home beside the canonical
auth file and hard-links only `auth.json`, preserving the file's permissions.
The pinned CLI writes token refreshes through that link, so updated credentials
remain available after the eval. Cleanup removes the temporary home and link;
it leaves the saved login in place. If another login replaces the original file
during the run, the eval's existing link does not overwrite that replacement.
Before selecting an `OPENAI_API_KEY` fallback, the native account preflight
checks whether Codex has an account. Saved accounts retain precedence; an empty
or malformed auth file does not suppress the fallback. An explicit
`CODEX_API_KEY` retains its native precedence.

On SIGINT or SIGTERM, the eval waits for the SDK turn to stop before removing
temporary state. Only runtime, proxy/certificate, and model-authentication
environment variables reach the Codex process. Shell tools inherit Codex's core
environment with default credential exclusions. Login shells, shell snapshots,
plugins, and connected apps are disabled. Authentication data is never printed
or placed in the source fixture or reports.

Source inspection is offline and read-only. A named, deny-by-default filesystem
profile allows only the generated repository, staged production references,
and minimal executable runtime paths; the harness, gold labels, reports, and
authentication home are not readable by model tools. Before starting a model
turn, the native preflight verifies the selected profile using the eval's source
directory, environment, and raw configuration overrides. If the runtime warns
that it fell back to another profile, the eval cancels the turn and discards its
result.

On Windows, these read restrictions require Codex's elevated sandbox. Codex
sets it up for the temporary home through its installed service or the standard
Windows administrator approval prompt. Setup must succeed before shell commands
run.

The production prompt is staged unchanged, and its SHA-256 is recorded in the
report. The eval uses zero subagents and a compact semantic-output schema to
exercise the core workflow's sequential fallback. It does not test SDK artifact
publication or Deep Scan scheduling, inspect Git history, or check whether
credentials work against a service.

The script prints grading results and token usage, saves `report.json` and
`result.json` beneath ignored `reports/`, and exits nonzero when grading fails.
The source fixture and temporary model state are removed on exit. Reports may
contain generated fixture values; no real service credentials are supplied to
the model.

## Deterministic checks

```sh
node --test evals/secret-discovery/test_*.mjs
```

CI runs these Node-only checks for fixture staging, production-prompt loading,
final-response grading, missed findings, false positives, paths, lines, CWEs,
source-evidence preservation, and SDK isolation. The optional model run is not
part of CI.
