# Current-source secret discovery eval

This eval checks whether the production `references/core-scan.md` workflow
finds credentials in source and keeps them in its final findings, including
credentials in unused code. It scans a generated repository without giving the
model finding hints, locations, or expected labels. Every fixture credential and
key is generated locally, grants no access to a service, and is never used to contact
or authenticate to one.

The default run expects eight exposures: active, unused, and integration-test
credentials, a password in a database URL, a JSON client secret, a private
signing key, a provider-format API token in release configuration, and a public
endpoint returning a token supplied at runtime. The external-scanner run adds
a root `SECURITY.md` delegating standalone provider-format API token literals.
The release configuration still contains the token, but reporting it as a
standalone exposure now fails. The other seven cases remain reportable in both
runs. Controls include environment references, placeholders, a public key, a
public ID, a digest, and a provider-shaped value generated only for a parser
test. The values are freshly generated for each run.

To pass, the final `findings` must account for every in-policy exposure with
appropriate taxonomy and a location identifying the exposure. The grader
scores the public response leak separately from hardcoding. Generic disclosure
CWEs (`CWE-200`, `CWE-540`) count for source literals only when the category
names credential, secret, hardcoding, or private-key exposure.
Mentions in resolved questions, intermediate responses, or deferred coverage
do not count.

Every location must cite a fixture file and an in-bounds line range. Each
non-supporting location must match an exposure classified by that finding's
taxonomy. The grader rejects unrelated locations. Scope notes, exclusions,
deferred work, and follow-up questions remain in the saved result but do not
change the grade: final findings must independently satisfy every positive case.
Supporting locations, including the production `expected_control` role, may
cite benign context but cannot satisfy recall. Known credential-use
sites may be cited as sinks; they cannot replace the exposed source location.

Each finding must also include nonempty `codeEvidence`. Every snippet must cite
a fixture file and stay within its line bounds. For each exposure reported in a
finding, at least one snippet must cover the credential declaration or a known
use site. Additional snippets may show benign context. Snippet text must match
the cited source lines, allowing CRLF or LF line endings and a trailing newline.
Credential values remain part of the source evidence.

## Run

Install dependencies and build the TypeScript SDK using the repository's normal
setup, including the MCP app dependencies. `build:evals` type-checks the eval
sources; Node runs them directly with `--experimental-strip-types`. The eval
reuses the pinned Codex SDK, CLI, esbuild, and SDK helper for
creating private homes. It bundles the MCP app's permission-profile preflight
locally with esbuild and adds no dependencies.

```sh
pnpm --dir sdk/typescript run build:evals
node --experimental-strip-types evals/secret-discovery/run.mts
node --experimental-strip-types evals/secret-discovery/run.mts --external-token-scanner
```

An optional positional argument selects a model. When omitted, Codex selects
its default. Each command runs one independent model turn and the report records
the selected reporting policy. The report cannot name that model because the SDK's turn result
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

## Review the remediation

After each model run, read the finding's `remediation`, `validation`, and
severity/confidence rationales in `result.json`. Record the following judgments
alongside the discovery score. The deterministic grader checks locations and
evidence. The reviewer assesses the advice.

- For the committed database password and, in the default run, the provider
  token, does the finding identify who must rotate, revoke, or establish prior
  retirement of the exposed credential? Does it also explain how to remove the
  literal and prevent future commits? A code change alone cannot establish that
  a previously usable credential was retired.
- For the public status response, does the proposed code change stop returning
  the credential? Does the advice cover retiring an exposed value if this path
  was deployed, without claiming that the reviewer used it or proved it live?
- For each exposure, does the report distinguish what the source establishes
  from outstanding questions about live status, audience, and privileges? A
  report that promises complete incident resolution from a source patch fails
  this review even when its discovery score passes.

## Deterministic checks

```sh
pnpm --dir sdk/typescript run build:evals
node --experimental-strip-types --test evals/secret-discovery/test_*.mts
```

CI runs these Node-only checks for fixture staging, production-prompt loading,
final-response grading, missed findings, false positives, paths, lines, CWEs,
source-evidence preservation, and SDK isolation. The optional model run is not
part of CI.
