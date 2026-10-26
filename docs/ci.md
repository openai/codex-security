# Continuous integration

The `node-ci` workflow selects checks from the complete pull request diff. An
ordinary documentation-only change runs static checks and the final `ci` gate.
Static checks format the tracked Markdown in this route. The Action README also
runs Action CI to check generated input documentation and usage examples.
Plugin skills, references, schemas, examples, and unrecognized paths receive
full qualification because plugin Markdown is part of the product.

PRs limited to the SDK package manifest's Markdown files, optionally mixed with
ordinary docs or `RELEASING.md`, require the native payload, the real package
build and archive inspection, and one Ubuntu Node 24 installation. Removing or
renaming a required guide must still pass archive inspection. The static job
validates the canonical recovery example in `RELEASING.md` on docs-only PRs too.
Mixing either kind of guide with product source selects full qualification.

Product source changes run the complete SDK suite on Linux, macOS, and Windows,
plus MCP, standalone-plugin, native-runtime, and installed-package checks. Tests
are discovered from the source tree, including new files without timing data.
Platform-specific filesystem, credential, process, cancellation, and resumed
worker cases remain enabled.

SDK shards wait for static checks and a successful package build. A failing
static check skips the shards when a PR opens, reopens, or receives new commits.
Pushes to `main`, nightly and manual runs, and PR edits that need full
qualification still run the shards.

The two Linux MCP jobs discover the same test files as local MCP testing. CI
assigns files by observed runtimes and starts the longest files first on each
job's two Node workers. Refresh the
slow-file estimates in `run-mcp-test-shard.mts` when the jobs drift apart.

Pull requests limited to `.ts` files under `sdk/typescript/src/`,
`sdk/typescript/tests-ts/`, `plugins/codex-security/mcp-app/src/`, and
`plugins/codex-security/mcp-app/tests/`, optionally mixed with ordinary docs,
use reduced version matrices. They test the minimum Node 22, 24, and 26 versions,
current Node 24 for the Action adapter, macOS installation, and Windows Node 22
installation. When selected, Python runs the full suite on 3.12 and the native
subsets on macOS and Windows. All source changes still select container
validation.

PRs limited to top-level `sdk/typescript/tests-ts/*.test.ts` keep all SDK
shards, static checks, native builds, packages, and containers. They skip the
plugin suites and run evals only when their `codex-dependency-pins.test.ts`
input changes. Mixed changes follow the usual source or full route.

PRs limited to Action metadata, wrapper implementation, tests, npm manifests,
locks, or checked-in bundles run Action CI. It verifies a clean rebuild, runs
the published CLI integration, audits the wrapper and pinned runtime, and
exercises the local Action on eligible events. Fork PRs run validation and
both audits. Same-repository PRs also run the hosted dry-run smoke. Changes to
these Action files keep the Linux Node 24 integration against the package built
from the PR. The focused SDK Action release contracts run when the rest of the
SDK suite is skipped. Changes to the shared SDK Git remote parser also select
Action CI.

PRs limited to Standard time-budget eval modules, experiment configuration or
README, or to the triage eval's scripts, assertions, README, manifest or lock,
run the deterministic eval job and static checks. The eval job builds the SDK
and host plugin, checks the Codex version across the SDK, MCP and triage
lockfiles, and runs the triage, secret-discovery, Standard time-budget and
workflow-routing suites.

Edits limited to existing top-level `plugins/codex-security/tests/test_*.py`
modules keep all five Python jobs, MCP, host, native, package, compatibility,
and container checks. They skip the SDK shards, Windows install checks, Action
and eval jobs. Adding, removing, or renaming modules, editing shared helpers,
or including any other path selects full qualification.

Inputs outside these routes select full qualification, including workflow checks,
containers, current Node 26, Windows Node 24 installation, and Python 3.10 and
3.14 Linux suites. This includes dependency configuration such as `.npmrc` and
`pnpm-workspace.yaml`, build tooling, Python and native code, and unknown paths
even when mixed with ordinary source or documentation. Mixing Action
implementation or eval changes with product code also selects full qualification.

Every push to `main`, nightly run, manual `node-ci` dispatch, and pull-request
retarget runs the complete version matrices. Release automation still requires
successful CI for the exact main commit before publication. Title and body edits
leave source CI running. On an edit, CI checks the source result for the same
pull request, base, head and test merge. It waits for a running source check and
reports a verified result, including static checks, through the required checks.
Only the original source run and an uninterrupted sequence of successful edits
can carry a green result. A cancelled or retried run, a changed target, missing
evidence or conflicting results require full qualification. Use **Re-run all
jobs** to retry an edit. A partial retry cannot refresh a previous attempt's
required checks.

## Required gate

The `ci` job checks every selected required job. A failed, cancelled, missing,
or unexpectedly skipped selected job fails the gate. An explicitly unselected
job can be skipped. Static checks are always required. The separate `test-quality`
workflow runs weekly property and mutation tests. Dispatch it to compare full SDK
shard layouts.

The required GitHub Actions checks on `main` are `ci` and `Validate PR Title`.
The title check runs on pull request edits. To diagnose a failed `ci`, open
the selected job named in the gate output.

## Diagnostics and local checks

The workflow-selection and gate tests run without installing dependencies:

```bash
node --test .github/scripts/test-ci-selection.mjs .github/scripts/test-verify-pr-source.mjs .github/scripts/test-release-guide.mjs
```

The [SDK testing guide](../sdk/typescript/TESTING.md) describes local behavioral
tests. For CI edits, also run actionlint and the repository's configured zizmor
checks. Test-runner changes should compare the same test inventory, outcomes,
and covered lines with the same Bun version, seed, and coverage settings before
promotion. A different runtime or disabled coverage is a different experiment.

Linux coverage artifacts are review evidence, not a percentage-based merge
gate. Mutation diagnostics also measure results without enforcing a minimum
score. Ordinary report upload failures do not replace the test result.

Only the same pull request can reuse caches saved on `refs/pull/<number>/merge`.
After the PR merges into `main`, a maintenance job deletes those caches.

When measuring CI changes, separate time to required-green from summed job
execution time, prerequisite waits, runner scheduling, approval waits, and
manual retry delays. Compare matching revisions and test configurations, and
record failures as well as successful runs.

Protected `main` pushes that miss the same native cache share a queue per block
of 16 consecutive workflow numbers. Each run waits behind at most 15 others,
then restores the verified payload or builds and proves all eight platforms.
Hits, unavailable listings, different inputs, and PR checks can start independently.

When a batch can wait, look for the first protected cache save before landing
more changes with the same inputs: `gh cache list --ref refs/heads/main --key KEY`.
The key uses the UTC week selected for the run and the paths in
[the native key action](../.github/actions/native-cache-key/key.sh). Repository
scripts are included by default: a native proof can load a helper at runtime.
The workflow excludes known CI entrypoints that run elsewhere. Compare the
next change against current `main`: its PR run may have tested an older base
or skipped native preparation. PRs cannot populate this
cache for `main`.
