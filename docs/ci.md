# How this repository tests pull requests

To scan your own repository in CI, follow the [GitHub Action guide](../github-action/README.md). For contributions to Codex Security, [`node-ci`](../.github/workflows/node-ci.yml) selects jobs from the complete PR diff. Static checks and the final `ci` gate run on every path. The [selection rules](../.github/scripts/select-ci-checks.mjs) define the individual paths and matrices.

## Which checks run

| Changes in the pull request                                                                                                       | Checks selected                                                                                                                                                                                                                             | Exceptions                                                                                                                                                                                      |
| --------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Repository README, contributing guide, `docs/**/*.md`, Action or Docker README, or release guide                                  | Static checks, including Markdown formatting and the release guide’s recovery example.                                                                                                                                                      | The Action README also selects Action CI to verify generated inputs and examples.                                                                                                               |
| Markdown listed in the [SDK package manifest](../sdk/typescript/package.json), optionally with ordinary docs or the release guide | Build with the universal native payload, inspect the archive and install it on Ubuntu with Node 24.                                                                                                                                         | Removing or renaming a required guide still runs archive inspection.                                                                                                                            |
| TypeScript sources or tests in the SDK or MCP app, optionally with ordinary or packaged docs                                      | Full SDK suite on Linux, macOS and Windows. MCP, standalone plugin, native, deterministic eval and container checks also run. Installation covers the minimum supported Node majors and current Node 24 on Linux, plus macOS and Windows.   | Python runs its full suite on Linux 3.12 and native subsets on macOS and Windows. The shared SDK Git remote parser also selects Action CI.                                                      |
| Only top-level `sdk/typescript/tests-ts/*.test.ts` modules                                                                        | All SDK shards, native builds, packaging and an Ubuntu Node 24 installation with the Action adapter.                                                                                                                                        | Skips containers and plugin suites. The Codex dependency pin test additionally selects deterministic evals.                                                                                     |
| Action metadata, wrapper sources, tests, npm manifests, locks or checked-in bundles                                               | Action CI checks a clean rebuild, runs the published CLI integration, and audits wrapper and runtime dependencies. It tests the PR-built package on Ubuntu Node 24 and runs focused SDK Action release tests when the SDK suite is skipped. | Fork PRs run validation and both audits. Same-repository PRs also run a hosted dry run.                                                                                                         |
| Standard time-budget eval modules, configuration or README, or triage eval scripts, assertions, README, manifest or lock          | Build the SDK and host plugin, verify the shared Codex version and run deterministic triage, secret-discovery, time-budget and workflow-routing tests.                                                                                      | Mixing these paths with product code selects full qualification.                                                                                                                                |
| Only edits to existing top-level `plugins/codex-security/tests/test_*.py` modules                                                 | All five Python jobs, workflow checks, MCP, plugin host, native builds, packaging and Unix installation checks.                                                                                                                             | Adding, deleting or renaming modules, or changing helpers, selects full qualification.                                                                                                          |
| Other paths or changes outside these combinations                                                                                 | Full qualification adds workflow checks, containers, current Node 26, Windows Node 24, and the full Linux Python matrix.                                                                                                                    | Includes plugin skills, references, examples, schemas, build tooling and dependency configuration. Mixing the release guide or Action implementation with product source also takes this route. |

SDK shards wait for static checks and a successful package build on opening, reopening or updating a PR. Pushes to `main`, nightly and manual runs, and PR edits requiring full qualification still run the shards after a static-check failure if the package build succeeded. Tests are discovered from the source tree, so a new test runs even before it has recorded timing data.

The two Linux MCP jobs split the same test files as local MCP testing. Each starts the longest files first on its two Node workers. Refresh the slow-file estimates in [the MCP shard runner](../sdk/typescript/scripts/run-mcp-test-shard.mts) when shard durations drift apart.

## Reusing checks after a PR edit

Every push to `main`, nightly run, manual `node-ci` dispatch, and pull-request
retarget runs the complete version matrices. Release automation still requires
successful CI for the exact main commit before publication. Title and body edits
leave source CI running. On an edit, CI checks the source result for the same
pull request, base, head and test merge. It waits for a running source check and
reports a verified result, including static checks, through the required checks.
If the PR event reports an older base, CI can verify the edit on a newer test
merge whose first parent is the current tip of that same branch. A stale merge
or a retarget with different parents needs a fresh PR event after the merge ref
updates. Reopening the PR or pushing a commit starts one.
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
