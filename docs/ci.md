# Continuous integration

The `node-ci` workflow selects checks from the complete pull request diff. An
ordinary documentation-only change runs static checks and the final `ci` gate.
Static checks format the tracked Markdown in this route. The Action README also
runs Action CI to check generated input documentation and usage examples.
Plugin skills, references, schemas, examples, and unrecognized paths receive
full qualification because plugin Markdown is part of the product. SDK README and
documentation changes also receive full qualification because those files are
required package contents. Deleting or renaming them must pass archive checks.
`RELEASING.md` also receives full qualification because SDK tests validate its
canonical release recovery example.

Source changes run the complete SDK suite on Linux, macOS, and Windows, plus
MCP, standalone-plugin, native-runtime, and installed-package checks. Tests
are discovered from the source tree, including new files without timing data.
Platform-specific filesystem, credential, process, cancellation, and resumed
worker cases remain enabled.

Pull requests limited to `.ts` files under `sdk/typescript/src/`,
`sdk/typescript/tests-ts/`, `plugins/codex-security/mcp-app/src/`, and
`plugins/codex-security/mcp-app/tests/`, optionally mixed with ordinary docs,
use reduced version matrices. They test the minimum Node 22, 24, and 26 versions,
current Node 24 for the Action adapter, macOS installation, and Windows Node 22
installation. Python runs the full suite on 3.12 and the native subsets on macOS
and Windows. All source changes still select container validation.

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
workflow-routing suites. This job also runs on source changes, independently
of the Python matrix.

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

One compatibility matrix forwards the `ci` result to the three OS-named Node 22
checks required by the current `main` ruleset. Migrate the required checks in
this order.

1. Merge the workflow change and verify that `ci` is reported for source and
   documentation pull requests, including a failing selected-check example.
2. Change the repository's required status checks to `ci` and `Validate PR Title`,
   preserving their GitHub Actions integration and all unrelated protection rules.
3. Remove the compatibility matrix `required-test` and its three OS check
   names from source verification in a follow-up.

Do not remove the old contexts before changing the rules. The workflow change
itself does not change repository protection settings.

## Diagnostics and local checks

The workflow-selection and gate tests run without installing dependencies:

```bash
node --test .github/scripts/test-ci-selection.mjs .github/scripts/test-verify-pr-source.mjs
```

The [SDK testing guide](../sdk/typescript/TESTING.md) describes local behavioral
tests. For CI edits, also run actionlint and the repository's configured zizmor
checks. Test-runner changes should compare the same test inventory, outcomes,
and covered lines with the same Bun version, seed, and coverage settings before
promotion. A different runtime or disabled coverage is a different experiment.

Linux coverage artifacts are review evidence, not a percentage-based merge
gate. Mutation diagnostics also measure results without enforcing a minimum
score. Ordinary report upload failures do not replace the test result.

When measuring CI changes, separate time to required-green from summed job
execution time, prerequisite waits, runner scheduling, approval waits, and
manual retry delays. Compare matching revisions and test configurations, and
record failures as well as successful runs.

When a batch of merges can wait, check **Restore verified native payload** in
an active `node-ci` push or scheduled run on `main`. On a miss, another push
with the same inputs can start all eight platform builds again. Before merging
a PR that leaves those inputs unchanged, look for the exact key in
`gh cache list --ref refs/heads/main --key KEY`. Once it is there, it does not
matter which `main` run saved it. Different inputs can build in parallel.

The key uses the UTC week and the paths listed in **Identify native build and
proof inputs**. Compare the next change against current `main`: its PR run may
have tested an older base or skipped native preparation entirely. PR runs
cannot populate this cache for `main`.
