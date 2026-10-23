# Continuous integration

The `node-ci` workflow selects checks from the complete pull request diff. An
ordinary documentation-only change runs static checks and the final `ci` gate.
Plugin skills, references, schemas, examples, and unrecognized paths still run
source qualification: plugin Markdown is part of the product. SDK README and
documentation changes also run source qualification because those files are
required package contents; deleting or renaming them must pass archive checks.

Source changes run the complete SDK suite on Linux, macOS, and Windows, plus
MCP, standalone-plugin, native-runtime, and installed-package checks. Tests
are discovered from the source tree, including new files without timing data.
Platform-specific filesystem, credential, process, cancellation, and resumed
worker cases remain enabled.

Ordinary pull requests test the minimum supported Node 22, 24, and 26 versions,
current Node 24 for the Action adapter, macOS installation, and Windows Node 22
installation. Node dependencies, build tooling, native code, and CI changes also
select current Node 26 and Windows Node 24 installation checks. Python runs the
full suite on 3.12 and the native subsets on macOS and Windows; Python source,
dependencies, schema, or CI changes also select the 3.10 and 3.14 Linux suites.

Every push to `main`, nightly run, manual `node-ci` dispatch, and pull-request
retarget runs the complete version matrices. Release automation still requires
successful CI for the exact main commit before publication. Title and body edits
neither cancel source runs nor satisfy their required check names.

## Required gate

The `ci` job checks every selected required job. A failed, cancelled, missing,
or unexpectedly skipped selected job fails the gate. An explicitly unselected
job can be skipped. Static checks are always required. Broad test-runner
experiments run through the separate scheduled/manual `test-quality` workflow;
they are not merge gates.

The existing OS-named check contexts temporarily forward the `ci` result so
repository branch rules continue to work during migration. To finish migration:

1. Merge the workflow change and verify that `ci` is reported for source and
   documentation pull requests, including a failing selected-check example.
2. Change the repository's required status checks to `ci` and `Validate PR Title`,
   preserving their GitHub Actions integration and all unrelated protection rules.
3. Remove the compatibility jobs `required-test` and `windows` in a follow-up.

Do not remove the old contexts before changing the rules. The workflow change
itself does not change repository protection settings.

## Diagnostics and local checks

The workflow-selection and gate tests run without installing dependencies:

```bash
node --test .github/scripts/test-ci-selection.mjs
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
