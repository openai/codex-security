# Testing the SDK and CLI

Use the pnpm version in `package.json` and Bun 1.3.14, matching required CI.
Run these commands from `sdk/typescript`:

```sh
pnpm install --frozen-lockfile
npm ci --prefix ../../plugins/codex-security/mcp-app --no-audit --no-fund
pnpm run check:plugin-source
bun test --timeout 30000 ./tests-ts/worker-progress.test.ts
pnpm run types
pnpm run test:mcp
pnpm run format
pnpm run test
pnpm run test:ci
pnpm pack --pack-destination ../../dist
pnpm run test:package
```

The authored plugin lives in `plugins/codex-security`. `pnpm pack` generates
the ignored `_bundled_plugin` runtime payload from `plugins/codex-security/plugin-files.json` during
`prepack`, including the MCP runtime built from `mcp-app`; do not edit generated
files there. Run `pnpm run build:plugin` when you need to inspect the staged
payload locally. `plugins/codex-security` contains authored source and assets,
not the generated `mcp/server.mjs` or compressed runtime chunks.
`pnpm run check:plugin-source` fails if any file beneath `_bundled_plugin` is
tracked by Git. Required CI runs the same check before installing dependencies.

For CI's full archive inspection, pass the exact `.tgz` path printed by
`pnpm pack` to `pnpm run check:package`.

Tests run in random order by default. To replay a failure, pass the seed from
Bun's summary to `pnpm run test --seed 12345`.

The local test commands pass a 30-second per-test timeout explicitly. Windows
CI and the Windows runner experiment allow 120 seconds for slower native
credential and document checks. `test:ci` runs four independent Bun processes
and writes `reports/junit-*.xml` and `coverage/shard-*/lcov.info`. These are
per-shard reports, not four measurements of the full suite. Coverage measures loaded
JavaScript and TypeScript, not the Python helpers or child processes. It is
diagnostic for now. Use several successful CI runs to establish a baseline
before proposing a coverage floor.

The scan-history Python fixtures use direct interpreter lookup and a 30-second
child deadline, raised from 10 seconds after repeated hosted Windows timeouts.
They still run real Python processes and fail if Python is unavailable.
Production interpreter discovery and its deadlines are unchanged.

## Writing tests

- Test observable results, failures, cancellation, and cleanup. Prefer a
  regression case that fails before a fix over assertions about private calls
  or exact prose.
- Keep fixtures synthetic and independent. Use real temporary directories,
  Git repositories, SQLite databases, and installed packages when those
  boundaries are the behavior under test. Do not use live model credentials.
- Use the typed `TestClient` and `createApiTestFixtures` helpers for API tests.
  Do not add a production abstraction solely to support a mock.
- Restore spies, timers, and environment changes. Tests that change the process
  cwd or install persistent ESM module mocks use `runTestInSubprocess`.
  Per-file Bun isolation does not isolate process-wide state inside one file.
- Keep shared behavior enabled on Linux, macOS, and Windows. The constrained
  PowerShell test changes machine-wide policy and runs alone, only on an
  explicitly enabled GitHub-hosted Windows runner.
- Add property tests for meaningful invariants, with accepted and rejected
  inputs. Keep example-based regression tests for readable failure cases.
- Give parameterized cases distinct names. Use `%p`, `%j`, or `%#` for values
  that are not strings. The JUnit comparison rejects duplicate identities.

Property tests use a fixed default seed. Fast-check prints the seed, shrink
path, and counterexample on failure. To replay one property, select its file
and test name, then set `CODEX_SECURITY_PROPERTY_SEED` and
`CODEX_SECURITY_PROPERTY_PATH` to the reported values. Set
`CODEX_SECURITY_PROPERTY_RUNS` to increase the case count. Pure properties
default to 100 cases; filesystem contract properties default to 20.

## GitHub Actions

`node-ci` retains the required `ubuntu-latest / node-22`,
`macos-latest / node-22`, and `windows-latest / node-22` checks. Its Ubuntu
Node 22 job runs static checks and uploads JUnit and LCOV. Every existing OS and
Node runtime lane still runs the full suite in full CI: tests also launch Node subprocesses,
so changing Node can affect more than the Bun test runtime. All supported runtime
lanes still inspect an installed package. Package inspection includes
a strict NodeNext TypeScript consumer and the actual installed CLI. Failed
tests block CI; a failed diagnostic upload does not. Unix package verification
runs in six separate jobs alongside the six test lanes, with the same OS and
Node versions. Required checks depend on both matrices. Together with the
plugin-source contract job, this raises full CI from 28 to 34 jobs and
duplicates checkout and dependency setup, trading more runner resources for
less sequential work; it does not duplicate the test suite.

Pull-request validation classifies changes before starting test and package
jobs. Markdown-only diffs run changed-file formatting instead; pushes, base
retargets, empty diffs, and changes to other file types run full CI. Required
check names remain stable and reject failed validation or an unknown CI mode.
Every pull-request edit is reclassified and shares the same cancellation group,
so editing the body of a code pull request can restart its full CI run.

`scripts/run-ci-tests.mjs` discovers the test files and balances them using
rounded timings in `scripts/test-shards.mjs`. Unix estimates average measured
Linux and macOS file timings. Unix jobs run four processes;
Windows runs seven separate jobs with `node scripts/run-ci-tests.mjs 1/7`
(substitute the shard number), each using up to two Bun processes with separate
reports such as `junit-1-1.xml` and `junit-1-2.xml`. Each file runs once. New files
are included automatically; stale timing estimates can affect balance, but not coverage.
Credential-home locking and ACL checks live in `runtime-credentials.test.ts` so
they can run independently of the plugin, output-directory, and Python checks
in `runtime.test.ts`.
The machine-wide Windows policy test still runs separately and serially.
Windows caches the exact pnpm version from `packageManager` in a dedicated
runner-temp prefix. A cache miss or cache error installs it with npm; only an
exact hit skips installation. The resolved pnpm store is cached separately.
In full CI, Unix jobs and Windows package-verification jobs restore the npm
download cache; Windows test jobs do not. Cache failures do not suppress
installation failures. Unix keeps its pinned pnpm
setup action. Windows package inspection enables npm's native phase timings to
diagnose installation delays without changing its failure or timeout behavior.
It also logs npm cache/fetch activity and uses a 16-thread libuv pool for
filesystem-heavy package extraction. The fresh Windows npm consumer uses
GitHub's `RUNNER_TEMP` when available, otherwise the normal temporary directory.
Its `TEMP` and `TMP` use the same private Windows root as the tests; the
installed credential fixture gets a separate temporary state directory there
so its ancestor ACL checks remain enabled. Both temporary directories are
removed after use.
These settings apply only to Windows package inspection; the install arguments,
assertions, and timeouts are unchanged.

When forwarding `--test-name-pattern` to a sharded run, also pass Bun's
`--pass-with-no-tests` if some workers may have no matching tests. Normal CI
does not enable that option, and empty file partitions are never launched.

To compare the serial and CI runners on the same machine, commit, and seed:

```sh
mkdir -p reports
pnpm run test --seed 12345 --reporter=junit --reporter-outfile=reports/baseline.xml
node scripts/run-ci-tests.mjs --seed 12345
python3 scripts/compare-test-reports.py reports/baseline.xml 'reports/junit-*.xml'
```

Use a clean reports directory and compare wall time as well as the test
identities and outcomes. Run both commands with the same coverage options
when measuring coverage overhead. The Windows serial baseline includes a
skipped machine-policy case that the shard runner excludes; compare that
case separately. Update the timing estimates only when reports show a
meaningful imbalance, not on every timing fluctuation.

The separate `test-quality` workflow runs weekly, can be dispatched manually,
and runs on pull requests that change its workflow file. It compares Bun's
default runner, `--isolate`, `--parallel=2`, and seven-way Windows sharding.
Every mode uses the same seed for property cases and test ordering: pull
requests replay seed 1; scheduled and manual runs use the workflow run number.
The workflow compares test identities and outcomes against the unsharded
default run and records timings, including failed shards, in the job summary.
It is not a required check or part of the release trigger.

Runner trials use Bun 1.3.13 to avoid the
[async-module initialization bug in 1.3.14](https://github.com/oven-sh/bun/issues/31410)
that breaks the Ink UI tests under isolation. Keep the trial pin until a newer
release passes the full SDK suite in every mode. Required CI and the mutation
trial remain on Bun 1.3.14.

Keep the file-balanced CI runner until the native runner has
matching inventories and acceptable Windows timings. Before promotion, compare
native and file-balanced shards using the same commit and Bun version.
Keep the machine-policy test serial. Do not replace the full required suite
with `--changed`: Python files, schemas, fixtures, and workflows loaded at
runtime are not necessarily part of Bun's import graph.

## Mutation testing

```sh
pnpm run test:mutation
pnpm exec stryker run --mutate src/worker-progress.ts
```

The initial Stryker trial covers progress parsing, safe error messages, and
pure cost arithmetic. It uses the fixed default property-test seed and writes
HTML and JSON under `reports/mutation`. Review surviving mutants for missing
behavior assertions or equivalent changes. There is no score gate yet; set
one only after the trial has a stable, useful baseline. Do not hide surviving
mutants with assertions about implementation details.
