# Testing the SDK and CLI

Use the pnpm version in `package.json` and Bun 1.3.14, matching required CI.
Install both the SDK and MCP app dependencies before building or testing.
Prepare the [universal native payload](../../plugins/codex-security/native/README.md#package-inputs)
before running a command that builds the bundled plugin.
Run these commands from `sdk/typescript`:

```sh
pnpm install --frozen-lockfile
pnpm --dir ../../plugins/codex-security/mcp-app install --frozen-lockfile
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
These checks include native Node contracts for SDK completion, cancellation,
close cleanup, and CLI terminal sanitization. They use the installed package,
controlled model output, and the real workbench without live model credentials.
The installed-package checks also verify hosted SDK exports, input validation,
and the `scan --host` protocol without preparing a repository or requiring Git.
The hosted-scan tests cover real repository scans, scope, artifact seals, and
executor receipts. To rerun just the installed-package check, use
`node scripts/smoke-hosted-package.mjs /absolute/path/to/node_modules/@openai/codex-security`.

Tests run in random order by default. To replay a failure, pass the seed from
Bun's summary to `pnpm run test --seed 12345`.

The local test commands pass a 30-second per-test timeout explicitly. Windows
CI and the Windows runner diagnostics allow 120 seconds for slower native
credential and document checks. `test:ci` writes `reports/junit.xml` and
`coverage/lcov.info`. Coverage measures loaded
JavaScript and TypeScript, not the Python helpers or child processes. It is
diagnostic for now. Use several successful CI runs to establish a baseline
before proposing a coverage floor.

## Native artifacts in fresh development environments

SDK tests, including Ona's **Run tests** automation, require the eight verified
native payloads. Installing Node and Python dependencies alone does not supply
them. Select a successful native-artifacts or node-ci run built from this
checkout's native sources and toolchain, then use the exact artifact name from
that run (pull request artifacts use the tested merge commit):

```sh
gh run download <run-id> --name native-universal-<commit> --dir plugins/codex-security/native/prebuilt
```

Run this command from the repository root before starting the automation.
Refresh the artifact after changing native source or toolchain. The standalone
plugin supports a host-only build; that does not satisfy the SDK's universal
packaging tests. See the [native build guide](../../plugins/codex-security/native/README.md).

## Python test dependencies

Use Python 3.10 or later. From the repository root, install the Python test and lint dependencies with:

```sh
python -m pip install --disable-pip-version-check --no-input -r plugins/codex-security/requirements-test.txt
```

This replaces `pip install -e 'plugins/codex-security[test]'`. Tests load the plugin scripts from source; the repository does not need an installed Python distribution.
The requirements file is the single list of pinned Python test dependencies. Ruff and pytest settings remain in `plugins/codex-security/pyproject.toml`; the Ruff dependency and its `required-version` setting must agree.

## Writing tests

- Test observable results, failures, cancellation, and cleanup. Prefer a
  regression case that fails before a fix over assertions about private calls
  or exact prose.
- Pair a fault case with a healthy control when that shows the failure's cause.
  For ordering bugs, coordinate the relevant events explicitly rather than
  relying on sleeps: for example, persist a checkpoint before cancellation or
  fail an operation before its cleanup runs.
- Keep fixtures synthetic and independent. Use real temporary directories,
  Git repositories, SQLite databases, and installed packages when those
  boundaries are the behavior under test. Do not use live model credentials.
- Follow the changed behavior through its consumer. Parser checks alone do not
  prove public API output, persisted state, child-process settings, or installed
  package behavior. Use the relevant boundary without repeating every test at
  every layer. See the [source map](../../CONTRIBUTING.md#where-to-make-a-change).
- When a result can be partial, assert what was retained and what remains
  unknown. Distinguish empty results from unavailable results, and checkpointed
  worker output from accepted results and published scan artifacts.
- Use the typed `TestClient` and `createApiTestFixtures` helpers for API tests.
  Do not add a production abstraction solely to support a mock.
- Test workflow retry, resume, and checkpoint permutations with the existing
  injected workbench dependency. `scriptedWorkbench` rejects unexpected
  requests; `checkpointWorkbench` stores review results without reproducing the
  Python workflow engine. Keep real workbench calls in the focused workflow
  integration file for process termination, migration, and source snapshots.
- Test Python database behavior by calling the production functions in pytest.
  The `workbench_db` fixture copies a migrated, empty schema into a fresh
  in-memory SQLite database for each test, with foreign keys enabled. Use
  file-backed databases for migrations, reopening, locking, and crash recovery;
  an in-memory database cannot exercise those boundaries.
- Restore spies, timers, and environment changes. Tests that change the process
  cwd or install persistent ESM module mocks use `runTestInSubprocess`.
  Per-file Bun isolation does not isolate process-wide state inside one file.
- Keep shared behavior enabled on Linux, macOS, and Windows. The constrained
  PowerShell test changes machine-wide policy and runs alone, only on an
  explicitly enabled GitHub-hosted Windows runner.
- Add property tests for meaningful invariants, with accepted and rejected
  inputs. Keep example-based regression tests for readable failure cases.
- Give parameterized cases distinct names. Use `%p`, `%j`, or `%#` for values
  that are not strings. Duplicate identities remain valid; the JUnit comparison
  checks their occurrence and outcome counts.

Property tests use a fixed default seed. Fast-check prints the seed, shrink
path, and counterexample on failure. To replay one property, select its file
and test name, then set `CODEX_SECURITY_PROPERTY_SEED` and
`CODEX_SECURITY_PROPERTY_PATH` to the reported values. Set
`CODEX_SECURITY_PROPERTY_RUNS` to increase the case count. Pure properties
default to 100 cases; filesystem contract properties default to 20.

## GitHub Actions

`node-ci` reports one `ci` gate for all selected required checks. The existing
`ubuntu-latest / node-22`, `macos-latest / node-22`, and
`windows-latest / node-22` check names forward that result while repository
branch rules migrate. The [CI guide](../../docs/ci.md) describes documentation-only
routing, platform/version selection, full scheduled qualification, and the gate
migration.

For source qualification, CI builds and inspects one package archive, then passes
that archive to jobs in the same workflow run, using the commit SHA in the
artifact name. Selected Node runtimes install and inspect the package, including
a strict NodeNext TypeScript consumer, the actual CLI, credential locking, and a
nested Codex worker. Native plugin-build tests remain in the shared Bun suite.
Typechecking and formatting run once in an independent required job, so package
consumers do not wait for those checks. Package compilation and archive
validation still finish before the test jobs start.

Source qualification runs the full Bun suite once per OS under Node 22: six
file shards on Linux and macOS, and fourteen on Windows. GitHub runs the shards
as separate jobs; each job uses Bun's default serial runner. The other selected
Node versions run the installed-package checks instead of repeating the same
Bun suite. MCP tests run in two required jobs using Node's native file sharding,
with two isolated test file processes per job. Local and release `test:mcp`
commands still run the full suite. Python tests run separately and use four
isolated pytest-xdist workers with work stealing; worker crashes fail the run
without automatic restarts.

`scripts/run-ci-tests.mts` discovers every shared test file and balances whole
files using the platform's recorded durations in `scripts/test-timings.json`.
It assigns longer files first to the shard with the least estimated work, then
passes each shard's files directly to Bun. Every job uses the same checked-in
snapshot. New files are included automatically with the mean known-file duration;
deleted files in the timing snapshot are ignored. Timing hints never select or
exclude tests, and adding or splitting tests does not require updating them.
To reproduce one Windows shard locally after building the plugin, run
`node --experimental-strip-types scripts/run-ci-tests.mts 3/14 --seed=12345`.

Refresh timing hints from successful CI JUnit artifacts when shard runtimes
become uneven. From the SDK directory, pass reports for one platform to
`node --experimental-strip-types scripts/update-test-timings.mts win32 <junit.xml> ...`
(use `linux` or `darwin` for the other platforms). The updater sums testcase
durations per file and uses their median across reports, preserving the other
platforms. Review and commit the generated snapshot. The initial hints use runs
`39521539826`, `39694506447`, and `39694510011`. Keep runner versions, coverage,
timeouts, seeds, and platform-specific checks unchanged when comparing scheduling
changes; compare complete JUnit inventories and outcomes as well as wall time.

Every Bun lane uploads JUnit; Linux lanes also upload LCOV per shard. Python
reports include case durations, and the MCP runner can upload its JUnit report.
Coverage is diagnostic and split across shards, not a combined percentage.
Failed tests and missing package artifacts block CI; failed diagnostic uploads
do not. Use `python -m pytest -n 0` to reproduce Python failures serially.

Each week `test-quality` runs the mutation trial on Linux. On Linux, macOS, and
Windows it runs the test files that import the shared property options, using
the workflow run number as the property seed. Each platform uploads its JUnit
report. To replay the weekly jobs, dispatch with `compare-layouts` disabled.
Ordinary source pull requests run focused contracts for the shard runner, timing
metadata, report comparator, and Windows test-root helper in the required SDK suite.

Manual and reusable workflow runs default to comparing the previous layout
(three shards on Linux/macOS,
seven on Windows) with the expanded production layout (six on Linux/macOS,
fourteen on Windows), for 39 sharded runner jobs. Both layouts use the same serial
Bun runner and platform timing snapshot; the comparison combines all shards for
each OS before checking inventory and outcomes. Local full-suite runs still cover
unsharded cross-file ordering. More jobs add setup overhead, so compare required-green
latency and summed runner time alongside shard test timings.

The comparison uses the same seed for property cases and test ordering in every
layout. Manual runs use the workflow run number. Calls from pull request workflows
use seed 1. Reports have unique OS/layout/shard
names. The workflow requires every expected shard report
before accepting comparisons, then compares complete shard groups by test
identity, outcome, assertion count, and occurrence count, retaining legitimate
repeated names from parameterized tests while detecting missing or extra instances. It records every
shard's timing, including failed shards, in the job summary. It is not a required
check or part of the release trigger.

Required CI and shard diagnostics use Bun 1.3.14 without `--parallel` or
`--isolate`. Runtime upgrades and worker-based execution need separate
qualification of process-failure propagation and report/coverage finalization
before promotion.

Both layouts use the same property seed and coverage settings. Required CI uses
the default property seed and collects Linux coverage; diagnostics use the seed
above and the same Linux LCOV instrumentation. Artifacts include JUnit and
coverage in separate OS/layout/shard paths. The automated comparison checks JUnit
inventories, outcomes, and assertion counts; LCOV remains available for covered-line
comparison during qualification. Compare inventories across required CI and
diagnostics, but measure scheduling changes between diagnostic layouts.
Both workflows install ripgrep on Linux so the inventory-path test executes.

Keep the machine-policy test serial. Do not replace the full required suite
with `--changed`: Python files, schemas, fixtures, and workflows loaded at
runtime are not necessarily part of Bun's import graph.

## Mutation testing

Mutation tests require Node 22.18+ or 24.11+ because Stryker 10 uses Babel 8.
CI runs this tooling on Node 24.15.0. The SDK itself still supports Node 22.13+.

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
