# Testing the SDK and CLI

## Install dependencies

Use [the repository’s pinned pnpm version](../../package.json) and [CI’s Bun version](../../.bun-version). From the repository root, enter the SDK directory and install both packages:

```sh
cd sdk/typescript
pnpm install --frozen-lockfile
pnpm --dir ../../plugins/codex-security/mcp-app install --frozen-lockfile
```

The commands below run from `sdk/typescript` unless a different directory is named. For a test that builds or loads the bundled plugin, first [download the universal native payload](../../plugins/codex-security/native/README.md#package-inputs). The SDK’s `test`, `test:ci`, `test:mcp` and `prepack` scripts all build that bundle.

## Run a focused test

Run the file for the behavior you changed. This example exercises progress parsing:

```sh
bun test --timeout 30000 ./tests-ts/worker-progress.test.ts
```

For an MCP change, follow the [MCP test guide](../../plugins/codex-security/mcp-app/TESTING.md). To see which suites this repository requires for a PR, see [How this repository tests pull requests](../../docs/ci.md).

### Native Windows sandbox tests

Two tests in `tests-ts/config.test.ts` start the real Codex sandbox to check
workspace writes and policy-source reads. Sandbox setup can change machine-wide
Windows state. These tests run by default on GitHub-hosted Windows Actions
runners. To include them in a local or self-hosted PowerShell run, set
`$env:CODEX_SECURITY_TEST_WINDOWS_SANDBOX = '1'` before running Bun. The value
`true` also enables them. Set the variable to `0` or `false` to skip both, even
on a hosted runner. The PowerShell machine-policy test has its own
`CODEX_SECURITY_ALLOW_MACHINE_POLICY_TEST` setting.

## Check the package

Run static checks, the MCP suite and the SDK suite after installing the dependencies and native payload:

```sh
pnpm run check:plugin-source
pnpm run types
pnpm run format
pnpm run test:mcp
pnpm run test
```

To collect JUnit and coverage while running the SDK suite, use `pnpm run test:ci` in place of `pnpm run test`. To test what an npm consumer receives, pack the archive and pass its exact path to the inspection command:

```sh
pnpm pack --pack-destination ../../dist
pnpm run check:package ../../dist/openai-codex-security-X.Y.Z.tgz
pnpm run test:package
```

Replace `X.Y.Z` with the version in the filename printed by `pnpm pack`.
Packing regenerates SDK defaults and project schemas before building the MCP runtime.

The authored plugin lives in `plugins/codex-security`. `pnpm pack` generates
the ignored `_bundled_plugin` runtime payload from `plugins/codex-security/plugin-files.json` during
`prepack`, including the MCP runtime built from `mcp-app`; do not edit generated
files there. Run `pnpm run build:plugin` when you need to inspect the staged
payload locally. `plugins/codex-security` contains authored source and assets,
not the generated `mcp/server.mjs` or compressed runtime chunks.
`pnpm run check:plugin-source` fails if any file beneath `_bundled_plugin` is
tracked by Git. Required CI runs the same check before installing dependencies.

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

The SDK shards in `node-ci` use the workflow run number as their seed, so
rerunning a job repeats its test order. To replay a shard locally, use its
platform, shard selector, and seed, for example
`node --experimental-strip-types scripts/run-ci-tests.mts 2/6 --seed=12345`.
On Linux, if the original workflow ran the separate MCP tests, prefix that
command with `CODEX_SECURITY_TEST_MCP_WORKERS_SEPARATE=true` to skip the four
worker groups they cover. Leave it unset to replay a run that skipped MCP.

The local test commands pass a 30-second per-test timeout explicitly. Windows
CI and the Windows runner diagnostics allow 120 seconds for slower native
credential and document checks. `test:ci` writes `reports/junit.xml` and
`coverage/lcov.info`. Coverage measures loaded
JavaScript and TypeScript, not the Python helpers or child processes. It is
diagnostic for now. Use several successful CI runs to establish a baseline
before proposing a coverage floor.

## Native artifacts in fresh development environments

Before running the full SDK tests or Ona’s **Run tests** task in a fresh checkout, [download the verified native package inputs](../../plugins/codex-security/native/README.md#package-inputs) for that checkout. Refresh them whenever the native source or build toolchain changes.

## Python test dependencies

Use Python 3.10 or later. From the repository root, install the Python test and lint dependencies with:

```sh
python -m pip install --disable-pip-version-check --no-input -r plugins/codex-security/requirements-test.txt
```

Tests load the plugin scripts from source; the repository does not need an installed Python distribution.
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

`node-ci` reports one `ci` gate for all selected required checks. The
[CI guide](../../docs/ci.md) describes documentation-only routing,
platform/version selection, and full scheduled qualification.

For source qualification, CI builds and inspects one package archive, then passes
that archive to jobs in the same workflow run, using the commit SHA in the
artifact name. Selected Node runtimes install and inspect the package, including
a strict NodeNext TypeScript consumer, the actual CLI, credential locking, and a
nested Codex worker. The installed Deep Scan smoke exercises a real retry on
one runtime per OS for PRs and main pushes, and on every scheduled or manual
qualification lane. All selected runtimes still complete direct and detached scans.
Native plugin-build tests remain in the shared Bun suite. Each supported OS
exercises the maintainer release preview, Git branch and commit updates,
concurrent ref conflicts, and preservation of maintainer edits.
Typechecking and formatting run once in an independent required job, so package
consumers do not wait for those checks. Package compilation and archive
validation still finish before the test jobs start.

Source qualification runs the full Bun suite once per OS under Node 22: six
file shards on Linux and macOS, and fourteen on Windows. GitHub runs the shards
as separate jobs; each job uses Bun's default serial runner. The other selected
Node versions run the installed-package checks instead of repeating the same
Bun suite. MCP CI assigns files by measured duration and starts the longest
files first, using two isolated Node test processes per job. From
`plugins/codex-security/mcp-app`, replay shard 1
with `node --experimental-strip-types ../../../sdk/typescript/scripts/run-mcp-test-shard.mts 1 2`.
Local and release `test:mcp` commands run the full suite. Python tests run
separately and use four
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
durations for executed cases per file and uses their median across reports. A
report that skipped every case in a file leaves its timing hint unchanged. Other
platforms retain their hints. Review and commit the generated snapshot. Keep runner versions, coverage,
timeouts, seeds, and platform-specific checks unchanged when comparing scheduling
changes; compare complete JUnit inventories and outcomes as well as wall time.

Every Bun lane uploads JUnit; Linux lanes also upload LCOV per shard. Python
reports include case durations, and the MCP runner can upload its JUnit report.
Coverage is diagnostic and split across shards, not a combined percentage.
Failed tests and missing package artifacts block CI; failed diagnostic uploads
do not. Use `python -m pytest -n 0` to reproduce Python failures serially.

Each week `test-quality` runs the mutation trial on Linux. On Linux, macOS, and
Windows it runs the test files that import the shared property options, using
the workflow run number as the property seed. The filesystem properties use the
same bundled plugin as the SDK tests to read the example scan and validate its
sealed artifacts. Each platform uploads its JUnit report. To replay the weekly jobs, dispatch with `compare-layouts` disabled.
Ordinary source pull requests run focused contracts for the shard runner, timing
metadata, report comparator, and Windows test-root helper in the required SDK suite.

For a scheduling comparison, run [test-quality](../../.github/workflows/test-quality.yml) with `compare-layouts` enabled. It runs the same serial Bun test inventory under two shard layouts. Compare the aggregate JUnit identities, outcomes, occurrence counts, and assertion counts for each OS, then review Linux LCOV artifacts for coverage differences. The job summary includes failed shard timings. Compare both elapsed time to a green gate and total runner time.

Use the same Bun version, seed, timeouts and coverage settings across layouts. Run the full local suite separately to exercise cross-file ordering. Qualify changes to Bun or its execution mode separately, including how test failures propagate and whether JUnit and coverage finish writing.

Keep the machine-policy test serial. Do not replace the full required suite
with `--changed`: Python files, schemas, fixtures, and workflows loaded at
runtime are not necessarily part of Bun's import graph.

## Mutation testing

Mutation tests require Node 22.18+ or 24.11+ because Stryker 10 uses Babel 8.
Use the Node version pinned by the [mutation job](../../.github/workflows/test-quality.yml). The SDK’s supported runtimes are listed in its [package manifest](package.json).
The commands below install Stryker from the separate, frozen `sdk/mutation`
lockfile and run it from the SDK directory.

```sh
pnpm run test:mutation
pnpm run test:mutation --mutate src/worker-progress.ts
```

The Stryker configuration covers progress parsing, safe error messages, and
pure cost arithmetic. It uses the fixed default property-test seed and writes
HTML and JSON under `reports/mutation`. Review surviving mutants for missing
behavior assertions or equivalent changes. There is no score gate yet; set
one only after the trial has a stable, useful baseline. Do not hide surviving
mutants with assertions about implementation details.
