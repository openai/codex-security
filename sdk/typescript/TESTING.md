# Testing the SDK and CLI

Use the pnpm version in `package.json` and Bun 1.3.14, matching required CI.
Install both the SDK and MCP app dependencies before building or testing.
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

Tests run in random order by default. To replay a failure, pass the seed from
Bun's summary to `pnpm run test --seed 12345`.

The local test commands pass a 30-second per-test timeout explicitly. Windows
CI and the Windows runner experiment allow 120 seconds for slower native
credential and document checks. `test:ci` writes `reports/junit.xml` and
`coverage/lcov.info`. Coverage measures loaded
JavaScript and TypeScript, not the Python helpers or child processes. It is
diagnostic for now. Use several successful CI runs to establish a baseline
before proposing a coverage floor.

## Writing tests

- Test observable results, failures, cancellation, and cleanup. Prefer a
  regression case that fails before a fix over assertions about private calls
  or exact prose.
- Keep fixtures synthetic and independent. Use real temporary directories,
  Git repositories, SQLite databases, and installed packages when those
  boundaries are the behavior under test. Do not use live model credentials.
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
  that are not strings. The JUnit comparison rejects duplicate identities.

Property tests use a fixed default seed. Fast-check prints the seed, shrink
path, and counterexample on failure. To replay one property, select its file
and test name, then set `CODEX_SECURITY_PROPERTY_SEED` and
`CODEX_SECURITY_PROPERTY_PATH` to the reported values. Set
`CODEX_SECURITY_PROPERTY_RUNS` to increase the case count. Pure properties
default to 100 cases; filesystem contract properties default to 20.

## GitHub Actions

`node-ci` retains the required `ubuntu-latest / node-22`,
`macos-latest / node-22`, and `windows-latest / node-22` checks. It builds and
inspects one package archive, then passes that archive to jobs in the same
workflow run, using the commit SHA in the artifact name. Every supported Node
runtime still installs and inspects the package, including a strict NodeNext
TypeScript consumer, the actual CLI, credential locking, dashboard assets, and
a nested Codex worker. Native plugin-build tests remain in the shared Bun suite.

The full Bun suite runs once per OS under Node 22: three file shards on Linux
and macOS, and seven on Windows. The other Node versions run the installed
package checks instead of repeating the same Bun suite. MCP and Python tests
run in separate required jobs. Python uses four isolated pytest-xdist workers
with work stealing; worker crashes fail the run without automatic restarts.

`scripts/run-ci-tests.mjs` assigns the longest measured files first. Its
`ci-test-durations.json` records per-file seconds from CI reports.
Every new test file is included automatically with a one-second estimate.
Refresh those estimates from the uploaded reports when adding or splitting
expensive files; estimates affect scheduling, never whether a test runs.
To reproduce one Windows shard locally after building the plugin, run
`node scripts/run-ci-tests.mjs 3/7 --seed=12345`.

Every Bun lane uploads JUnit; Linux lanes also upload LCOV per shard. Python
reports include case durations, and the MCP runner can upload its JUnit report.
Coverage is diagnostic and split across shards, not a combined percentage.
Failed tests and missing package artifacts block CI; failed diagnostic uploads
do not. Use `python -m pytest -n 0` to reproduce Python failures serially.

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

Keep the measured file-balanced runner until the native runner has
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
