# Testing the SDK and CLI

Use the pnpm version in `package.json` and Bun 1.3.14, matching required CI.
Run these commands from `sdk/typescript`:

```sh
pnpm install --frozen-lockfile
bun test --timeout 30000 ./tests-ts/worker-progress.test.ts
pnpm run types
pnpm run format
pnpm run test
pnpm run test:ci
pnpm pack --pack-destination ../../dist
pnpm run test:package
```

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
Node 22 job runs static checks and uploads JUnit and LCOV. All supported runtime
lanes still test and inspect an installed package. Package inspection includes
a strict NodeNext TypeScript consumer and the actual installed CLI. Failed
tests block CI; a failed diagnostic upload does not.

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

Keep the current file-balanced Windows runner until the native runner has
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
