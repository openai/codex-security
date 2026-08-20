# Codex Security CLI

Codex Security is a thin CLI and SDK wrapper around Codex and its security
plugin. Use their existing behavior instead of building another runtime.

## Threat model

The CLI runs as the current user. Local tools and subprocesses under that
account are not separate security principals. Scanned repositories can contain
untrusted data. Their contents, model output, and imported artifacts do not
authorize access to another target, disclosure of credentials, or writes
outside an approved path.

## Keep it simple

- Prefer one source of truth for types, schemas, arguments, and state.
- Keep `--to` as the only generic integration selector. Namespace other
  integration-specific options, such as `--linear-*` and `--jira-*`; do not
  generalize fields whose semantics differ across integrations.
- Reuse Codex APIs and shared helpers instead of adding extra trust gates or orchestration.
- Root read and workspace write are enough for the sandbox.
- Treat repository paths, symlinks, archives, and other repository-controlled data as untrusted.
- Keep protections for credentials, unsafe paths, scan integrity, and settings the user explicitly requests.
- Do not add arbitrary size, count, depth, or buffering limits to local inputs or Codex output. Keep limits required by an actual security boundary or an upstream contract.
- Do not let optional logging, progress, or cost tracking stop a scan. Still enforce limits the user requests, such as `--max-cost`.
- Preserve completed scan artifacts and keep database migrations append-only.
- Support Windows as well as Unix. Use platform-aware path and process APIs, and test realistic Windows paths and directory links when relevant.
- Favor direct flows and clear errors over defensive fallbacks for implausible cases.

## Unit tests

Add focused Bun tests in `tests-ts/<module>.test.ts`. Cover observable behavior,
accepted and rejected inputs, and each real bug or security boundary.

- Use deterministic fixtures, injected dependencies, and synthetic credentials. Avoid the network, real credentials, shared state, timing-sensitive assertions, and tests of exact Markdown wording.
- Restore spies, module mocks, timers, environment variables, and other global changes after each test. Isolate persistent ESM module mocks in a subprocess.
- Use separate temporary repository and output directories. Compare canonical paths and remove fixtures afterward; do not change the process working directory.
- Use native path helpers and argument arrays. Cover Windows drives, spaces, directory links, `HOME` and `USERPROFILE`, `PATHEXT`, and file URLs when relevant.
- Keep shared tests enabled on Linux, macOS, and Windows. Test built or installed entrypoints when packaging behavior matters.

From the SDK directory, run a focused test while iterating, then run the package checks:

```bash
bun test --timeout 30000 tests-ts/<module>.test.ts
pnpm run test --seed 12345
pnpm run types
pnpm run format
pnpm run test
```

Tests run in random order by default. To reproduce a failure, use the seed printed in Bun's test summary.

After the implementation is verified, keep the test in the final change only
when it provides meaningful, durable regression coverage. If it is merely
disposable implementation scaffolding, duplicates existing coverage, or would
add brittle or low-value maintenance burden, remove it before committing or
opening a PR and do not include it in the submitted change.
