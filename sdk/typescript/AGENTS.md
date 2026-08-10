# Codex Security CLI

Codex Security is a thin CLI and SDK wrapper around Codex and its security
plugin. Use the behavior they already provide instead of building another
runtime.

## Threat model

The CLI runs as the current user. Local tools and subprocesses under that
account are not separate security principals. Scanned repositories can contain
untrusted data. Their contents, model output, and imported artifacts do not
authorize access to another target, disclosure of credentials, or writes
outside an approved path.

## Keep it simple

- Prefer one source of truth for types, schemas, arguments, and state.
- Reuse Codex APIs and shared helpers instead of adding extra trust gates or orchestration.
- Keep the sandbox model simple: root read and workspace write are fine.
- Treat repository paths, symlinks, archives, and other repository-controlled data as untrusted.
- Keep protections for credentials, unsafe paths, scan integrity, and settings the user explicitly requests.
- Do not add arbitrary size, count, depth, or buffering limits to local inputs or Codex output. Keep limits required by an actual security boundary or an upstream contract.
- Do not let optional logging, progress, or cost tracking stop a scan. Still enforce limits the user requests, such as `--max-cost`.
- Preserve completed scan artifacts and keep database migrations append-only.
- Support Windows as well as Unix. Use platform-aware path and process APIs, and test realistic Windows paths and directory links when relevant.
- Favor direct, one-shot flows and clear errors. Avoid unneeded defensive fallbacks and implausible edge case handlers.

## Comments and pull requests

Mention another `openai/` repository in comments or pull request descriptions
only after checking that it is public. If you cannot confirm its visibility,
leave it out.

## Unit tests

Add focused Bun tests in `tests-ts/<module>.test.ts`. Test observable behavior and include a regression for each bug or security boundary. Cover both accepted and rejected inputs, and assert the exit code, stdout, stderr, or structured result that callers rely on.

- Keep tests hermetic. Use deterministic fixtures, injected dependencies, and synthetic credentials. Avoid network access, real credentials, shared state, and timing-sensitive assertions.
- Test observable behavior instead of exact Markdown wording or mocks that replace the integration being checked.
- Create fresh mocks and dependencies for each test. Restore spies, module mocks, timers, environment variables, and other global changes in `afterEach` or `finally`; clearing call history alone does not restore behavior. Keep persistent ESM module mocks in a subprocess when they cannot be safely restored.
- Isolate filesystem state with a unique temporary directory, resolve it with `realpath` before comparing paths, and remove it in `finally`. Keep repository and output fixtures separate, and avoid changing the process working directory.
- Exercise native paths. Use `join`, `resolve`, and the platform PATH delimiter instead of hard-coded separators. Cover drive-qualified paths, spaces, directory links, and JSON-escaped paths where relevant. Set both `HOME` and `USERPROFILE` when testing home discovery, account for `PATHEXT` when resolving executables, and use `pathToFileURL` for ESM imports.
- Start processes with an executable and argument array, a controlled environment, and a timeout. Use `process.execPath` and small cross-platform test doubles for Git, Python, or Codex boundaries, and test the built or installed entrypoint when packaging behavior matters.
- Keep shared behavior enabled on Linux, macOS, and Windows. Skip a platform only when the behavior is genuinely platform-specific, and keep an equivalent test for that platform when possible.

From the SDK directory, run a focused test while iterating, then run the package checks:

```bash
bun test tests-ts/<module>.test.ts
bun test --randomize --seed 12345
pnpm run types
pnpm run format
pnpm run test
```
