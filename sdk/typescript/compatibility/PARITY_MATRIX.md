# TypeScript SDK and CLI reference

This reference describes the supported TypeScript SDK, CLI, and observable scan
contracts. The SDK is asynchronous and uses camelCase option and result names.

## Public SDK surface

| Historical surface                           | Supported behavior                                  | TypeScript contract                                                                           |
| -------------------------------------------- | --------------------------------------------------- | --------------------------------------------------------------------------------------------- |
| `CodexSecurity(config)`                      | Eager isolated-runtime preparation; context manager | `new CodexSecurity(config)` with lazy async preparation; `await close()` / async disposal     |
| `AsyncCodexSecurity(config)`                 | Async mirror of the synchronous client              | Folded into the single async `CodexSecurity` class                                            |
| `.metadata`                                  | Codex SDK runtime metadata                          | Exact aligned npm SDK/executable package names and versions                                   |
| `.run(repository, target, mode, output_dir)` | Start, await, validate, and return a scan           | `await run(repository, options)`                                                              |
| `.turn(...)`                                 | Return a controllable scan handle                   | `await turn(repository, options)`                                                             |
| `.close()`                                   | Close Codex and remove isolated runtime             | `await close()`; idempotent cleanup                                                           |
| `.login_api_key(key)`                        | Materialize API-key authentication                  | `await loginApiKey(key)` without persisting the key in metadata                               |
| `.login_chatgpt()`                           | Browser login handle                                | `await loginChatGPT()` child-process handle around the exact public Codex CLI                 |
| `.login_chatgpt_device_code()`               | Device-code login handle                            | `await loginChatGPTDeviceCode()` child-process handle around `--device-auth`                  |
| `.account(refresh_token=False)`              | Return Codex account state                          | `await account()` from `codex login status`; refresh-token metadata is explicitly unsupported |
| `.logout()`                                  | Clear isolated authentication                       | `await logout()` through the exact public Codex CLI                                           |
| `ScanHandle.id`                              | Turn identifier                                     | Always `null`; the public JavaScript SDK event stream has no turn identifier                  |
| `ScanHandle.thread_id`                       | Thread identifier                                   | `threadId`, populated from `thread.started`                                                   |
| `ScanHandle.scan_dir`                        | Persistent partial/final output directory           | `scanDir`                                                                                     |
| `ScanHandle.stream()`                        | Stream Codex events                                 | Async iterable `stream()`                                                                     |
| `ScanHandle.run()`                           | Collect final result                                | `await run()`                                                                                 |
| `ScanHandle.interrupt()`                     | Interrupt running turn                              | `interrupt()` via the supported `AbortSignal` boundary                                        |
| `ScanHandle.steer(input)`                    | Send input to the active turn                       | Requires a reusable public JS SDK capability; `0.142.0` has no steering API                   |
| `DiffTarget.refs(base, head)`                | Committed ref diff                                  | `DiffTarget.refs({base, head})`                                                               |
| `DiffTarget.working_tree(base)`              | Staged and unstaged diff                            | `DiffTarget.workingTree({base})`                                                              |
| `CodexSecurityConfig.plugin_path`            | Directory/ZIP override                              | `pluginPath`                                                                                  |
| `CodexSecurityConfig.codex_overrides`        | Deep-merged isolated Codex config                   | `codexOverrides`                                                                              |
| n/a                                          | Explicit plugin Python interpreter                  | `pythonPath` and CLI `--python`                                                               |
| `ScanResult` paths/properties                | Canonical contract plus paths and turn result       | Readonly camelCase fields and path getters                                                    |
| Contract Pydantic models                     | Typed nested documents; unknown fields retained     | TypeScript interfaces plus Ajv 2020 validation; parsed JSON objects retain unknown fields     |
| Error hierarchy                              | Typed SDK failures                                  | Same class names in TypeScript, plus a plugin-Python diagnostic subtype if needed             |

## CLI flags and arguments

| Surface                        | CLI behavior                                                                  |
| ------------------------------ | ----------------------------------------------------------------------------- |
| no arguments                   | Print root help to stdout and exit 0                                          |
| `-h`, `--help`                 | Print root help and exit 0                                                    |
| `--version`                    | Print SDK version and bundled plugin version to stdout; exit 0 without Python |
| `scan [repository]`            | Repository defaults to the current directory                                  |
| repeatable `--path PATH`       | Path-only scan; mutually exclusive with diff/working-tree                     |
| `--diff BASE`                  | Ref diff using `--head` or `HEAD`                                             |
| `--working-tree`               | Staged and unstaged changes using `--base` or `HEAD`                          |
| `--head REF`                   | Valid only with `--diff`                                                      |
| `--base REF`                   | Valid only with `--working-tree`                                              |
| `--mode standard\|deep`        | Deep rejects diff targets                                                     |
| `--output-dir DIR`             | Must be absent or empty and outside the repository; preserved on interruption |
| `--plugin-path PATH`           | Plugin directory or safe ZIP override                                         |
| repeatable `--codex KEY=VALUE` | Parse TOML literals, reject duplicate/conflicting/owned keys                  |
| `--json`                       | Machine JSON only on stdout; progress/errors on stderr                        |
| `--python PATH`                | Intentional additive v0 option for the explicit plugin runtime boundary       |

## Output, exit, and signal contract

| Condition                      | stdout                                                     | stderr                                   | exit |
| ------------------------------ | ---------------------------------------------------------- | ---------------------------------------- | ---- |
| successful human scan          | Scan, report, plugin, finding-count lines                  | timed progress stages                    | 0    |
| successful JSON scan           | manifest/findings/coverage, scan/thread/path/turn metadata | timed progress stages                    | 0    |
| SDK/validation/bootstrap error | empty                                                      | `codex-security: <message>`              | 1    |
| parser/usage error             | empty                                                      | usage plus error                         | 2    |
| Ctrl-C                         | empty                                                      | cancellation and partial-output location | 130  |
| SIGTERM                        | empty                                                      | termination and partial-output location  | 143  |

`@openai/codex-sdk@0.142.0` provides run, streaming, and `AbortSignal`
cancellation. The aligned public Codex executable provides login, account-status, and
logout commands. Neither surface exposes steering, stable login/turn IDs, refresh-token
metadata, structured skill input, or turn duration. Those missing reusable capabilities
are the optional prerequisite boundary; the security package does not invent a private
transport.
