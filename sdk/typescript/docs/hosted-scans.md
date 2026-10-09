# Hosted Standard scans (protocol v2)

`codex-security scan --host` runs one scan using newline-delimited JSON-RPC on
stdin/stdout. Use the flag alone. It performs no login, update check, local
inference, or model fallback. Ordinary local scans keep their existing behavior.

## Public executor API

Use the standalone `runHostedScan(input, { executor, signal, onEvent })`
function to run one hosted Standard scan. `CodexSecurity.run()` retains its local
scan behavior; it does not accept a hosted executor. The CLI command is a thin
JSON-RPC adapter around the same standalone function.

The CLI owns scan registration, plugin lifecycle, target checks, finalization,
report generation and sealed artifact validation. The host owns authorization,
frozen checkout, execution, durable run state, replay, reconciliation, usage,
billing and cleanup. It collects authoritative usage before cleanup and persists
accepted output independently from inference. Findings ingestion and
deduplication consume that accepted output separately. CLI workbench state
remains scan-domain state; there is no hosted-attempt replay store.

```ts
import { runHostedScan, type ScanExecutor } from "@openai/codex-security";

const executor: ScanExecutor = {
  async run(request, { signal, onEvent }) {
    // Persist the request identity before dispatch. Mount the matching plugin,
    // checkout, scan state and output directory in the remote executor.
    return await host.executeOnce(request, { signal, onEvent });
  },
};
const result = await runHostedScan(
  {
    version: 2,
    repository: "/workspace/repository",
    revision: "0123456789012345678901234567890123456789",
    scope: { paths: ["services/api", "services/web"] },
    outputDirectory: "/scan/output",
    stateDirectory: "/scan/state",
    model: "gpt-5.6-sol",
    reasoningEffort: "high",
    identity: {
      runId: "run-1",
      attemptId: "attempt-1",
      buildId: "runtime-build",
    },
  },
  {
    executor,
    onEvent(event) {
      console.error(event);
    },
  },
);
```

The function creates and closes its scan client internally, reusing the ordinary
Standard scan lifecycle. Omit `scope` for the entire repository, or pass literal
repository-relative folders/files. Model settings come from the frozen input;
local profiles and other local scan options are not accepted.

`ScanExecutor.run` receives an AbortSignal and an optional `onEvent` observer for
`{type: "progress", progress}` or `{type: "activity", activity}` events. Progress
uses the existing `ScanProgress` type; activity uses `ScanActivity`. Observer
failures cannot stop execution. Aborting waits for the executor to settle; the
host must cancel remote work and return its recorded outcome.

Preparation errors throw before execution. Execution and finalization return a
`HostedScanResult` receipt with status `completed`, `incomplete`, `failed`,
`canceled`, or `acceptance_unknown`. The receipt retains the executor's outcome, session
identity, usage, message and structured error even if artifact finalization
fails. Only validated artifacts receive hashes and sizes. Repeated invocations
are separate scans; the host decides whether a new invocation is allowed.

## Wire contract

Send `{"jsonrpc":"2.0","id":"run","method":"run","params":...}` with the
parameters below. IDs are strings or safe integers from -9007199254740991 through
9007199254740991; send larger numeric identifiers as strings.

```json
{
  "version": 2,
  "repository": "/workspace/repository",
  "revision": "0123456789012345678901234567890123456789",
  "scope": { "paths": ["services/api", "services/web"] },
  "outputDirectory": "/scan/output",
  "stateDirectory": "/scan/state",
  "model": "gpt-5.6-sol",
  "reasoningEffort": "high",
  "identity": {
    "runId": "example-run",
    "attemptId": "example-attempt",
    "buildId": "exact-runtime-build"
  }
}
```

Omit `scope` to scan the entire repository, matching the local CLI default.
`{"paths":["."]}` also means the repository. An explicit empty list is invalid;
root cannot be mixed with narrower paths. Paths are normalized, deduplicated and
sorted. Every selected path must exist and remain inside the repository at the
frozen revision before any execution request. Missing paths fail the whole
request; the CLI never skips them or broadens the scope. Canonical path aliases
are rejected with an actionable correction. Diff, Deep, resume, mock, local
workflow and post-scan execution are unsupported in this hosted Standard API.

The CLI verifies HEAD before path existence, registers the scan with its bundled
workbench, and sends one `execution.run` request. Its JSON-RPC ID equals the
required `params.requestId`. Params contain `version: 2`, normalized
`repository`, `revision`, `scope`, `identity`, registered `scanId`, `prompt`,
`model`, `reasoningEffort`, and `runtime`:

- `pluginRoot` and `pluginVersion`: the matching bundled plugin.
- `stateDirectory` and `outputDirectory`: writable paths outside the repository.
- `environment`: explicit runtime paths and interpreter settings, never host
  inference credentials.

The CLI and executor must share these filesystem paths or explicitly transfer
the same state. Run the plugin stdio server from
`pluginRoot/scripts/launch_codex_security_mcp --stdio` with the supplied
environment. The executor needs the target files, plugin skills and registered
artifacts, and must expose `record_codex_security_scan_draft`. CLI workbench
finalization follows the turn. Merely returning model text is insufficient.
Separately provisioned executors must receive the exact frozen runtime/plugin
build and preserve state; do not interpret plugin schemas as strict Structured
Outputs schemas.

The execution response `result` has:

- Required `requestId` matching the execution request, and `status`:
  `completed`, `failed`, `canceled`, or `acceptance_unknown`.
- `sessionId`, required for completed execution and optional for other outcomes.
- Optional `finalResponse`, `message`, and structured `error` with numeric `code`,
  string `message` and optional `data`.
- Optional opaque host `usage`. Absence means unknown, never zero. The host collects
  it for diagnostics; these observations do not replace authoritative accounting.

A transport failure or mismatched receipt is not proof of non-acceptance. The
CLI stops without resubmitting and leaves reconciliation to the host. The terminal
result retains `execution` even when scanning fails or is canceled. The runtime's
`hostProtocolVersion` identifies this protocol as version 2.
A package-exported example is available at
`@openai/codex-security/schemas/hosted-scan-v2.fixture.json`.

## Progress, cancellation and artifacts

The host sends `execution.progress` notifications with `{requestId, event}`.
The CLI forwards valid progress/activity through `scan.progress` notifications
with `{id: <original run RPC id>, event}`. Invalid optional event payloads are
ignored; mismatched request IDs are rejected. Stdout contains JSON-RPC only.

Send `{"jsonrpc":"2.0","method":"cancel","params":{"id":"run"}}` with the
original run request ID. The CLI aborts its executor signal, emits
`execution.cancel` with `{requestId}`, and waits for the host's outcome/usage
before returning a canceled result. The host must continue reading notifications
while executing. SIGINT/SIGTERM, disconnects and blocked output terminate the
transport promptly, even while a write callback is stuck. The host independently
cancels remote work and reconciles its known execution identities in those cases.

Preparation failures include typed `error.data.reason` for missing, escaping,
aliased or syntactically invalid paths and revision mismatch. Other failures
must not be presented as missing paths.

The terminal run result includes `version: 2`, `status`, frozen
identity/revision/normalized scope, output directory, scan ID and plugin version
when registered, `provenance` (CLI/plugin/build identity), optional `execution`,
and `artifacts`. Each artifact is `{path, sha256, bytes}` over its exact bytes.
Receipts cover canonical outputs, sealed supplemental files, and preserved
source files bound by the manifest. Sealed partial coverage stays `incomplete`;
unvalidated files never receive artifact receipts. `acceptance_unknown`, failed
and canceled results are not accepted completed scans.

The host verifies receipt paths, hashes, sizes, scope, revision and seals before
accepting output.
