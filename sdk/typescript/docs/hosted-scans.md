# Hosted Standard scans (protocol v2)

`codex-security scan --host` runs one scan using newline-delimited JSON-RPC on
stdin/stdout. Use the flag alone. It performs no login, update check, local
inference, or model fallback. Ordinary local scans keep their existing behavior.

For hosted patch generation and verification, use the separate
[hosted remediation API](hosted-remediation.md).

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

// These host methods are application code, outside the CLI.
await host.persistReceipt(result);
if (result.status === "completed") {
  // Check the frozen identity/scope and artifact paths, hashes, sizes and seals.
  await host.verifyAndAcceptArtifacts(result);
} else if (result.status === "acceptance_unknown") {
  // Look up the existing attempt/session; do not call runHostedScan again.
  await host.reconcileExecution(result.identity, result.execution);
}
// Failed and canceled receipts remain recorded but are not accepted
// completed scans. Persistence retries reuse this receipt without more inference.
```

The function creates and closes its scan client internally, reusing the ordinary
Standard scan lifecycle. Omit `scope` for the entire repository, or pass literal
repository-relative folders/files. Model settings come from the frozen input;
local profiles and other local scan options are not accepted.

Pass optional `severityRubric: { markdown, revision, sha256 }` to bind execution
to a host-resolved policy. The revision must be a positive safe integer and the
hash must match the exact UTF-8 Markdown. Without it, the SDK uses the bundled
rubric without fetching rubric configuration by default. Set
`CODEX_SECURITY_ENABLE_REMOTE_SEVERITY_RUBRIC=1` in the CLI environment or SDK
options' `environment` to opt in to fetching the shared Statsig default once,
with a three-second timeout and the bundled rubric as its fallback. Unset the
variable or use `0` to disable fetching; only the exact value `1` enables it.
An explicit host snapshot always takes precedence. Once resolved, the same
snapshot appears in `execution.run`, the terminal receipt, and the saved scan
recipe. Workers use it to grade findings. Each scan workflow still determines
how to validate a candidate and whether to report it. Hosts should verify the
snapshot alongside the frozen checkout and retain it when retrying a run.

Set `ownerSuggestions: true` to record ownership evidence during the existing
scan execution. The scan agent may include an optional hint on each finding:

```json
{
  "extensions": {
    "ownerSuggestion": {
      "email": "alex@example.test",
      "commit": "0123456789012345678901234567890123456789",
      "reason": "Maintains the affected source."
    }
  }
}
```

Use an observed contributor email and a full supporting commit hash from Git
blame/history for the affected source. Omit the hint when ownership is unclear.
Hints use the scan's existing session and budget; there is no extra ownership
turn or model call. Security findings take priority over optional hints.

After sealing the scan, the SDK builds `owner-suggestions.json` without inference.
CODEOWNERS declarations take precedence. Other hints must match an observed Git
identity and supporting commit in the finding's evidence. Missing hints abstain;
invalid hints produce per-finding owner errors. Neither invalid hints nor report
failures invalidate sealed findings. A completed receipt includes the artifact
when available, or `ownerSuggestionsError` if finalization fails.

Hosts run the normal scan request and capture the optional owner report.
Automatic reporting uses `suggestOwnersFromScan`; it does not use the legacy
`ownerCodex` option or send `owner.infer` / `owner.cancel` requests.

The standalone `suggestOwners` API and `suggest-owners` command can call a
model under their own budget. Both paths use the same CODEOWNERS rules, Git
evidence, identity checks, and report format.

Report generation works after the scan reaches `maxCostUsd`. It uses the
hints already recorded and never starts another model call to fill gaps.

`ScanExecutor.run` receives an AbortSignal and an optional `onEvent` observer for
`{type: "progress", progress}` or `{type: "activity", activity}` events. Progress
uses the existing `ScanProgress` type; activity uses `ScanActivity`. Progress may
include `reviewItems: { completed, total }` for saved reviews, counted separately
from files. Observer failures cannot stop execution. Aborting waits for the
executor to settle; the host must cancel remote work and return its recorded
outcome.

Preparation errors throw before execution. Execution and finalization return a
`HostedScanResult` receipt with status `completed`, `failed`,
`canceled`, or `acceptance_unknown`. The receipt retains the executor's outcome, session
identity, usage, message and structured error even if artifact finalization
fails. Only validated artifacts receive hashes and sizes. Repeated invocations
are separate scans; the host decides whether a new invocation is allowed.

Temporary runtime cleanup failures preserve the terminal receipt, including
its execution outcome, session identity, usage, and validated artifacts. They
are reported separately through `onEvent` as a failed message activity with
ID `runtime.cleanup` (a `scan.progress` notification over JSON-RPC). A cleanup
failure does not change the scan status or require another execution attempt.

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
root cannot be mixed with narrower paths. Each entry is one literal filename or
directory: `app/[slug]/page.tsx` and `reports/a,b.ts` are not patterns or lists.
Significant whitespace is preserved; `" service "` and `" "` do not select
`"service"` or the repository. An explicit empty string is invalid. Paths use the
ordinary CLI target resolver's filename semantics, with repository-relative
paths required here. They are normalized, deduplicated and sorted without
changing filename characters. Preparation also checks the existing output
contract: scope paths must be valid UTF-8 and cannot contain control characters,
backslashes, or start with a drive prefix such as `C:`. Incompatible filenames
fail before executor dispatch, including on POSIX where those files may exist.
Every selected path must exist and remain inside
the repository at the frozen revision before any execution request. Missing paths fail the whole
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
the same state. This includes:

- The frozen checkout and matching `pluginRoot` tree, including its executable
  helpers, skills, and MCP server.
- The whole `stateDirectory`, including the registered workbench database,
  journals, and scan inputs; a live database file alone is not a consistent copy.
- `outputDirectory`, where the executor records its draft and the CLI later
  writes the validated manifest, findings, coverage, and report.
- The temporary files named by `CODEX_SECURITY_CONFIG_PATH` and, for path scans,
  `CODEX_SECURITY_TARGET_PATHS_FILE` in `runtime.environment`. These are required
  by preflight and scope binding, even though they can live outside the state
  and output directories. The supplied interpreter paths must also resolve.

Keep these paths available throughout the invocation. The CLI removes its
temporary config/scope files when the invocation closes; caller-owned state
and output directories remain available. If remote work may outlive an
`acceptance_unknown` return, the host must preserve the files that work still
needs before returning that outcome. Use shared mounts or a coordinated transfer
that preserves the supplied path bindings, not independent copies of mutable
workbench state.

Run the plugin stdio server from
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
`@openai/codex-security/schemas/hosted-scan-v2.fixture.json`. Its `response` is
the executor's reply; `terminal` is the separate final scan receipt. The example
hashes and sizes are illustrative and do not validate any real files.

| Final scan status      | Host handling                                                                                    |
| ---------------------- | ------------------------------------------------------------------------------------------------ |
| `completed`            | Verify artifact receipts and seals before accepting output.                                      |
| `failed` or `canceled` | Retain identity, diagnostics and any execution/usage receipt.                                    |
| `acceptance_unknown`   | Reconcile the existing remote attempt and collect usage before cleanup; do not resubmit blindly. |

Reconciliation uses the host's durable attempt/session identifiers and provider
status. Preserve state and output for inspection, and cancel or join remote work
before releasing resources it still uses. The hosted API has no replay store,
resume, or finalize-only operation: calling `runHostedScan` again registers a new
scan. A provider reporting execution completion does not substitute for a
validated, sealed scan receipt.

## Progress, cancellation and artifacts

The host sends `execution.progress` notifications with `{requestId, event}`.
The CLI forwards valid progress/activity through `scan.progress` notifications
with `{id: <original run RPC id>, event}`. Invalid optional event payloads are
ignored; mismatched request IDs are rejected. Stdout contains JSON-RPC only.

Send `{"jsonrpc":"2.0","method":"cancel","params":{"id":"run"}}` with the
original run request ID. If cancellation arrives while the CLI is fetching the
default rubric, it returns a canceled receipt without a rubric or execution.
Once execution starts, the CLI aborts its executor signal, emits
`execution.cancel` with `{requestId}`, and waits for the host's outcome/usage
before returning a canceled result. The host must continue reading notifications
while executing. SIGINT/SIGTERM, output errors/closure, and cancellation with
blocked output terminate the transport even while a write callback is stuck.
Input EOF before the terminal response fails the run; EOF while that response is
flushing waits for the write callback. A selected successful result is not a
successful delivery. Hosts own deadlines and independently cancel remote work
and reconcile known execution identities after transport failure.

Preparation failures include typed `error.data.reason` for missing, escaping,
aliased or syntactically invalid paths and revision mismatch. Other failures
must not be presented as missing paths.

The terminal run result includes `version: 2`, `status`, frozen
identity/revision/normalized scope, output directory, scan ID when registered,
plugin version when known, `provenance` (CLI/plugin/build identity), optional `execution`,
and `artifacts`. Each artifact is `{path, sha256, bytes}` over its exact bytes.
Receipts cover canonical outputs, sealed supplemental files, and preserved
source files bound by the manifest. Coverage limitations remain diagnostics in
completed scans; required-output failures return `failed`, and unvalidated files
never receive artifact receipts. `acceptance_unknown`, failed
and canceled results are not accepted completed scans.

The host verifies receipt paths, hashes, sizes, scope, revision and seals before
accepting output.
