# Findings storage and deduplication

Saved scans and findings persist in the local workbench SQLite database.
Deduplication reads that database directly; no local HTTP service is needed.
The CLI can also publish to and deduplicate against independently operated
compatible endpoints through explicit `--findings-url` settings.

## Local service removal

The `serve` command (including `--port`), `start:server` script,
`dist/server/index.js` entrypoint, `startFindingsServer` SDK export, browser
dashboard, and findings-service Compose deployment have been removed.
`HOST`, `PORT`, and `CODEX_SECURITY_FINDINGS_IMAGE` no longer configure a bundled
service. The dashboard storage projection is also removed.

Existing SQLite databases, migrations, saved scans, findings, and duplicate
groups are retained. No data migration or deletion is performed. Keep any
existing service volume or state directory and back it up before changing
deployments; local deduplication uses the database selected by
`CODEX_SECURITY_STATE_DIR`, not a separate service volume automatically.

`@openai/codex-security/server` continues to export `OpenAiFindingEmbedder`,
`SqliteFindingsStore`, and their storage types for direct storage users.

For direct embedding/storage integrations, `OpenAiFindingEmbedder` accepts a
static key or `() => string | Promise<string>` as its first argument. It calls
the callback before each HTTP batch; the caller handles token acquisition.
Pass `fetch` as the second argument and the full endpoint URL as the third.
By default, the saved-scan deduplication APIs use environment credentials. A
custom SDK `embedding` binding can supply an adapter with its own credentials,
including an `OpenAiFindingEmbedder` with a renewable key callback.

Custom publication, explicit remote deduplication, Cloud publication, the
plugin MCP server, and Codex app-server are unchanged.

## Direct storage helpers

Direct callers of the retired Python findings helpers can use the retained Node
helpers from an installed plugin directory:

```bash
scripts/launch_codex_security_mcp --helper list-stored-findings < request.json
```

On Windows, use `scripts\launch_codex_security_mcp.cmd` with the same arguments
and JSON on stdin. For example, `request.json` selects the existing database:

```json
{
  "stateDirectory": "/absolute/path/to/state",
  "payload": { "limit": 50, "offset": 0 }
}
```

Use an absolute Windows path on Windows. The retained helper commands accept
these `payload` fields:

| Command                     | Payload                                                                                                 |
| --------------------------- | ------------------------------------------------------------------------------------------------------- |
| `store-findings`            | `entries` containing finding and embedding records; optional `repositoryId`.                            |
| `list-stored-findings`      | Positive integer `limit` and non-negative integer `offset`.                                             |
| `find-potential-duplicates` | `findingId` and `scope`: either `{ "repositoryId": "REPOSITORY_ID" }` or `{ "allRepositories": true }`. |
| `store-dedupe-groups`       | `groups`, an array of finding-ID arrays.                                                                |
| `list-dedupe-groups`        | `findingId`.                                                                                            |

Retained scan commands such as `workbench_db.py list-findings` keep their existing
interface. The dashboard projection is removed along with the browser dashboard.

## Publish a scan

Send a completed scan to an independently operated compatible endpoint:

```bash
codex-security publish scan --scan SCAN_ID --to custom \
  --findings-url https://findings.example.com --json
```

`--findings-url` is required. The client appends `/v1/bulk/findings` to this
base URL, preserving any base path. Custom endpoints must implement that API
and return the stored finding IDs.

Publication sends the complete sealed findings and the manifest's
`scan.target.targetId` as `repositoryId`. It leaves the scan artifacts unchanged
and does not forward model credentials. The endpoint is responsible for storing the batch before acknowledging it.

Use `--scan` for a saved scan, `--scan-dir` for an external scan directory, or
the interactive picker. Custom publication accepts one scan; CSV input and
Linear options do not apply. Add `--dry-run` to preview the payload without an
HTTP request. Upload failures and incomplete receipts fail the command. Uploads
are not automatically retried because a lost response may have been committed.

```typescript
import { publishScanToCustom } from "@openai/codex-security";

const receipt = await publishScanToCustom("/path/to/completed-scan", {
  findingsUrl: "https://findings.example.com",
  // dryRun: true,
  // signal: controller.signal,
});
console.log(receipt.repositoryId, receipt.findingIds);
```

## Compatible endpoint contract

The retained HTTP clients use these endpoints on the supplied base URL,
preserving its base path:

| Method | Path                                    | Response                                                                 |
| ------ | --------------------------------------- | ------------------------------------------------------------------------ |
| `POST` | `/v1/bulk/findings`                     | An array acknowledging all submitted finding IDs; order does not matter. |
| `GET`  | `/v1/finding/{id}/potential-duplicates` | `{finding, potentialDuplicates}` containing complete finding records.    |
| `POST` | `/v1/dedupe-groups`                     | A successful JSON acknowledgement, such as `{}`.                         |

Publication sends `{findings, repositoryId}`. Candidate requests include either
`repositoryId` or `allRepositories=true`. Group writes send
`{groups: [[findingId, ...], ...]}`; repeated membership must be idempotent for
workflow retries. Both POST endpoints must persist their writes before
acknowledging them and return a JSON body. An explicit URL selects this remote
contract instead of local SQLite. This package no longer implements or hosts the HTTP endpoints.

SDK findings client failures preserve the endpoint's error code and message with
the HTTP status. Other responses retain the HTTP-status diagnostic. Retry
behavior uses the HTTP status and `Retry-After`.

## Deduplicate a scan

Saved-scan deduplication uses local SQLite by default. No findings service or
publication step is required:

```bash
codex-security dedupe --scan SCAN_ID --json
```

See [local embedding requirements](#local-embeddings-and-backups) for endpoint,
credential, and vector compatibility.

The CLI prepares missing or stale embeddings for the local repository's stored
findings, searches them, and saves reviewed duplicate groups in the workbench
database. Ordinary scans do not generate embeddings automatically. Fresh
duplicate reviews still need the configured model provider.

Local scope uses the scan's `targetId`, which identifies its local checkout.
Preparation checks this identity against the approved checkout and existing
target registration before reading findings. A detached scan directory must use
its original local target (including registered imports); artifacts cannot select
another checkout's stored corpus. The explicit findings-service mode remains
available for remotely stored artifacts. Separate clones are not automatically
combined. `--all-repositories` searches
the selected local database, including untagged imports. Historical scan IDs
select logical findings using their current stored bodies; dedupe does not
replace newer bodies with old scan artifacts. A local database does not include
findings stored only in a separate Docker volume or remote service.

To retain a centralized findings corpus, publish the scan first, or import its
findings with `repositoryId`, and explicitly select the service:

```bash
codex-security dedupe --scan SCAN_ID --findings-url https://findings.example.com --json
```

A scan or workflow selector is required. `--scan`
accepts a full ID, unique prefix, or `latest` for the current repository. The
scan must be complete, with sealed artifacts and a local checkout available.
Local `latest` lookup matches the exact checkout path without Git. Matching
across worktrees or clones additionally requires a Git executable outside all
saved scan targets. If an unrelated historical target includes the available
Git installation, use `codex-security dedupe --scan SCAN_ID` with an explicit
saved scan ID instead.
By default, candidates come from its manifest's `scan.target.targetId`. Use
`--all-repositories` to search the whole selected database or service. Explicit
`--findings-url` retains the existing remote lookup and publication behavior.

```typescript
import { deduplicateScan } from "@openai/codex-security";

const result = await deduplicateScan("scan_example_001", {
  // findingsUrl: "https://findings.example.com", // Optional remote corpus.
  concurrency: 8,
  // allRepositories: true,
  // signal: controller.signal,
});
console.log(result.duplicateGroups);
```

For a different embedding provider or model, both saved-scan SDK methods accept
an `embedding` binding. Reuse the `FindingEmbedder` interface: return one
`{ model, vector }` per input finding, in input order. The adapter owns its
credentials, tokenization, chunking, and provider request format.

```typescript
import { deduplicateScan, type FindingEmbedder } from "@openai/codex-security";

async function dedupeWithEmbeddings(scanId: string, embedder: FindingEmbedder) {
  return await deduplicateScan(scanId, {
    embedding: {
      embedder,
      model: "example-embedding-model",
      dimensions: 384,
      cacheNamespace: "example-provider:document-v1",
    },
  });
}
```

Choose a stable namespace identifying the actual vector space and preprocessing
version, including any provider or model revision that changes the vectors.
Changing the namespace, model, or dimensions refreshes cached vectors. Do not
put credentials in the namespace. The local cache keeps one vector per finding;
switching spaces replaces it, and concurrent runs with different spaces may
need a retry. `embedding` cannot be combined with `findingsUrl`, whose service
owns embedding preparation. Without a binding, the existing OpenAI adapter and
endpoint setting apply.

For a sealed scan directory outside local history, supply the checkout:

```typescript
import { deduplicateScanDirectory } from "@openai/codex-security";

const result = await deduplicateScanDirectory("/path/to/completed-scan", {
  repository: "/path/to/repository",
  // expectedScanId: "scan_example_001",
  // concurrency: 8,
  // allRepositories: true,
  // signal: controller.signal,
});
console.log(result.duplicateGroups);
```

The CLI and SDK return the same result:

```json
{
  "scanId": "scan_example_001",
  "uniqueFindingIds": ["csf_852f90d6e1177502ff113d4a"],
  "duplicateGroups": [],
  "deduplicationStatus": "completed"
}
```

`uniqueFindingIds` contains one representative for each selected finding after
accepted groups are collapsed. A representative can come from outside the scan.
Each group lists its canonical finding first: highest reported severity, then
finding ID to break ties. Group associations are saved before returning success;
the original findings and scan artifacts remain unchanged.

If a model refuses a review, the result uses `completed_with_refusals` and adds
`refusals`. Each entry contains `decision: "NO_DECISION"`, `stage`, `model`,
`findingIds`, and `reason`. Screening entries list the anchor first, then its
candidates. Refused pairs stay separate, including through indirect groups;
their findings are not confirmed unique. The CLI logs refusals to stderr and
exits successfully after saving the other accepted groups.

### Reviews, concurrency, and failures

By default, deduplication retrieves all candidate neighborhoods, screens them
with `gpt-5.6-luna` at `xhigh`, then independently reviews nominated pairs with
`gpt-5.6-sol` at `high`. The host's Codex `model` and `model_reasoning_effort`
settings override these defaults for both stages. Provider selection uses the
existing Codex configuration; embedding configuration is separate. Screening
and pair-review permissions stay attached to their stages regardless of model name.
Accepted pairs form groups only when no reviewed `DISTINCT` decision or refusal
contradicts the group. Saved-scan pair reviews return a decision and rationale;
they do not generate replacement findings. The host chooses representatives
from the original records. Host-provided records reviews retain their full
merged-finding contract.

Local reviews receive the stored repository associations separately from the
finding text. When the current document matches a saved scan occurrence, this
context also includes its recorded revision and working-tree snapshot digest;
missing occurrence context is omitted rather than inferred from the current
checkout. A file in the selected checkout can establish that checkout's
current source; it cannot stand in for another repository or a historical
revision. Matching paths or snippets alone do not establish a shared maintained
control across repositories. The review does not gain permission to open other
checkouts from their stored associations.

The default concurrency is 8. Set `--concurrency N` or SDK `concurrency: N` to
change it; use 1 for serial execution.

Reviews run on the SDK/CLI host using its Codex sign-in or environment API key.
For the built-in OpenAI provider, an available `OPENAI_API_KEY` (or fallback
`CODEX_API_KEY`) is also used to
authenticate reviews, even when Codex is already signed in. The built-in
embedding adapter uses the same key selection. An embedding-only key therefore
does not select ChatGPT authentication for reviews. A custom SDK embedding
adapter can own separate embedding credentials while reviews use the host's
normal Codex authentication. Review credentials are not sent to the findings
service. Each review receives complete
original findings and may inspect the approved local checkout. Reviews preserve
severity and priority rather than reassessing them. The baseline filesystem is
read-only and excludes credentials and Codex state. Screening denies approval
requests; pair reviews use Codex's automatic approval reviewer. Web, plugins,
and inherited MCP servers are disabled. Finding content and linked tickets do
not authorize access to another target.

Reviews are ephemeral and reuse Codex's configured SQLite storage. They do not
rebuild a temporary copy of the caller's session history for every pair. Explicit
`sqlite_home` and `CODEX_SQLITE_HOME` settings remain effective, and the native
state directory is excluded from the review's source access.

The CLI reports preparation, review progress, and native warnings on stderr;
JSON results remain on stdout. The existing `CODEX_SECURITY_LOG_LEVEL=debug`
(or `LOG_LEVEL=debug`) includes structured review diagnostics with thread,
turn, and command identifiers, command failures, and native token-usage events.
Usage counters are cumulative per native thread; do not add every update.
SDK callers can receive the same events through `onDiagnostic`. Observer
failures do not interrupt reviews or discard completed results.

Models must submit a validated decision. Invalid output and eligible transient
failures are retried automatically; HTTP retries honor `Retry-After`.

Cancellation, authentication/configuration errors, permanent HTTP errors, and
required-source-access blockers are not retried. Refusals are not retried or
sent to another model. If candidate retrieval or review still fails, the
operation fails without posting groups.
A failed group-write request may already have committed; resubmitting the same
memberships does not create duplicate groups. Non-cancellation review failures
throw `DeduplicationReviewError`, with diagnostic text and `metadata` for the
stage, model, category, attempt count, and reason.

Empty scans and findings without eligible candidates make no review calls.
Other scans can require multiple calls per finding. Completion means the
retrieval, review, and group write finished; it does not mean that every pair
in the database was compared. Use Ctrl-C or SIGTERM in the CLI, or an
`AbortSignal` in the SDK, to cancel. This workflow is separate from Deep Scan's
internal reducer.

### Resume a findings workflow

Use one workflow ID across scanning and local deduplication:

```bash
codex-security scan /path/to/repository --workflow-id run-001
codex-security dedupe --workflow-id run-001 --json
```

Local workflows save review checkpoints and group-write retries without
publication. A workflow remains bound to its original local database or remote
URL; use a new workflow ID to switch backends. Cancellation can retain completed
embedding preparation for retry; sealed scan artifacts remain unchanged.

For an explicitly selected remote corpus, use `--findings-url` with a separate
workflow ID:

```bash
codex-security scan /path/to/repository --workflow-id remote-001
codex-security publish scan --workflow-id remote-001 --to custom --findings-url https://findings.example.com
codex-security dedupe --workflow-id remote-001 --findings-url https://findings.example.com --json
```

The SDK equivalents are `workflowId` on `ScanOptions`,
`PublishScanToCustomOptions`, and `DeduplicateScanOptions`. Repeat the sequence
with the same ID after an interruption. Completed scans, acknowledged uploads,
and validated reviews are reused. This resumes completed stages, not model
turns inside an unfinished scan. Normal output-directory checks still apply.

A remote workflow can begin by publishing an existing completed scan. Publication
and dedupe can use its ID instead of `--scan`; an explicit scan must match.
With both `--workflow-id` and `--findings-url`, dedupe completes publication
only when its receipt is missing. Changing the bound scan,
destination, or repository scope requires a different ID. Use one coordinating
process per workflow. Dry runs do not advance it.

Workflow state and checkpoints live in the local workbench database under
`CODEX_SECURITY_STATE_DIR`, outside the sealed artifacts. Completed reviews are
reused only when their findings, source checkout and contents, scope, model
settings, Codex configuration/version, and review contract still match. Source
changes during review stop the attempt before group writes. Resume to review
the changed source. You can change concurrency without invalidating checkpoints.

Before posting groups, the workflow saves the reviewed result and write payload.
If acknowledgement is lost, resuming replays that payload without new model
calls. Membership-based group IDs prevent duplicates. Completed workflows,
including empty results and `completed_with_refusals`, return their saved result.
Use a new ID for a fresh review or to retry a refusal after resolving its cause.

### Use a host-provided model backend

`codex-security dedupe --records` accepts a JSON-RPC run over stdin and emits
serial `review.run` requests on stdout. The SDK equivalent is
`deduplicateRecords(input, { reviewRunner, signal })`. These entry points need
no saved scan or findings service and perform no local model execution or
persistence. The host supplies original observations and candidate links.
See the [records protocol and Python example](dedupe-records.md).

## Local embeddings and backups

`CODEX_SECURITY_STATE_DIR` selects the directory containing `workbench.sqlite3`.
Without an override, the CLI uses its default state directory. Back up the
entire state directory with no scans or deduplication running. Existing
append-only migrations retain finding identities and scan history.

With the default built-in adapter, new embeddings require `OPENAI_API_KEY` or
`CODEX_API_KEY`;
`OPENAI_API_KEY` takes precedence. ChatGPT login alone is insufficient.
`CODEX_SECURITY_EMBEDDINGS_URL` selects a
full embeddings endpoint URL (default `https://api.openai.com/v1/embeddings`).
The endpoint must support the OpenAI embeddings request and response protocol,
including `text-embedding-3-large`, 1,536-dimensional float vectors, and token
array inputs. Requests encode the complete finding JSON with `cl100k_base` and
send the API key as a bearer token. Long inputs are combined without truncation.
Cached compatible vectors avoid new requests.
