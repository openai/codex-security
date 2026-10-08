# Findings service (preview)

Store findings from multiple scans, browse them in a dashboard, and review
possible duplicates with the CLI or SDK. The service stores findings and
duplicate groups; scans and model reviews run on the calling machine.

The API has no authentication. Keep it on loopback or behind an authenticated
TLS proxy. Imports send the complete finding JSON to the configured embeddings
endpoint. The database and generated embeddings stay in local storage.

CLI examples use `codex-security`. With a local npm installation, use
`npx @openai/codex-security` instead.

## Start the service

Use the repository's
[Compose file](https://github.com/openai/codex-security/blob/main/compose.findings.yaml)
and [.env example](https://github.com/openai/codex-security/blob/main/.env.example).
From the repository root, copy the example if you do not already have a `.env`:

```bash
cp .env.example .env
```

Set `OPENAI_API_KEY` in `.env`, then start the service:

```bash
docker compose -f compose.findings.yaml pull
docker compose -f compose.findings.yaml up --no-build -d
curl -i http://127.0.0.1:3000/v1/findings
```

Open [the dashboard](http://localhost:3000/dashboard) to browse stored findings
and duplicate groups.

You can deploy with just `compose.findings.yaml` and a private `.env`; no source
checkout or Node.js installation is required. The public image supports Linux
`amd64` and `arm64`. Set `CODEX_SECURITY_FINDINGS_IMAGE` to a published version,
`sha-<commit>` tag, or digest for repeatable deployments. Its default is
`ghcr.io/openai/codex-security:latest`.

Compose binds port 3000 to host loopback and stores `/state` in the
`findings-state` volume. Keep the same Compose project name to reuse the volume.
The image runs as UID/GID `10001:10001`; a replacement bind mount must be writable
by that user. Inside the container, `HOST=0.0.0.0`, `PORT=3000`, and
`CODEX_SECURITY_STATE_DIR=/state`.

Stop with `docker compose -f compose.findings.yaml down`. Add `--volumes` only
when you intend to delete the stored data. For source builds or older deployments,
see the [container guide](https://github.com/openai/codex-security/blob/main/docker/README.md).

## Credentials and embeddings

Compose reads the embedding credentials and endpoint from `.env` or the host
environment. For a service started outside Docker, export any of these settings:

| Setting                         | Purpose                                                                                                                                            |
| ------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| `OPENAI_API_KEY`                | API key for embeddings; takes precedence over `CODEX_API_KEY`.                                                                                     |
| `CODEX_API_KEY`                 | Alternative embedding API key. Remove `OPENAI_API_KEY` when using it.                                                                              |
| `CODEX_SECURITY_EMBEDDINGS_URL` | Full embeddings endpoint URL, including its path and any query parameters. Defaults to `https://api.openai.com/v1/embeddings` when unset or empty. |
| `CODEX_SECURITY_STATE_DIR`      | State directory containing `workbench.sqlite3`; Compose uses `/state`.                                                                             |
| `HOST` / `PORT`                 | Listen address and port; outside Compose, defaults are `127.0.0.1` and `3000`.                                                                     |

Exported values override Compose's `.env` values. The repository excludes `.env`
from Git and Docker builds. Startup, listing, duplicate-group operations, and
empty imports need no embedding key. A Codex ChatGPT login cannot supply
embedding API credentials.

The endpoint receives the complete finding JSON and the API key as a bearer
token. It must support the OpenAI embeddings request and response format. For
example, to use a compatible endpoint outside Docker:

```bash
CODEX_SECURITY_EMBEDDINGS_URL=https://embeddings.example.com/v1/embeddings codex-security serve
```

The service uses `text-embedding-3-large` with 1,536 dimensions. It tokenizes
the complete JSON with `cl100k_base`, splits long inputs without truncation,
then combines the vectors by token weight and normalizes them. Requests observe
the provider's 8,192-token input, 300,000-token request, and 2,048-input limits.

## Publish a scan

Send a completed scan to the service:

```bash
codex-security publish scan --scan SCAN_ID --to custom \
  --findings-url http://localhost:3000 --json
```

`--findings-url` is required. The client appends `/v1/bulk/findings` to this
base URL, preserving any base path. Custom endpoints must implement that API
and return the stored finding IDs.

Publication sends the complete sealed findings and the manifest's
`scan.target.targetId` as `repositoryId`. It leaves the scan artifacts unchanged
and does not forward model credentials. The service creates embeddings and
commits the batch before acknowledging it.

Use `--scan` for a saved scan, `--scan-dir` for an external scan directory, or
the interactive picker. Custom publication accepts one scan; CSV input and
Linear options do not apply. Add `--dry-run` to preview the payload without an
HTTP request. Upload failures and incomplete receipts fail the command. Uploads
are not automatically retried because a lost response may have been committed.

```typescript
import { publishScanToCustom } from "@openai/codex-security";

const receipt = await publishScanToCustom("/path/to/completed-scan", {
  findingsUrl: "http://localhost:3000",
  // dryRun: true,
  // signal: controller.signal,
});
console.log(receipt.repositoryId, receipt.findingIds);
```

## HTTP API

Both POST endpoints require `Content-Type: application/json`; charset parameters
are accepted. Other or missing content types return HTTP 400 before embedding
or storage.

| Method | Path                                    | Response                                                                |
| ------ | --------------------------------------- | ----------------------------------------------------------------------- |
| `POST` | `/v1/bulk/findings`                     | HTTP 201; stored finding IDs in request order.                          |
| `GET`  | `/v1/findings?limit=50&offset=0`        | HTTP 200; a page of complete findings.                                  |
| `GET`  | `/v1/finding/{id}/potential-duplicates` | HTTP 200; the anchor finding and up to 50 candidates. Requires a scope. |
| `POST` | `/v1/dedupe-groups`                     | HTTP 201; persisted duplicate groups.                                   |
| `GET`  | `/v1/finding/{id}/dedupe-groups`        | HTTP 200; every group containing the finding.                           |
| `GET`  | `/v1/dashboard`                         | HTTP 200; counts, repository choices, records, and optional details.    |

### Import findings

`POST /v1/bulk/findings` accepts `{"findings": [...]}` using the SDK `Finding`
model, including `findingId`, `occurrenceId`, and `fingerprints`. A complete
exported `findings.json` document is also accepted; only its `findings` array is
imported. The service does not open files or source paths referenced by a finding.

Include `repositoryId` beside `findings` to associate every imported finding
with that repository. For SDK/CLI scans, use `scan.target.targetId` from
`scan-manifest.json`. IDs match exactly; the service does not infer them from
titles, paths, or URLs. Reimports add associations without removing earlier ones.
Findings imported without an ID are available only to all-repository candidate
searches until imported with an association.

Add `repositoryId` to a copy of the export, leaving the sealed artifacts intact:

```bash
curl http://127.0.0.1:3000/v1/bulk/findings \
  -H 'Content-Type: application/json' \
  --data-binary @findings-import.json
```

The response is an array such as `["csf_852f90d6e1177502ff113d4a"]`.

A batch is atomic: failed embedding generation or an identity conflict writes
none of it. Reusing a `findingId` updates its document and embedding without
creating another row. It cannot replace the existing fingerprint, rule, or
identity anchor/instance. Repeated IDs in one request are applied in order;
the last record remains. Stored scan occurrences are unchanged.

### List findings

Listing defaults to `limit=50` and `offset=0`. `limit` must be a positive integer
and `offset` a non-negative integer. Results sort by first insertion time, then
finding ID. Follow `nextOffset` until it is `null`:

```json
{
  "findings": [],
  "limit": 50,
  "offset": 0,
  "total": 0,
  "nextOffset": null
}
```

The list includes imports and complete documents from existing CLI scan history,
using the latest document for each ID. Legacy identities without complete
documents are omitted. Responses exclude embedding vectors. Separate requests
reflect the current database rather than one shared snapshot.

### Find potential duplicates

Choose exactly one scope:

```text
GET /v1/finding/{id}/potential-duplicates?repositoryId=target_sha256_example
GET /v1/finding/{id}/potential-duplicates?allRepositories=true
```

Repository scope requires both the anchor and candidates to belong to that
repository. All-repository scope includes associated and unassociated findings.
Missing or combined scopes return HTTP 400. Scope filters candidates; it does
not control access.

The response contains `finding` and `potentialDuplicates`, both using complete
`Finding` records without vectors. The candidates exclude the anchor, have cosine
similarity of at least 0.55, and use the same embedding model and dimensions.
Up to 50 are returned in descending similarity order, with ties resolved by
insertion time and finding ID. Each request uses a consistent read snapshot.
The service retrieves candidates; model review decides whether they are duplicates.

### Store duplicate groups

`POST /v1/dedupe-groups` accepts reviewed member sets:

```json
{
  "groups": [
    ["csf_000000000000000000000001", "csf_000000000000000000000002"],
    ["csf_000000000000000000000002", "csf_000000000000000000000003"]
  ]
}
```

Each group needs at least two distinct, existing finding IDs. A missing member
returns HTTP 409 and writes none of the batch. The response contains `groupId`,
`findingIds`, and `createdAt` for each group. Resubmitting the same membership
in any order returns the original ID and timestamp.

Overlapping groups stay separate; the service does not infer a larger group.
Stored members sort by ID and do not designate a canonical finding.
`GET /v1/finding/{id}/dedupe-groups` returns full membership for every containing
group, or `[]`. These associations do not rewrite findings, fingerprints,
artifacts, embeddings, or tickets, and require no model calls or embedding key.

### API errors

Errors contain an `error` code and, for expected failures, a `message`.

| HTTP status | Code                    | Meaning                                                                                |
| ----------- | ----------------------- | -------------------------------------------------------------------------------------- |
| 400         | `invalid_request`       | Invalid JSON, finding, repository metadata, group, scope, pagination, or content type. |
| 409         | `finding_conflict`      | Conflicting identity or missing group member.                                          |
| 502         | `embedding_failed`      | Embedding provider failure or unusable vectors.                                        |
| 503         | `embedding_unavailable` | Missing embedding credentials.                                                         |
| 404         | `finding_not_indexed`   | The anchor has no current embedding in the requested repository scope.                 |
| 404         | `not_found`             | Unknown route.                                                                         |
| 500         | `internal_error`        | Unexpected server failure.                                                             |

For `finding_not_indexed`, import the finding with the matching `repositoryId`
before retrying. Updating a document can invalidate its earlier embedding.
This error does not mean that the finding has no duplicates.

## Browse the dashboard

The dashboard has Findings and Duplicate groups views with search, repository
filters, sorting, pagination, and record details. Click a column header to sort
all matching records; click again to reverse it. It refreshes every five seconds,
keeping the selected order and the last successful data if a refresh fails.

It reads only the service database, not local source files or scan directories.
It displays no remote scan or workflow history and cannot modify findings or
start scans, publication, or deduplication.

`GET /v1/dashboard` accepts:

| Parameter             | Values and defaults                                                                                  |
| --------------------- | ---------------------------------------------------------------------------------------------------- |
| `view`                | `findings` (default) or `groups`.                                                                    |
| `query`, `repository` | Search text and exact repository ID.                                                                 |
| `sort`                | `activity` (default), `newest`, `title`, `repository`, `severity` (findings), or `members` (groups). |
| `direction`           | `asc` or `desc` (default).                                                                           |
| `limit`, `offset`     | Positive limit and non-negative offset; defaults are 50 and 0.                                       |
| `id`                  | Record ID to include in `detail`; an unknown ID returns `detail: null`.                              |

Overview counts cover the whole service, regardless of filters. The default
order is last update descending, then severity descending for findings, then ID
ascending. Search compares uppercase JavaScript strings; text sorts compare
lowercase strings. Severity and member counts use their natural order. The
dashboard uses the same unauthenticated endpoint as the API.

### Migrating direct Python helper calls

The Python `workbench_db.py` commands listed below have been retired. Direct
helper callers can use the existing Node helpers from an installed plugin
directory. For example:

```bash
scripts/launch_codex_security_mcp --helper dashboard < dashboard-request.json
```

On Windows, use `scripts\launch_codex_security_mcp.cmd --helper dashboard` with
the same JSON on stdin. The request wraps the dashboard query in `payload` and
specifies the absolute directory containing the existing `workbench.sqlite3`:

```json
{
  "stateDirectory": "/absolute/path/to/state",
  "payload": {
    "view": "findings",
    "sort": "activity",
    "limit": 50,
    "offset": 0
  }
}
```

Use an absolute Windows path on Windows. The SDK, service API, and
`codex-security` CLI already use the Node implementation and need no changes.

Use the same command name after `--helper`, with these fields in `payload`:

| Command                     | Payload fields                                                                                    |
| --------------------------- | ------------------------------------------------------------------------------------------------- |
| `dashboard`                 | The dashboard query shown above; optional `direction`, `query`, `repository`, and `id`.           |
| `store-findings`            | `entries` containing finding and embedding records; optional `repositoryId`.                      |
| `list-stored-findings`      | Positive integer `limit` and non-negative integer `offset`.                                       |
| `find-potential-duplicates` | `findingId` and `scope`: either `{"repositoryId":"REPOSITORY_ID"}` or `{"allRepositories":true}`. |
| `store-dedupe-groups`       | `groups`, an array of finding-ID arrays.                                                          |
| `list-dedupe-groups`        | `findingId`.                                                                                      |

Pagination and finding/repository selectors move from Python command flags into
these JSON fields. Retained scan commands such as `workbench_db.py list-findings`
keep their existing interface.

## Deduplicate a scan

Saved-scan deduplication uses local SQLite by default. No findings service or
publication step is required:

```bash
codex-security dedupe --scan SCAN_ID --json
```

The CLI prepares missing or stale embeddings for the local repository's stored
findings, searches them, and saves reviewed duplicate groups in the workbench
database. Local vectors are stored separately from findings-service vectors,
even when both use the same database. Repeated runs reuse compatible vectors.
Ordinary scans do not generate
embeddings automatically. New embeddings still send complete finding JSON to
the configured embeddings endpoint and require `OPENAI_API_KEY` or `CODEX_API_KEY`
on the CLI host; ChatGPT login alone is insufficient. Cached vectors avoid those
requests, but fresh duplicate reviews still need the configured model provider.

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
codex-security dedupe --scan SCAN_ID --findings-url http://127.0.0.1:3000 --json
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

`--workflow-id` also works locally and saves review checkpoints and group-write
retries without running a publication stage. A workflow remains bound to its
original local database or remote URL; use a new workflow ID to switch backends
or review changed inputs. Completed workflow results describe that run, not
findings added afterward. Cancellation can retain completed embedding preparation
for retry; it does not change sealed scan artifacts.

```typescript
import { deduplicateScan } from "@openai/codex-security";

const result = await deduplicateScan("scan_example_001", {
  // findingsUrl: "http://127.0.0.1:3000", // Optional remote corpus.
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
  findingsUrl: "http://127.0.0.1:3000",
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
change it; use 1 for serial execution. Candidate retrieval uses that limit, and
screenings and ready pair reviews share one worker pool. Results are combined
in input order, independent of completion order.

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
sent to another model. If candidate retrieval or review still fails, queued jobs
stop and running jobs finish before the operation fails without posting groups.
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

Use one workflow ID across scanning, custom publication, and deduplication:

```bash
codex-security scan /path/to/repository --workflow-id run-001
codex-security publish scan --workflow-id run-001 --to custom --findings-url http://localhost:3000
codex-security dedupe --workflow-id run-001 --findings-url http://localhost:3000 --json
```

The SDK equivalents are `workflowId` on `ScanOptions`,
`PublishScanToCustomOptions`, and `DeduplicateScanOptions`. Repeat the sequence
with the same ID after an interruption. Completed scans, acknowledged uploads,
and validated reviews are reused. This resumes completed stages, not model
turns inside an unfinished scan. Normal output-directory checks still apply.

A workflow can begin by publishing an existing completed scan. Publication and
dedupe can use its ID instead of `--scan`; an explicit scan must match. Dedupe
completes publication if its receipt is missing. Changing the bound scan,
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

## Storage, upgrades, and backups

Storage initializes before the server listens. The service uses the workbench
SQLite database at `$CODEX_SECURITY_STATE_DIR/workbench.sqlite3`; startup applies
append-only migrations and retains existing finding identities and scan history.
Changing a stored document invalidates its old embedding. Historical findings
are not embedded automatically; import them through the bulk endpoint first.

Before an upgrade, read the release notes, stop the service, and back up all of
`/state`:

```bash
docker compose -f compose.findings.yaml stop findings
mkdir -p backups
chmod 700 backups
docker compose -f compose.findings.yaml run --rm --no-deps --user 0:0 \
  --entrypoint tar -T findings -C /state -czf - . > backups/findings-state.tgz
chmod 600 backups/findings-state.tgz
```

Keep backups separately. This overwrites an existing backup of the same name.
Set `CODEX_SECURITY_FINDINGS_IMAGE` to the new version or digest, then pull and
start it while retaining the volume. To roll back, stop the service, restore
the pre-upgrade backup, and select the previous image digest. Older images may
not support the migrated database.

## Run without Docker

With the package's supported Node.js version installed (22.13 or later in a supported major):

```bash
npm install -g @openai/codex-security
CODEX_SECURITY_STATE_DIR="$HOME/.codex-security-findings" codex-security serve --port 3000
```

`--port` overrides `PORT`. The service does not load `.env`; export the embedding
key before importing findings. Without a state override, it shares the CLI's
default state directory. `HOST`, `PORT`, and `CODEX_SECURITY_STATE_DIR` also
work on Windows. The findings service uses Node’s built-in SQLite and does not
require Python. Stop with Ctrl-C or SIGTERM.

For source builds, prepare the
[universal native payload](https://github.com/openai/codex-security/blob/main/plugins/codex-security/native/README.md#package-inputs),
then run from `sdk/typescript`:

```bash
pnpm install --frozen-lockfile
pnpm --dir ../../plugins/codex-security/mcp-app install --frozen-lockfile
pnpm run build:plugin
pnpm run build
node bin/codex-security.mjs serve --port 3000
```

`pnpm run start:server` and `node dist/server/index.js` also start the service.

For renewable embedding credentials, import `OpenAiFindingEmbedder`,
`SqliteFindingsStore`, and `startFindingsServer` from
`@openai/codex-security/server`. The embedder accepts a static key or a callback
`() => string | Promise<string>` as its first argument. It calls the callback
before every HTTP batch; the caller handles token acquisition. Pass `fetch` as
the second argument and the full endpoint URL as the third; omitting the URL
uses the OpenAI endpoint. `startFindingsServer({ store, embeddings, host, port })`
returns a Node HTTP server. Importing the module does not start a listener.
