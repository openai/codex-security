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
| `PYTHON`                        | Python interpreter used by the storage adapter.                                                                                                    |

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
ascending. Text sorts ignore case; severity and member counts use their natural
order. The dashboard uses the same unauthenticated endpoint as the API.

## Deduplicate a scan

Publish the scan first, or import its findings with `repositoryId`. Then run:

```bash
codex-security dedupe --scan SCAN_ID --findings-url http://127.0.0.1:3000 --json
```

Both `--findings-url` and a scan or workflow selector are required. `--scan`
accepts a full ID, unique prefix, or `latest` for the current repository. The
scan must be complete, with sealed artifacts and a local checkout available.
By default, candidates come from its manifest's `scan.target.targetId`. Use
`--all-repositories` to search the whole service.

```typescript
import { deduplicateScan } from "@openai/codex-security";

const result = await deduplicateScan("scan_example_001", {
  findingsUrl: "http://127.0.0.1:3000",
  concurrency: 8,
  // allRepositories: true,
  // signal: controller.signal,
});
console.log(result.duplicateGroups);
```

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

Deduplication retrieves all candidate neighborhoods, screens them with
`gpt-5.6-luna` at `xhigh`, then independently reviews nominated pairs with
`gpt-5.6-sol` at `high`. A pair review can start after all screenings that cover
it finish without a `DISTINCT` decision. Accepted pairs form groups only when
no reviewed `DISTINCT` decision or refusal contradicts the group.

The default concurrency is 8. Set `--concurrency N` or SDK `concurrency: N` to
change it; use 1 for serial execution. Candidate retrieval uses that limit, and
screenings and ready pair reviews share one worker pool. Results are combined
in input order, independent of completion order.

Reviews run on the SDK/CLI host using its Codex sign-in or environment API key;
credentials are not sent to the findings service. Each review receives complete
original findings and may inspect the approved local checkout. Reviews preserve
severity and priority rather than reassessing them. The baseline filesystem is
read-only and excludes credentials and Codex state. Screening denies approval
requests; pair reviews use Codex's automatic approval reviewer. Web, plugins,
and inherited MCP servers are disabled. Finding content and linked tickets do
not authorize access to another target.

Models must submit a validated decision. A session that ends without one gets
one corrective turn. Invalid output and eligible transient failures can retry
in fresh sessions, up to three sessions per review. Transient service failures
allow up to three request attempts; HTTP retries honor `Retry-After`. Backoff
occupies the job's concurrency slot.

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

With the package's supported Node.js and Python versions installed:

```bash
npm install -g @openai/codex-security
CODEX_SECURITY_STATE_DIR="$HOME/.codex-security-findings" codex-security serve --port 3000
```

`--port` overrides `PORT`. The service does not load `.env`; export the embedding
key before importing findings. Without a state override, it shares the CLI's
default state directory. `HOST`, `PORT`, `CODEX_SECURITY_STATE_DIR`, and `PYTHON`
also work on Windows. Stop with Ctrl-C or SIGTERM.

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
