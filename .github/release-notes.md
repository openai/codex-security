<!-- release-version: 0.1.23 -->

## Highlights

- Store complete findings and embeddings in the preview findings service, with
  paginated listing, repository-scoped candidate retrieval, and durable duplicate
  groups. Publish a completed scan with
  `publish scan --to custom --scan SCAN_ID --findings-url URL`, or preview the
  payload with `--dry-run`. See the
  [findings service](https://github.com/openai/codex-security/blob/npm-v0.1.23/sdk/typescript/README.md#findings-service-preview)
  and [custom publication](https://github.com/openai/codex-security/blob/npm-v0.1.23/sdk/typescript/README.md#publishing-to-a-custom-findings-service).
- Review potential duplicates from the CLI or SDK with
  `dedupe --scan SCAN_ID --findings-url URL`. Reviews run on the calling host and save accepted groups
  without replacing original findings. Searches default to the scan's repository;
  `--all-repositories` explicitly broadens the scope. Add `--workflow-id` to scan,
  custom publication, and deduplication to reuse completed stages and checkpointed
  reviews after interruption. See
  [deduplication](https://github.com/openai/codex-security/blob/npm-v0.1.23/sdk/typescript/README.md#deduplication-from-the-sdk-and-cli)
  and [workflow recovery](https://github.com/openai/codex-security/blob/npm-v0.1.23/sdk/typescript/README.md#resuming-a-local-findings-workflow).
- Browse stored findings and duplicate groups in the service's read-only
  `/dashboard`, with search, repository filters, sorting, and record details.
  The dashboard shows service-owned data, not local scan or workflow history.
  See the [dashboard guide](https://github.com/openai/codex-security/blob/npm-v0.1.23/sdk/typescript/README.md#read-only-dashboard).
- Add a separate findings-service container release and a Compose runner for the
  existing scanner CLI, with persistent state and source mounts. Both images
  support Linux `amd64` and `arm64`. See
  [container releases and the workflow runner](https://github.com/openai/codex-security/blob/npm-v0.1.23/docker/README.md).
- Preserve sealed scan artifacts when optional follow-up instructions fail,
  propagate caller cancellation during cloud publication, respect the exact
  POSIX `PATH` when resolving trusted executables, and retain nested attack-path
  evidence strings in saved finding previews.

## Upgrade notes

- The findings API and dashboard have no built-in authentication. Keep the
  service on a trusted local endpoint or behind an authenticated TLS proxy;
  Compose publishes only to host loopback. Nonempty imports send complete finding
  JSON to the OpenAI embeddings API and require an API key. A ChatGPT login is not
  an embedding credential. Duplicate review uses the calling host's Codex
  credentials separately, and embedding and review calls can incur usage charges.
- Stop the findings service and back up its entire state directory before
  upgrading. Startup applies SQLite migrations automatically; rollback requires
  the pre-upgrade backup and previous image. Existing findings are not
  automatically embedded: import them with their repository ID before using
  repository-scoped deduplication. Keep runner state separate from service state.
  See [backups and upgrades](https://github.com/openai/codex-security/blob/npm-v0.1.23/sdk/typescript/README.md#upgrades-and-backups).
- Container publication is separate from npm publication. Use a version or digest
  only after the selected image release is available; source builds remain
  supported. Follow the [container setup](https://github.com/openai/codex-security/blob/npm-v0.1.23/docker/README.md#ghcr-administrator-setup)
  before the first registry release.
- Source checkouts now generate the SDK's bundled plugin from
  `plugins/codex-security`. Contributors should edit the canonical plugin source
  and run `pnpm run build:plugin`; the published npm package still includes the
  runtime payload. See [plugin source ownership](https://github.com/openai/codex-security/blob/npm-v0.1.23/sdk/typescript/TESTING.md).

The categorized list below contains the individual changes.
