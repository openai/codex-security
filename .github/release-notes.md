<!-- release-version: 0.1.25 -->

## Highlights

- Preserve confirmed finding identities across scans and comparisons, and show
  related findings with their reasons while keeping distinct findings separate.
  Large comparisons now use bounded batches without truncating finding text;
  inputs that cannot fit leave matching explicitly incomplete.
- Improve deduplication with separate screening and pair reviews, validated
  pair assignments, and groups that respect explicit `DISTINCT` decisions.
  Invalid submissions receive one corrective turn; blocked reviews fail without
  recording a verdict. `DeduplicationReviewError` exposes structured, sanitized
  failure details. The SDK also adds `deduplicateScanDirectory` for complete,
  sealed scans outside local history.
- Generate synthetic Standard scan results with `scan --mock` or the SDK's
  `mock: true`, without authentication or model calls. Mock results support
  normal reports, exports, history, and reruns. See
  [mock scans](https://github.com/openai/codex-security/blob/npm-v0.1.25/sdk/typescript/README.md#generate-mock-scan-results).
- Increase a running scan's total budget from the interactive dashboard when
  usage reaches 80% of its limit, or use the SDK's `onBudgetApproaching`
  callback. The existing limit remains enforced until an increase is saved.
  See [scan cost limits](https://github.com/openai/codex-security/blob/npm-v0.1.25/sdk/typescript/README.md#progress-and-cost).
- Recognize existing Codex authentication in CLI and SDK login status. SDK
  scans, comparisons, and deduplication reviews now honor native command-auth
  providers, including renewable tokens.
- Configure the findings service's full embeddings endpoint with
  `CODEX_SECURITY_EMBEDDINGS_URL`. The new `@openai/codex-security/server`
  exports support embedding credentials supplied by a callback before each
  HTTP batch. See
  [embeddings and storage](https://github.com/openai/codex-security/blob/npm-v0.1.25/sdk/typescript/README.md#embeddings-and-storage).
- Include PowerShell module (`.psm1`) and data (`.psd1`) files in scan
  inventories, and recognize BOM-marked UTF-16 source files as text.
- Preserve scoped scan and component-plan inventories after directory renames
  that change only letter casing on case-insensitive filesystems.
- Support long Codex executable paths on Windows, including nested Deep Scan
  workers, and retry credential snapshots for another `Get-Acl` path-not-found
  race when a descendant disappears during inspection.
- Honor case-insensitive Windows environment variable names during finding
  deduplication, so configured API credentials and private configuration paths
  are used consistently.
- Stream tracked binary diffs when hashing repository snapshots, reducing
  memory use while preserving the existing digest format.
- Include complete OCI metadata in container image labels and multiarchitecture
  annotations, with documentation pinned to the source commit and image
  verification commands in the release workflow summary. See
  [container metadata and verification](https://github.com/openai/codex-security/blob/npm-v0.1.25/docker/README.md#image-metadata-and-verification).

## Upgrade notes

- Mock mode is opt-in and saves clearly marked synthetic findings in local
  history; use a separate `CODEX_SECURITY_STATE_DIR` for disposable test data.
  It supports Standard scans only and does not audit the repository.
- Interactive budget increases are unavailable in CI, JSON/JSONL, headless,
  and verbose modes. Existing cost limits continue to apply in those modes.
- The embeddings URL defaults to the existing OpenAI endpoint. A configured
  endpoint receives finding inputs and the bearer credential and must support
  the OpenAI embeddings format. Embeddings credentials remain separate from
  Codex ChatGPT sign-in.
- Local history applies an automatic database index migration. Completed scan
  artifacts remain unchanged.
- Source builds now use repository-pinned pnpm 11.19.0, including MCP app
  dependencies, whose configuration requires a seven-day minimum release age.
  From the repository root, run
  `pnpm --dir plugins/codex-security/mcp-app install --frozen-lockfile`.
  See
  [running without Docker](https://github.com/openai/codex-security/blob/npm-v0.1.25/sdk/typescript/README.md#running-without-docker).
- Container publication remains separate from npm publication. Existing stable
  container tags are not updated in place.

Build and CI updates also improve package verification, portable Python checks,
Windows fixtures, and test scheduling. Documentation clarifies portable
environment-variable guidance and safe examples.

The categorized list below contains the individual changes.
