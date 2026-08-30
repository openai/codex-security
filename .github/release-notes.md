<!-- release-version: 0.1.25 -->

## Highlights

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
- Include complete OCI metadata in container image labels and multiarchitecture
  annotations, with documentation pinned to the source commit and image
  verification commands in the release workflow summary. See
  [container metadata and verification](https://github.com/openai/codex-security/blob/npm-v0.1.25/docker/README.md#image-metadata-and-verification).

## Upgrade notes

- No new CLI flags, SDK options, or required application migrations are
  introduced.
- Source builds now use the repository-pinned pnpm for MCP app dependencies.
  From the repository root, run
  `pnpm --dir plugins/codex-security/mcp-app install --frozen-lockfile`.
  See
  [running without Docker](https://github.com/openai/codex-security/blob/npm-v0.1.25/sdk/typescript/README.md#running-without-docker).
- Container publication remains separate from npm publication. Existing stable
  container tags are not updated in place.

The categorized list below contains the individual changes.
