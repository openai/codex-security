<!-- release-version: 0.8.0 -->

<!-- release-section: highlights:start -->

## Highlights

Codex Security 0.8.0 adds OpenGrep report imports and changes how scan results record scope and review details.

- **OpenGrep imports.** Import a native JSON or gzip-compressed report into the local workbench or publish it to Cloud with `publish findings --provider opengrep`. Supply `--source-repository-url` and enable external imports with `CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS=1`. Imported findings retain their scanner evidence and start as unassessed. See the [OpenGrep guide](https://github.com/openai/codex-security/blob/npm-v0.8.0/docs/scanner-imports/opengrep.md).
- **Scan recovery.** Resume an interrupted Deep Scan after clearing its additional instructions. Read a completed Workbench scan’s saved artifacts even after moving or removing the original checkout.

<!-- release-section: highlights:end -->

<!-- release-section: upgrades:start -->

## Upgrade notes

- **SDK and JSON consumers.** Replace reads of `ScanResult.coverage` or the serialized `coverage` field with `review` for comparison exclusions. Read scan mode and scope from `manifest.scan`. Integrations that write drafts should put reviewed surfaces, unfinished work, and open questions in `reviewState`.
- **Saved files and GitHub Actions.** New scans no longer write `coverage.json`. Replace `ScanResult.coveragePath` with `manifestPath` and read `scan.review` in `scan-manifest.json`. Workflows that read the Action’s `coverage-path` output should switch to `manifest-path`. The legacy output is empty for current scans. Existing saved scans remain readable. See [Action outputs](https://github.com/openai/codex-security/blob/npm-v0.8.0/github-action/README.md#outputs).

<!-- release-section: upgrades:end -->
