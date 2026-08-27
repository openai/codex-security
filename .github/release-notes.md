<!-- release-version: 0.1.21 -->

## Highlights

- Request an advisory assessment of a completed patch with
  `patch --assess-patch-risk`. Add `--create-pr` to include its concise summary
  in the draft pull request. The assessment is opt-in and does not approve or
  merge changes. See
  [patching and risk assessment](https://github.com/openai/codex-security/blob/npm-v0.1.21/sdk/typescript/README.md#validate-and-patch-findings).
- Import GitHub code scanning alerts through the CLI or SDK for validation
  against a local checkout. Imports are read-only and preserve the upstream
  alert context. See
  [GitHub alert imports](https://github.com/openai/codex-security/blob/npm-v0.1.21/sdk/typescript/README.md#import-github-code-scanning-alerts).
- Publish findings from CSV with `publish scan --to cloud --csv PATH`, or
  preview the upload without signing in or sending data with `--dry-run`.
  See
  [Cloud publication](https://github.com/openai/codex-security/blob/npm-v0.1.21/sdk/typescript/README.md#publish-findings-to-cloud).
- Improve repeated-scan credential handling on Windows, sign-in recovery
  messages, cleanup after interrupted publication, and refreshes of changed
  bundled plugins.

## Upgrade notes

- Finish operations using older versions before upgrading; credential-home
  locks now follow the owning process's lifetime. See
  [authentication](https://github.com/openai/codex-security/blob/npm-v0.1.21/sdk/typescript/README.md#authentication).
- The bundled Codex runtime and SDK are now `0.149.1`. Custom executables
  selected with `CODEX_CLI_PATH` need thread-source attribution support for
  both `exec` and `app-server` (Codex `0.149.1+`). See
  [runtime configuration](https://github.com/openai/codex-security/blob/npm-v0.1.21/sdk/typescript/README.md#environment-variables).
- Existing Windows state with invalid ancestor permissions is not repaired
  automatically. Keep the old reports and select a new private state
  directory as described in
  [scan history and recovery](https://github.com/openai/codex-security/blob/npm-v0.1.21/sdk/typescript/README.md#scan-history-and-reruns).

The categorized list below contains the individual changes.
