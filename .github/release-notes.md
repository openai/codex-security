<!-- release-version: 0.1.24 -->

## Highlights

- Start the preview findings service directly with
  `codex-security serve [--port PORT]`, without Docker or an internal package
  path. The command reuses the existing service, state, and shutdown behavior;
  `--port` overrides `PORT`, and port `0` selects a free port. See
  [running without Docker](https://github.com/openai/codex-security/blob/npm-v0.1.24/sdk/typescript/README.md#running-without-docker).
- Observe durable Deep Scan progress from the SDK with the optional
  `onDeepProgress({ completed, active, maximum })` callback. Updates report
  changed completed and active independent-review counts without blocking the
  scan. See
  [SDK scan options](https://github.com/openai/codex-security/blob/npm-v0.1.24/sdk/typescript/README.md#sdk-configuration-and-scan-options).
- Make stopped-result handling explicit and stable. Read, list, and export
  operations no longer publish late retained results as a side effect; the app
  reports when recovery is needed and can recover validated results on request.
  See
  [stopped result recovery](https://github.com/openai/codex-security/blob/npm-v0.1.24/plugins/codex-security/references/scan-contract.md#stopped-result-recovery).
- Include changed PowerShell `.ps1` files in diff-scan inventories and remove a
  conflicting reporting rule so valid internal attack paths remain eligible for
  review. Nested Deep Scan workers now also receive an explicitly configured
  OpenAI provider credential through the plugin's existing environment boundary.
- Improve Windows reliability by preserving case-insensitive `CODEX_HOME`
  entries and repository paths from ordinary PowerShell activity, and by
  retrying credential snapshots when a descendant file disappears during ACL
  inspection. Existing path-safety and permission failures remain fatal.

## Upgrade notes

- The findings API and dashboard still have no built-in authentication.
  `codex-security serve` binds to loopback by default; keep it local or place it
  behind an authenticated TLS proxy before sharing access. Python is still
  required, and nonempty imports still require an embeddings API credential.
- Stopped-scan recovery is now explicit. App clients should check
  `resultsRecoveryNeeded` and request recovery when they want validated late
  results republished. Canceled scans remain immutable and cannot use this
  recovery path.
- `onDeepProgress.maximum` is the configured independent-review cap, not a
  percentage denominator. The SDK polls the durable projection only when the
  callback is supplied.

The categorized list below contains the individual changes.
