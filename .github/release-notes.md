<!-- release-version: 0.4.0 -->

<!-- release-section: highlights:start -->

## Highlights

Codex Security 0.4.0 adds hosted Standard scan execution and improves token
accounting, bulk-scan recovery, and report formatting. The minor version marks
the removal of obsolete ranking helpers; direct helper users should follow the
migration guidance below.

- Hosts can run Standard repository or path scans through the TypeScript
  `runHostedScan(input, { executor, signal, onEvent })` API or the
  `codex-security scan --host` JSON-RPC adapter. Hosted execution is opt-in and
  requires a host-provided executor, frozen checkout, and explicit model and
  storage settings. Hosts own authorization, cancellation, and durable execution
  state. See the [hosted scan guide](https://github.com/openai/codex-security/blob/npm-v0.4.0/sdk/typescript/docs/hosted-scans.md).
  ([#1559](https://github.com/openai/codex-security/pull/1559))
- Scan token totals include recorded usage from earlier Deep Scan worker
  attempts and context compaction without counting resumed history twice.
  The SDK and compatible hosts can finish accounting for the final response
  after report generation. Missing records remain marked incomplete or
  unavailable rather than being presented as an exact total.
  ([#1657](https://github.com/openai/codex-security/pull/1657))
- Bulk scans preserve successful results and original scan failures when
  temporary-checkout cleanup fails. Cleanup errors are reported separately, and
  reusing a completed scan can retry its recorded cleanup without another scan.
  ([#1433](https://github.com/openai/codex-security/pull/1433))
- Reports render malformed evidence ranges as a valid single line or just the
  path. Finding text beginning with tilde fences or parenthesized list markers
  no longer changes the formatting of surrounding report sections. These fixes
  preserve the underlying findings.
  ([#1656](https://github.com/openai/codex-security/pull/1656),
  [#1604](https://github.com/openai/codex-security/pull/1604))
- The package includes Codex CLI/SDK 0.163.0 and restores the **Codex Security**
  display name in plugin listings, prompts, and tool labels. The npm package
  remains `@openai/codex-security`, with the `cs` and `codex-security` commands.
  ([#1670](https://github.com/openai/codex-security/pull/1670),
  [#1681](https://github.com/openai/codex-security/pull/1681))

<!-- release-section: highlights:end -->

<!-- release-section: upgrades:start -->

## Upgrade notes

### Scripts and custom workflows that invoke ranking helpers

The following plugin helper commands are removed:

- `make-repo-rank-input` and `select-deep-review-input`
- `make-rank-shards`, `validate-rank-shard`, and `merge-rank-outputs`
- `make-rank-pool-plan`, `validate-rank-worker`, and `validate-rank-pool`

Remove the ranking, shard/pool scheduling, and ranked-selection stages from
custom workflows. Generate the scoped inventory and review every selected file:

1. For explicit repository scopes, use
   `scripts/generate_rank_input.py make-repo-scope-input --repo <repo_root> --scopes-file <scopes_json> --out <output_jsonl>`
   with your Python interpreter and the script from the installed plugin.
   The scopes file is a JSON array, such as `["src", "tests"]`; use `["."]`
   for the whole repository instead of the old default `--scope .`.
   Output rows contain only `path`, for example `{"path":"src/example.ts"}`.
   Update your consumer to resolve each path against the repository root and
   read that file directly. If it requires a `path`/`area` review worklist,
   convert every row to `{"path":"src/example.ts","area":"repository"}`.
   This inventory contains no `area` or `preview` fields and cannot be passed
   directly to `copy-deep-review-input`.
2. For Git diffs, retain `make-diff-rank-input` with its existing revision or
   local-patch arguments. Copy all candidate rows into the review worklist with
   `scripts/launch_codex_security_mcp --helper copy-deep-review-input --rank-input <input_jsonl> --out <review_jsonl>`.
   On Windows, use the `.cmd` launcher.
3. Review the entire resulting worklist instead of selecting a ranked subset.
   `bind-repo-scopes` and the retained diff helpers keep their existing
   arguments and worklist formats.

See the [scoped review reference](https://github.com/openai/codex-security/blob/npm-v0.4.0/plugins/codex-security/skills/security-scan/references/scan-artifacts-and-ledger.md#scoped-deep-review)
for commands, scope inputs, and Windows invocation details.
([#1607](https://github.com/openai/codex-security/pull/1607))

Normal CLI and SDK scans do not need this helper migration. Hosted execution is
opt-in; existing local scans continue to use their current execution path.

<!-- release-section: upgrades:end -->
