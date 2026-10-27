<!-- release-version: 0.7.0 -->

<!-- release-section: highlights:start -->

## Highlights

Codex Security 0.7.0 adds optional post-scan validation and improves Deep Scan recovery, usage reporting, and saved results. Review the upgrade notes for changes to external imports, hosted verification, and direct helper integrations.

- **Post-scan validation.** Add `--validate` to run a supplemental validation pass after a scan and save a separate `validation.md` report. This pass makes additional model calls, leaves the saved findings and `--fail-on-severity` decision unchanged, and cannot be combined with `--max-cost`, a configured cost cap, `--dry-run`, or `--mock`. See [validation options](https://github.com/openai/codex-security/blob/npm-v0.7.0/sdk/typescript/docs/cli.md#follow-up-finding-validation).
- **Deep Scan recovery.** Deadline recovery retains unfinished checkpoints and worker coverage, retries keep selected results stable, and the CLI waits for the coordinator to finish before returning. Scan finalization preserves findings and honors project budgets.
- **Clearer usage and progress.** Scan output distinguishes file inventory from review progress and reports usage timestamps and account allowance. Large usage receipts, policy files, checkpoints, failure diagnostics, and reviewed feedback are retained.
- **Owner reports and saved results.** Scan owner reports are finalized without an extra model call. Saved findings remain consistent through recovery, SARIF exports retain run warnings, and report rendering preserves literal source paths and text.

<!-- release-section: highlights:end -->

<!-- release-section: upgrades:start -->

## Upgrade notes

- **External imports require opt-in.** Set `CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS=1` before using `publish findings`, `findings imported`, `import github-advisories`, or the corresponding SDK operations. Only the literal value `1` enables these features. SDK callers that supply `dependencies.environment` must include the flag there. Previously imported records are retained. See [external import setup](https://github.com/openai/codex-security/blob/npm-v0.7.0/sdk/typescript/docs/cli.md#import-vendor-findings-locally).
- **Hosted verification uses the CLI verdict contract.** Remove imports of `FindingVerificationCheck` and replace reads of `verification.checks` with `verification.status` and `verification.evidence`. The original executor report, when supplied, remains available in `execution.finalResponse`. Update custom executors to return the matching finding `id`, a status of `fixed`, `still_vulnerable`, or `inconclusive`, and nonempty evidence. See [the hosted remediation contract](https://github.com/openai/codex-security/blob/npm-v0.7.0/sdk/typescript/docs/hosted-remediation.md).
- **Direct inventory helper calls move to Node.** Integrations that invoke the removed Python inventory and ranking scripts must use the bundled launcher and its `--helper` commands below. SDK and MCP callers use the new implementation automatically; the inventory and ranking artifact formats are unchanged.
- **Committed-diff scans require a clean, full checkout.** Check out the requested head revision and commit or stash local changes before running a committed-diff scan, including with `--validate`. A mismatched checkout or local changes now fail before scanning. See [scan options](https://github.com/openai/codex-security/blob/npm-v0.7.0/sdk/typescript/docs/cli.md#scan-options-and-output).

<details>
<summary>Direct helper migration</summary>

Use `launch_codex_security_mcp` from the bundled plugin's `scripts` directory, or `launch_codex_security_mcp.cmd` on Windows, with the existing arguments after the helper name:

| Removed Python invocation | Launcher arguments |
| --- | --- |
| `generate_in_scope_files.py` | `--helper generate-in-scope-files` |
| `generate_rank_input.py make-repo-scope-input` | `--helper make-repo-scope-input` |
| `generate_rank_input.py make-diff-rank-input` | `--helper make-diff-rank-input` |

The removed `rank_preview.py` implementation is incorporated into these helpers. See [diff helper examples and Windows quoting](https://github.com/openai/codex-security/blob/npm-v0.7.0/plugins/codex-security/skills/security-scan/references/scan-artifacts-and-ledger.md).

</details>

<!-- release-section: upgrades:end -->
