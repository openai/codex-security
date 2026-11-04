# Start or resume a managed Standard scan

Use the bound scan’s target, scope, user context, ID, directory and token for every update. If the handoff failed or identifies a different mode, stop before source review. Resume the saved phase. For an older handoff still in preflight, advance it to `threat_model` once.

If the host supplies a target-paths file without a prepared inventory, resolve it using [scoped paths](scoped-paths.md) before review.

## During review

Advance the current scan with `update_codex_security_scan_progress` at real forward transitions. Publish `discovery` before dispatch, `validation` before checking candidates, `attack_path` before reachability assessment, and `reporting` before final assembly. Keep the current phase when work overlaps. When bound, persist user-requested context changes through `update_codex_security_scan_context` with the complete replacement and token. Use the returned `structuredContent.scan.userContext` from each progress transition for that phase and its workers.

Increase the investigator total as new batch assignments are dispatched. Record completed investigations as coverage surfaces before advancing their `review_receipts` count. Advance other counts only when the corresponding work exists. Publish meaningful batches without creating receipt files.
