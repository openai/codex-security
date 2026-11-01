# Codex Desktop Standard Scan

Load this reference only when the host identifies itself as the Codex desktop app; the listed tools alone do not establish that.

## Scan Context

Resolve the target, requested scope, and exact user context. Continue a supplied `scanId` through `get_codex_security_scan_context`, passing its `handoffClaimToken` when present. Otherwise call `start_codex_security_prompt_only_scan` once with `mode: "standard"`, `targetPath`, `scope`, and optional `userContext`.

Preserve the authoritative `scan.scanId`, `scan.scanDir`, scope, exact `userContext`, and handoff token. If startup fails or returns malformed context, report the error without creating a replacement scan, opening setup, or switching to a terminal workflow.

## Progress

Use `update_codex_security_scan_progress({ scanId, handoffClaimToken, phase })` at real phase transitions: `threat_model` before mapping security boundaries, `discovery` before investigation, `validation` before validation, `attack_path` before reachability assessment, and `reporting` before final draft assembly. Preserve the current phase when work overlaps; never move backward or repeat completed work. Use returned `scan.userContext` for the new phase and its workers.

Report meaningful completed-review batches. Increase the investigator total before dispatching a new assignment; the independent baseline auditor is not part of that total. Capture completed source-backed investigations as coverage surfaces before increasing `review_receipts`. Use actual findings and artifact completion for later counts, without extra receipt files.

Model-only checkpoints preserve the current phase. Checkpoints with findings or reviewed surfaces advance to at least `discovery`; a final draft advances to `reporting`. Publish earlier transitions when they occur.

## Completion and Review Comments

Use the parent skill's semantic checkpoint and completion workflow, including any host-required write-up handoff. Link the generated report and canonical artifacts after successful completion.

For each reported finding, emit one `::code-comment{title="[<priority-label>] <title>" body="<explanation>" file="<absolute path>" start=<line> end=<line> priority=<priority-number> confidence=<0-to-1>}` at the tightest root-control location, or the most relevant source location when no root control is identifiable. Map `critical`, `high`, `medium`, and `low` to `P0/0`, `P1/1`, `P2/2`, and `P3/3`. Keep comments consistent with the generated report.
