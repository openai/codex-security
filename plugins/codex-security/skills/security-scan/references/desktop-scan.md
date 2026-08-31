# Codex Desktop Standard Scan

Read this reference only after the host explicitly identifies itself as the Codex desktop app. Listed tools alone do not establish a desktop host.

## Resolve The Authoritative Scan

Resolve the target, requested scope, and user-provided security context before starting the scan.

- If the request already includes a `scanId`, call `get_codex_security_scan_context`, passing `handoffClaimToken` when provided, and continue that existing scan.
- Otherwise call `start_codex_security_prompt_only_scan` once with `mode: "standard"`, `targetPath`, `scope`, and any exact `userContext`. Require its authoritative `scan.scanId` and `scan.scanDir`; preserve its handoff token when provided.
- If the direct start fails or returns malformed context, surface that error. Do not invent scan ownership, start a replacement scan, open setup, or switch to a terminal workflow.

Use the returned `scanId`, `scanDir`, scope, and exact `userContext` throughout the parent workflow. Read `../../../references/desktop-config-preflight.md` and run capability preflight only after this authoritative context exists.

Use the existing desktop phase labels for work that actually occurs: threat mapping, investigation, parent-led validation, attack-path assessment, and report assembly. Preserve the authoritative scan ID and handoff token. Increase the investigator total before dispatching each newly discovered assignment; the concurrently running baseline is independent and does not inflate that total. Capture each completed, source-backed investigation as a real coverage surface before advancing its `review_receipts` progress count. Do not create separate receipt files. Advance later phase counts only after the corresponding finding or report artifact exists, and never invent counts, phase workers, or coverage.

## Complete The Same Scan

Save `complete: false` checkpoints as results arrive and validation decisions are made. Preserve pending candidates with their original evidence in `coverage.deferred`; they are not validated findings. When the audit finishes, record the final semantic scan draft once with `record_codex_security_scan_draft({ scanId, complete: true, handoffClaimToken?, scope?, threatModel?, findings, coverage })`. Supply the actual findings, source-backed coverage, and preserved threat model; let the workbench write the unsealed canonical artifacts and derive authoritative target, scope, coverage metadata, finding identities, and fingerprints.

Honor desktop handoff requirements for any per-finding write-ups before completion. After the semantic draft succeeds and all three canonical JSON files exist, call `complete_codex_security_scan` exactly once with the same authoritative scan ID and handoff token. Return only after completion succeeds and `report.md` exists, linking the generated report and canonical artifacts; retrieve the complete findings only when the user explicitly requests them. Include measured token usage when available and explicitly label partial or unavailable measurement.

For each reported finding, emit one `::code-comment{title="[<priority-label>] <title>" body="<explanation>" file="<absolute path>" start=<line> end=<line> priority=<priority-number> confidence=<0-to-1>}` review directive at its tightest `root_control` location, or the most relevant affected source location when no root control is identifiable. Map `critical`, `high`, `medium`, and `low` to `P0/0`, `P1/1`, `P2/2`, and `P3/3` respectively; keep its title and explanation consistent with the generated report.

If finalization fails, surface the exact error and preserve the durable scan for later continuation; do not retry completion in the same response, generate a replacement report, or claim success.
