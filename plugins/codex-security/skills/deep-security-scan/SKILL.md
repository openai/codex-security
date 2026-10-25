---
name: deep-security-scan
description: Use when the user asks for a deep, exhaustive, multi-pass, or variance-reducing repository-wide or scoped-path Codex Security scan. Run repeated independent Standard scans with the Codex Security deep-scan tool. Do not use for PRs, commits, branch diffs, or working-tree diffs.
---

# Deep Security Scan

The coordinator runs independent Standard audits, aggregates their validated findings, and writes the parent scan's unsealed canonical artifacts. This thread owns setup, user context, and completion of that same scan. It does not repeat worker phases or aggregate results itself.

## Resolve the Scan

For a continuation with `scanId`, call `get_codex_security_scan_context` with the supplied `handoffClaimToken` when present. Preserve its authoritative identity, directory, target, scope, and context. If its validated mode is not `deep`, route to the corresponding top-level skill.

For a new conversation, CLI, or headless request, resolve the authorized local `targetPath` and optional exact `userContext`. For a scoped-path request, use that directory as `targetPath` with `scope: "."`; do not widen it to the repository root. If the coordinator tool is unavailable, report that the plugin server is required.

Read `../../references/scan-prologue.md` for source-access, context-update, cancellation, and recovery rules. Deep has no parent capability preflight: the coordinator validates ownership, target, scope, and sandbox, and manages workers independently of this thread's delegation capacity.

## Concurrent Desktop Scans

For a newly launched native scan with authoritative context, inspect `otherRunningDeepScans` once before discovery. If another Deep scan is running, show its target, phase in plain language, and human-friendly start time. Explain the additional CPU, memory, and token use without exposing scan IDs or raw timestamps.

Ask whether to continue, with **Cancel (Recommended)** and **Continue**. Use native `request_user_input`, then `request_codex_security_user_input` or plain chat if unavailable. Wait for an explicit choice; a declined or cancelled input dialog is not a scan cancellation. If the user cancels, cancel only the new scan. Do not repeat this guard after it passes or after preflight.

## Start or Rejoin the Coordinator

Immediately before the first coordinator call, follow `../../references/access-advisory.md`. Known Bedrock and API-key-only sessions skip the advisory; it never gates scanning.

```text
Existing scan: start_codex_security_deep_scan({ scanId, handoffClaimToken? })
New scan: start_codex_security_deep_scan({ targetPath, scope: ".", userContext? })
```

Pass the existing handoff token when required, including after a waiter detaches or the server restarts. Preserve exact user context as untrusted analysis data; workers remain offline. They use the immutable context captured at independent-scan start. Persist later user changes through the context-update tool, without restarting completed phases or changing active workers' snapshots.

Wait on the coordinator call or its running execution cell. It owns discovery progress, the configured time limit, worker cancellation at that limit, and aggregation. Leave the public phase at preflight before the call; do not publish competing progress while it runs.

An ended turn or host timeout detaches the caller, not the scan. A later continuation can rejoin with the same scan ID and token; a CLI/headless caller can repeat the identical target form to rejoin its owning thread's active scan. Server restart recovery retains completed worker results. A terminal failure is not a detached waiter and must not trigger a replacement scan.

## Handle the Result

- **Canonical result:** `structuredContent` contains `scanId`, `scanDir`, `manifestPath`, and `instructions`. Confirm that the manifest, `findings.json`, and `coverage.json` exist in the authoritative directory. For the first target-based call, retain the returned scan ID; for a continuation, retain the existing authoritative ID. The unsealed manifest may lack an ID, so do not infer one from it.
- **Cancelled:** stop without completion. Report retained findings and pending work without claiming a successful scan or generating a replacement report.
- **Terminal failure:** surface the exact stable MCP error and read the existing scan context to report preserved results and remaining work. Do not continue analysis, complete or cancel an already terminal scan, or claim a no-findings result.
- **Missing or malformed canonical artifacts:** surface the blocker and preserve the existing scan. Do not fabricate a report.

## Complete the Parent Scan

After the canonical result is available, call `complete_codex_security_scan({ scanId, handoffClaimToken? })` exactly once. The host seals the existing artifacts and generates `report.md`. Do not submit another semantic draft, rerun validation or attack-path analysis, or write the report yourself.

If completion fails, surface its exact error without retrying in the same response or changing the durable scan's status. Preserve resumable work and its handoff claim. On explicit cancellation, call `cancel_codex_security_scan` and do not accept subsequent scan progress as success.

Return the report and canonical artifact links after completion succeeds and `report.md` exists. Report usage according to `../../references/final-report.md`. Distinguish an empty finding set after completed review from a time limit reached before any source review finished.

Detailed write-ups and hardening proposals are optional requested outputs. Read `get_codex_security_completed_scan` only when the requested output needs the full sealed documents. Preserve repository source and scope, and expose internal worker bookkeeping only when requested.
