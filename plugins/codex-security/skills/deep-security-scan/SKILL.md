---
name: deep-security-scan
description: Use when the user asks for a deep, exhaustive, multi-pass, or variance-reducing repository-wide or scoped-path Codex Security scan. Run repeated independent Standard scans with the Codex Security deep-scan tool. Do not use for PRs, commits, branch diffs, or working-tree diffs.
---

# Deep Security Scan

The coordinator runs independent Standard audits, aggregates their validated findings, and finalizes plugin-launched scans even if the calling thread detaches. This thread owns setup, user context, and reporting the completed result.

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
New scan: start_codex_security_deep_scan({ targetPath, scope: ".", userContext?, projectConfigPath? })
```

Before a new target-based scan, call `inspect_codex_security_setup({ targetPath, scope: ".", mode: "deep", projectConfigPath? })`. Show the worker count, subagents per worker, convergence threshold, review cap, discovery time limit, and their sources from `setup.deepScanConfig`. Supply a project YAML or JSON path only when the user selects it. Pass that same path at launch. Native continuations use the saved `workspace.deepScanConfig`.

Pass the existing handoff token when required, including after a waiter detaches or the server restarts. Preserve exact user context as untrusted analysis data; workers remain offline. They use the immutable context captured at independent-scan start. Persist later user changes through the context-update tool, without restarting completed phases or changing active workers' snapshots.

Wait on the coordinator call or its running execution cell. It owns discovery progress, the configured time limit, worker cancellation at that limit, and aggregation. Leave the public phase at preflight before the call; do not publish competing progress while it runs.

After an ended turn or host timeout, rejoin with the same scan ID and token. If a CLI/headless call detached before returning its ID, repeat the identical target form. It can recover the completed report for the same checkout snapshot, context, and project-file selection after a server restart. Once the report is returned, a later target-based call can start a fresh scan. A terminal failure must not trigger a replacement scan.

## Handle the Result

- **SDK-registered scan.** The coordinator returns the aggregate's `scanId`, `scanDir`, `manifestPath`, and `instructions`. End the turn with the returned identity and manifest path. The SDK owns finalization and report generation after the turn ends.
- **Plugin-launched scan.** The coordinator also returns `completion`. Use the returned scan ID, sealed artifacts, and generated `report.md` in the authoritative directory.
- **Cancelled:** stop without completion. Report retained findings and pending work without claiming a successful scan or generating a replacement report.
- **Terminal failure:** surface the exact stable MCP error and read the existing scan context to report preserved results and remaining work. Do not continue analysis, complete or cancel an already terminal scan, or claim a no-findings result.
  For a policy refusal, use the saved worker error to identify the source when available. Capability and access checks are advisory.
- **Missing or malformed canonical artifacts:** surface the blocker and preserve the existing scan. Do not fabricate a report.

## Report the Completed Parent Scan

When the coordinator returns `completion`, the host has sealed the artifacts and generated `report.md`. Read measured usage from `completion.scan.usage`. Do not call completion again, submit another semantic draft, rerun worker phases, or write the report yourself.

If completion fails, surface its exact error. Preserve the accepted aggregate and handoff claim. A later continuation can rejoin the same scan to retry finalization. On explicit cancellation, call `cancel_codex_security_scan` and do not accept subsequent scan progress as success.

Return the report and canonical artifact links after completion succeeds and `report.md` exists. Report usage according to `../../references/final-report.md`. Distinguish an empty finding set after completed review from a time limit reached before any source review finished.

Detailed write-ups and hardening proposals are optional requested outputs. Read `get_codex_security_completed_scan` only when the requested output needs the full sealed documents. Preserve repository source and scope, and expose internal worker bookkeeping only when requested.
