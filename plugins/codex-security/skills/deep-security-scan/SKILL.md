---
name: deep-security-scan
description: Run repeated Standard security scans of a repository or scoped path when the user requests a deep, exhaustive, or multi-pass audit. For changes to a PR, commit, branch or working tree, use security-diff-scan.
---

# Deep Security Scan

The host runs Standard audits and merges their findings. Later passes receive the titles and locations already reported. The host stops when consecutive audits add nothing new or the configured scan or time limit is reached. Its final report includes every accepted audit.

1. Resolve the authorized target and scope. For a scoped directory use that directory as `targetPath` and `scope: "."`. For a continuation, call `get_codex_security_scan_context` with its `scanId` and supplied `handoffClaimToken`. Use the saved identity, scope and mode. Follow `../../references/scan-prologue.md` for source access and context updates.
2. For a new target, call `inspect_codex_security_setup({ targetPath, scope: ".", mode: "deep", projectConfigPath? })`. Show the effective settings and their sources. `max_discovery_runs` caps the total number of Standard scans, including when several run together. Pass a project file only when the user selected it. Existing scans use their saved configuration.
3. For a newly launched native scan, inspect `otherRunningDeepScans` once. If another Deep scan is active, show its target, phase and human-friendly start time. Explain the additional CPU, memory and token use. Offer **Cancel (Recommended)** and **Continue** using `request_user_input`, then `request_codex_security_user_input` or plain chat if unavailable. Wait for an explicit choice. A dismissed dialog is not a cancellation. Cancel only the new scan if requested.
4. Follow `../../references/access-advisory.md`, then call `start_codex_security_deep_scan` with the existing scan ID and claim token, or with the new target, scope, exact user context and selected project file. Await the tool. If the tool runner returns a running cell ID, wait on that cell until it returns the scan result. If the connection closes, rejoin with the same arguments. Report a terminal failure with its saved results. On explicit cancellation call `cancel_codex_security_scan`.
5. For an SDK-owned scan, return the host's scan ID and manifest path so the SDK can finalize it. When the tool returns `completion`, link its generated `report.md` and canonical artifacts and report measured usage per `../../references/final-report.md`. Distinguish a completed audit with zero findings from a deadline reached before any audit completed.
