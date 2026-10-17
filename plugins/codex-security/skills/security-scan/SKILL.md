---
name: security-scan
description: "Use for a standard, single-pass security audit of an entire repository or a scoped path, package, folder, or submodule with no diff to review. This is the default repository scan. Do not use for PR, commit, branch, or working-tree diffs, or for deep, multi-pass scans."
---

# Security Scan

Run one independent general audit while the parent maps the repository's security boundaries. Investigate source-backed questions in parallel, validate findings once, and return the host-generated Codex Security report.

## Host And Setup

For an explicitly identified desktop host, load `references/desktop-scan.md`. Otherwise run headlessly: preserve an SDK-provided `CODEX_SECURITY_SCAN_ID` and `CODEX_SECURITY_SCAN_DIR`, or obtain the authoritative scan through `start_codex_security_standard_scan`. If the required start tool is unavailable, report the blocker before reviewing source or creating canonical files. Do not open desktop setup from a headless host.

Read `../../references/scan-prologue.md` once after resolving authoritative scan context and follow its runtime-tool guidance. It defines scan ownership, context updates, source-access boundaries, and recovery.

SDK hosts supply their own progress instructions. Use actual deduplicated reviewed paths for completed counts and the scoped inventory or host estimate for totals. Do not create inventories or receipt files solely for progress.

## Workflow

1. Resolve the authorized target, scope, scan directory, and source context. Preserve the supplied threat model, applicable inherited `SECURITY.md` guidance, and optional `CODEX_SECURITY_KNOWLEDGE_BASE`. When `CODEX_SECURITY_TARGET_PATHS_FILE` is supplied, use the SDK's exact `make-repo-scope-input` command to resolve every requested file and non-ignored directory descendant before review. Pass the resulting inventory to the core audit without widening scope; do not print, modify, or evaluate the scope file.
2. Read `../../references/core-scan.md` and perform the audit within the resolved scope and configured limits. Retain its semantic `scope`, `threatModel`, `findings`, and `coverage`, including source evidence, validation, attack paths, calibrated severity/confidence, and unresolved work.
3. For a host-backed scan, save a `complete: false` semantic checkpoint as soon as the threat model is available, with no findings when none exist yet. Checkpoint new findings and decisions, then submit an accepted `complete: true` draft through `record_codex_security_scan_draft({ scanId, complete, handoffClaimToken?, scope?, threatModel, findings, coverage })`. Let the host derive authoritative metadata and identities. Preserve saved surface IDs and unfinished candidates; close completed generic tasks using `coverage.resolvedDeferred: [{ id, reason }]` with their saved IDs. Follow `../../references/final-report.md` for rejected drafts and interrupted writes, preserving the same scan. For an SDK-owned scan with a bound semantic draft tool, use it for the same early model checkpoint and later drafts. Without that tool, retain the model in an early unsealed canonical draft and update `scan-manifest.json`, `findings.json`, and `coverage.json` using `../../references/scan-contract.md` and the SDK's exact identity and directory. Omit `scan.sealedAt` and `scan.artifacts`. For requested scopes, use `scoped_path` for coverage mode and inventory strategy; otherwise use `repository` mode with `directory` strategy for non-Git targets and `repository` strategy for Git targets. On SDK file-authored paths, run the supplied scope-binding command when a target-paths file is present.
4. Verify all three canonical JSON files exist. Return control for an SDK-owned scan; the SDK owns finalization and report generation. For other host-backed scans, call `complete_codex_security_scan({ scanId, handoffClaimToken? })` once and return after it succeeds and `report.md` exists. If completion fails, surface its exact error and preserve the scan for continuation. Do not hand-author reports or reread complete canonical findings unless requested. Report complete measured token usage only; leave pending usage to the host and identify unavailable counts.

Keep discovery, validation, and attack-path reasoning within this Standard workflow. Do not invoke separate phase skills, Deep-only tools, ranking phases, or per-file/per-candidate ledgers. Once assigned review and concrete follow-ups are settled, finish the configured audit with honest limitations rather than waiting for unspecified worker updates.

## Windows Scope Binding

Use the SDK-supplied command when available. For another explicitly permitted file-authored invocation, replace the placeholders below with literal paths, doubling single quotes within them. Keep the supplied scope-file environment value unchanged:

```powershell
$env:scopePluginRoot = Convert-Path -LiteralPath '<plugin_dir>' -ErrorAction Stop
$env:scopeScanDir = Convert-Path -LiteralPath '<scan_dir>' -ErrorAction Stop
$env:scopeTargetPaths = Convert-Path -LiteralPath $env:CODEX_SECURITY_TARGET_PATHS_FILE -ErrorAction Stop
cmd.exe /d /v:off /s /c '""%scopePluginRoot%\scripts\launch_codex_security_mcp.cmd" --helper bind-repo-scopes --scopes-file "%scopeTargetPaths%" --manifest "%scopeScanDir%\scan-manifest.json" --coverage "%scopeScanDir%\coverage.json""'
```

These are temporary shell variables. Resolve paths against PowerShell's current location, including UNC shares. Missing paths stop the command. CMD expands these references once, preserving literal `%` and `!` in paths.
