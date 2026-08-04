---
name: security-scan
description: "Use for a standard, single-pass security audit of an entire repository or a scoped path, package, folder, or submodule with no diff to review. This is the default repository scan. Do not use for PR, commit, branch, or working-tree diffs, or for deep, multi-pass scans."
---

# Security Scan

Review every file in scope. Use one file list and one candidate ledger. Standard scans use the existing validation and attack-path reasoning in compact mode, without the ranking, queues, fan-out, or per-candidate reports used by deep scans.

## Setup And Preflight

The `claude-security` CLI has already registered this scan before your session started. Take the authoritative scan identity from the environment and never invent, re-derive, or widen any of it:

| Value | Environment variable |
| --- | --- |
| Repository root | `CLAUDE_SECURITY_REPOSITORY` |
| Scan directory | `CLAUDE_SECURITY_SCAN_DIR` |
| Scan ID | `CLAUDE_SECURITY_SCAN_ID` |
| Target ID | `CLAUDE_SECURITY_TARGET_ID` |
| Target kind | `CLAUDE_SECURITY_TARGET_KIND` |
| Plugin root | `CLAUDE_SECURITY_PLUGIN_ROOT` |
| Python interpreter | `PYTHON` |

There is no setup workspace and no scan-registration tool to call: this is always a headless run. Author `scan-manifest.json` as an unsealed draft with no `scan.sealedAt` and no `scan.artifacts`. The CLI seals the canonical artifacts, generates `report.md` and SARIF, and indexes findings after your session ends. Surface a missing or malformed environment value instead of inventing a path.

Run the `security_scan` preflight in `../../references/config-preflight.md` before reviewing the target. It is a read-only capability check; continue on its documented degraded path when a capability is unavailable rather than stopping the scan.

Resolve the shared paths in `../../references/scan-artifacts.md` and apply relevant `SECURITY.md` guidance. The scan is complete only after every file is accounted for, every candidate is decided, and the required JSON is complete.

## Standard Workflow

1. Run `claude-security:threat-model` or use the supplied threat model. Keep a copy under `<context_dir>/threat_model.md`.
2. Read `references/repository-wide-scan.md` and follow its standard procedure. It builds `<discovery_dir>/in_scope_files.txt`, reviews every file, and combines raw candidates into `<discovery_dir>/candidate_ledger.jsonl`.
3. Run `claude-security:validation` once over the combined ledger in compact standard-scan mode. Validate every candidate and add one concise `validation` record to each ledger row. Preserve the candidate id, locations, instance, and discovery evidence.
4. Run `claude-security:attack-path-analysis` once in compact standard-scan mode over candidates whose validation disposition is `reportable` or `deferred`. Use the threat model to establish reachability and severity, and add one concise `attack_path` record to each candidate that enters the phase. Do not create ranking or phase queues, per-candidate subagent fan-out, receipts, or narrative phase reports.
5. Write `scan-manifest.json`, `findings.json`, and `coverage.json` using `../../references/final-report.md`. Put candidates that survive both compact phases in `findings.json`. Map rejected, not-applicable, and deferred candidates to the corresponding coverage outcomes. Include the relevant code locations.
6. Verify on disk that `scan-manifest.json`, `findings.json`, and `coverage.json` all exist at `$CLAUDE_SECURITY_SCAN_DIR`, then stop. Do not seal them, do not run the finalizer, and do not author `report.md`: the CLI owns sealing, report generation, and SARIF, and it will reject a draft that already carries `scan.sealedAt` or `scan.artifacts`. Detailed write-ups and hardening plans are optional.

   Report the absolute paths of the three canonical files you wrote as your final answer, plus any coverage gaps.

## Detection Notes

- Report a crash, cancellation, or resource drain when the code shows that a request or routine failure can cause it. Do not assume a public route or deployment condition that the code does not show.
- Keep the source, broken control, sink, and supporting code needed to show how each bug is reached. A safe neighboring path does not prove this path is safe.

Return the report path and any gaps in coverage. Do not claim complete coverage while a file or candidate remains unresolved.
