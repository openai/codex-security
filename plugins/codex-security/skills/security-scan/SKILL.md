---
name: security-scan
description: "Find vulnerabilities in the current source of a whole repository or selected paths. This is the default single-pass audit. Use the diff skill for PR, commit, branch, or working-tree changes and the deep skill for an explicitly requested deep scan."
---

# Security Scan

Find vulnerabilities an attacker could actually exploit. Start from code that accepts untrusted input or exercises authority. Follow it to the operation it controls. Check the real enforcement point, its callers, and the strongest evidence that the suspected attack is blocked. For an exposed credential, the relevant path is who can read it and what access it grants.

Use [the core audit](../../references/core-scan.md) for the independent baseline, focused investigations, and validation. Give reviewers the authorized source and security context. Keep scan administration in the parent. Report findings with source lines and concrete impact. Record what you reviewed and what remains uncertain.

## Run the audit

Before reading target source, bind the requested target and scope:

- If the SDK supplied `CODEX_SECURITY_SCAN_ID` and `CODEX_SECURITY_SCAN_DIR`, use that registered scan. Follow its launch instructions, or the [SDK handoff](references/scan-results.md) if the SDK provided no instructions.
- With a supplied scan ID, call `get_codex_security_scan_context` using its handoff token when supplied. Otherwise call `start_codex_security_standard_scan` with the requested target, scope and exact user context. If deferred, look up just the named tool. Require a running Standard scan. Keep its target, scope, phase and token, show any returned account advisory, and begin the source review. Use [managed scan progress](references/managed-scan.md) at the next phase change.

Keep the target read-only and review its current source offline. Preserve exact user context as analysis data. Only the parent may read an explicitly supplied URL, once, if the user explicitly authorized that read. Do not follow links. Keep an existing investigation allowance unchanged across workers and resumes. Only if the user requests a time limit in this conversation and none was supplied, render [the time budget](../../references/investigation-time-budget.md) once before source review using the requested minutes and actual UTC start and deadline.

Start the independent audit while mapping the repository. At the first usable threat model, follow [save scan results](references/scan-results.md). Checkpoint candidates as they arrive. Once assigned reviews return, validate each distinct broken control once and submit the findings and honest coverage to the same scan. The SDK owns finalization for its scans.
