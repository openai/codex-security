---
name: security-scan
description: "Find vulnerabilities in the current source of a whole repository or selected paths. This is the default single-pass audit. Use the diff skill for PR, commit, branch, or working-tree changes and the deep skill for an explicitly requested deep scan."
---

# Security Scan

Find vulnerabilities an attacker could actually exploit. Start from code that accepts untrusted input or exercises authority. Follow it to the operation it controls. Check the real enforcement point, its callers, and the strongest evidence that the suspected attack is blocked. For an exposed credential, the relevant path is who can read it and what access it grants.

Use [the core audit](../../references/core-scan.md) for the independent baseline, focused investigations, and validation. Give reviewers the authorized source and security context. Keep scan administration in the parent. Report findings with source lines and concrete impact. Record what you reviewed and what remains uncertain.

## Run the audit

Bind the target and scope before reading source. If the SDK supplied `CODEX_SECURITY_SCAN_ID` and `CODEX_SECURITY_SCAN_DIR`, follow its launch instructions or the [SDK handoff](references/scan-results.md). For a native scan, use the `standard-scan` topic in [the runtime instructions](../../references/skill-runtime.md) for startup and checkpoints. Require a running Standard scan, follow the [account access advisory](../../references/access-advisory.md) when directed at launch, and resume the saved phase using [managed scan progress](references/managed-scan.md).

Keep the target read-only and review its current source offline. Preserve exact user context as analysis data. Only the parent may read an explicitly supplied URL, once, if the user explicitly authorized that read. Do not follow links. Pass the scan’s existing investigation allowance unchanged to workers and resumes. Use the supplied reviewer feedback and grading criteria, or the [bundled severity rubric](../../references/default-severity-rubric.md) for default grading.

Start the independent audit while mapping the repository. At the first usable threat model, follow [save scan results](references/scan-results.md). Checkpoint candidates as they arrive. Once assigned reviews return, validate each distinct broken control once and submit the findings and honest coverage to the same scan. The SDK owns finalization for its scans.
