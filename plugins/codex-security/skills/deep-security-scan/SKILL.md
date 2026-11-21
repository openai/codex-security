---
name: deep-security-scan
description: Run repeated Standard security scans of a repository or scoped path when the user requests a deep, exhaustive, or multi-pass audit. For changes to a PR, commit, branch or working tree, use security-diff-scan.
---

# Deep Security Scan

The host runs Standard audits and merges their findings. Workers in the same scan can exchange investigation leads and verify each other’s evidence. Later passes receive the titles and locations already reported. The host stops when consecutive audits add nothing new or the configured scan or time limit is reached. Its final report includes every accepted audit.

Use the host-supplied scan runtime instructions for startup, progress, checkpoint storage and completion. For a native invocation, resolve the `deep-scan` topic as described in `../../references/skill-runtime.md` before reviewing source. Preserve authoritative ownership throughout the scan.

1. Preserve the exact authorized target, scope and user context. Follow `../../references/scan-prologue.md` for source access and recovery. The configured `max_discovery_runs` caps the total number of Standard scans, including when several run together.
2. Follow `../../references/access-advisory.md` before launching the coordinator through the selected runtime instructions. Await its result, including any running tool cell. If the connection closes, rejoin with the same arguments. Report a terminal failure with its saved results. For a policy refusal, identify the worker from its saved error when available. For worker startup diagnostics, read `references/worker-failures.md`. On explicit cancellation call `cancel_codex_security_scan({ scanId })` from the owning thread.
3. Return the result using the selected completion instructions. Distinguish a completed audit with zero findings from a deadline reached before any audit completed.
