---
name: security-scan
description: "Use for a standard, single-pass security audit of an entire repository or a scoped path, package, folder, or submodule with no diff to review. This is the default repository scan. Do not use for PR, commit, branch, or working-tree diffs, or for deep, multi-pass scans."
---

# Security Scan

Run one independent general audit while the parent maps the repository's security boundaries. Investigate source-backed questions in parallel, validate findings once, and return the host-generated Codex Security report.

## Host And Setup

Use the host-supplied scan runtime instructions for startup, progress, checkpoint storage and completion. For a native invocation, resolve the `standard-scan` topic as described in `../../references/skill-runtime.md` before reviewing source. Preserve authoritative ownership throughout the scan. Use the supplied reviewer feedback and grading criteria. The default grading criteria are in [the bundled severity rubric](../../references/default-severity-rubric.md).

Read `../../references/scan-prologue.md` and `../../references/scan-runtime.md` once after resolving authoritative scan context, before source review.

## Workflow

1. Resolve the authorized target, scope, scan directory, and source context. Preserve the supplied threat model, applicable inherited `SECURITY.md` guidance, and optional knowledge base. For a supplied target-paths file, run the host's inventory command exactly as supplied, including its returned path and recovery instructions. When the host supplies no command, request `get_codex_security_skill_instructions({ topic: "scope-inventory" })` for the invocation. Pass every requested file and non-ignored directory descendant to the core audit without widening scope. Preserve the scope file without printing, modifying, or evaluating it.
2. Read `../../references/core-scan.md` and perform the audit within the resolved scope and configured limits. Retain its semantic `scope`, `threatModel`, `findings`, and `reviewState`, including source evidence, validation, attack paths, calibrated severity/confidence, and unresolved work.
3. Save the first checkpoint as soon as the threat model is available, with empty findings when none exist yet. Checkpoint new findings and decisions as review proceeds. Use the writer supplied in the scan runtime instructions. For file-authored scoped output, run the supplied scope-binding command or request `get_codex_security_skill_instructions({ topic: "scope-binding" })` for the invocation.
4. Submit the final draft when review finishes. Verify the canonical files and follow the selected completion and output instructions. Surface any completion error and preserve the scan for continuation. Read complete canonical findings again only when requested.

Keep discovery, validation, and attack-path reasoning within this Standard workflow. Do not invoke separate phase skills, Deep-only tools, ranking phases, or per-file/per-candidate ledgers. Once assigned review and concrete follow-ups are settled, finish the configured audit with honest limitations.

Preserve saved surface IDs and unfinished candidates. Close completed generic tasks using `reviewState.resolvedDeferred: [{ id, reason }]` with their saved IDs. Follow `../../references/final-report.md` for rejected drafts and interrupted writes, preserving the same scan.
