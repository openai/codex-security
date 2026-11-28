---
name: finding-discovery
description: Use when Codex is already in the finding-discovery phase of a security scan or the user explicitly asks to discover candidate security findings in a repository or code change. Do not use as the primary trigger for full PR, commit, branch, patch, or repository scans.
---

# Security Finding Discovery

Identify technically plausible security vulnerabilities in the authorized source, using the threat model and applicable security policy. Discovery preserves evidence for later validation; it does not decide final severity.

Read `../../references/artifact-storage.md` before saving output and `../../references/security-guidance.md` before source review. Resolve applicable policy for each reviewed path, including delegated assignments. Honor explicit input and output paths; ask for an explicitly required input only when its absence prevents the requested analysis.

## Review the assigned source

Use the caller's inventory, authorized scope, and candidate output contract. For a standalone diff discovery request without a supplied inventory, follow the [standalone diff worklist](../security-scan/references/scan-artifacts-and-ledger.md) for changed files, receipts and the discovery report. For a standalone repository request, review the requested scope directly and return candidates with coverage limitations.

For a diff, inspect the actual changed behavior, including deleted files at the baseline revision. Follow supporting code far enough to understand the affected boundary; expand to sibling callers when a changed shared control affects them. Do not broaden into an unrelated repository audit.

## Evidence Criteria

- Trace attacker-controlled input or a privileged operation through the closest relevant control to the sink and security impact. Explain why the control is absent, bypassable, or applied to the wrong value or boundary.
- Check runtime reachability and deployment assumptions. Record effective guards and containment as counterevidence; a safe sibling implementation does not establish that the candidate path is safe.
- Preserve the root-control location as well as entrypoints, wrappers, concrete implementations, and sinks needed to understand the claim. When the claim covers several implementations, inspect those implementations rather than asserting that all are affected.
- Keep independently reachable vulnerable instances addressable. Merge duplicate observations of the same source/control/sink/impact instead of splitting cosmetic variants; retain all affected locations and original candidate IDs when merging.
- Follow explicit user or advisory seeds to their exact source and control. Record the evidence that supports, disproves, or leaves the seed unresolved; a nearby issue in the same family does not close it. Use only authorized source material and do not fetch advisory links without permission.
- Distinguish concrete security impact from maintainability or robustness concerns. A crash, dangerous API, optional feature, or missing check is a lead, not a finding by itself. Carry plausible candidates with explicit proof gaps to validation rather than inventing evidence or discarding them for lack of a runnable reproduction.

Divide independent review assignments among available workers when useful, with the target, scope, relevant policy/model, and required result fields. The parent reviews unassigned work and reconciles duplicates. Do not repeat validation or attack-path phases inside discovery.

## Candidate Output

For each candidate, retain:

- Stable candidate ID and title; preserve supplied seed or ledger IDs and advisory references.
- Affected file/line locations, labeling `entrypoint/wrapper`, `root_control`, `sink`, and `concrete_implementation` where useful.
- Attacker-controlled source, closest control, sink or broken control, plausible impact, and the source evidence connecting them.
- Counterevidence, deployment preconditions, unresolved questions, and what validation needs to establish.
- CWE IDs when known, otherwise an empty list.
- For repository or scoped-path instances, an instance key `<family>:<file>:<line>` when required by the caller.
- For diff findings, `relevant_lines` only where relevant buggy behavior overlaps the diff.

Finish when assigned source review and concrete follow-ups are accounted for. Record unfinished review honestly. If no plausible candidates remain, return that result with the actual reviewed scope and limitations.
