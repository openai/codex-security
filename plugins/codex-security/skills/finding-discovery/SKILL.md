---
name: finding-discovery
description: Use when Codex is already in the finding-discovery phase of a security scan or the user explicitly asks to discover candidate security findings in a repository or code change. Do not use as the primary trigger for full PR, commit, branch, patch, or repository scans.
---

# Security Finding Discovery

Identify technically plausible security vulnerabilities in the authorized source, using the threat model and applicable security policy. Discovery preserves evidence for later validation; it does not decide final severity.

Read `../../references/artifact-storage.md` before saving output and `../../references/security-guidance.md` before source review. Resolve applicable policy for each reviewed path, including delegated assignments. Honor explicit input and output paths; ask for an explicitly required input only when its absence prevents the requested analysis.

## Select the Workflow

Standard and Deep workers use their coordinator's self-contained prompts rather than this phase skill.

- **Running compact diff:** read the supplied inventory through `list_codex_security_review_items`, review every assigned changed file, and record all candidates once with `record_codex_security_discovery_candidates`. Do not create ranked worklists, per-finding ledgers, receipts, or discovery reports.
- **Standalone diff without a compact inventory:** use `../security-scan/references/scan-artifacts-and-ledger.md` for the changed-file worklist and retained phase artifacts.
- **Standalone repository discovery:** apply the evidence criteria below to the authorized source and return the candidates and coverage limitations. Do not start a scan or run the diff worklist pipeline.

For a diff, inspect the actual changed behavior, including deleted files at the baseline revision. Follow supporting code far enough to understand the affected boundary; expand to sibling callers when a changed shared control affects them. Do not broaden into an unrelated repository audit.

## Evidence Criteria

Use the “Locate Entry Points” section of `../../references/threat-model.md` when tracing registrations for a changed handler or mapping inputs into the authorized scope.

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

Use the caller's structured candidate contract. For a legacy diff, save the discovery report and discovery receipts at the paths in `../../references/scan-artifacts.md`; subsequent phases own their own evidence and receipts. Finish when assigned source review and concrete follow-ups are accounted for, recording unfinished review honestly. If no plausible candidates remain, return that result with the actual reviewed scope and limitations.
