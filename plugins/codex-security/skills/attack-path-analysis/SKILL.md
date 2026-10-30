---
name: attack-path-analysis
description: Use when Codex is already in the attack-path-analysis phase of a security scan or the user explicitly asks to trace a security finding from source to sink and calibrate severity. Do not use as the primary trigger for full PR, commit, branch, patch, or repository scans.
---

# Security Attack Path Analysis

Determine whether each supplied finding has a supported attacker path, what impact it has, and whether it is reportable. Before creating or retaining files, read `../../references/artifact-storage.md`.

## Establish the attack path

For a scan phase, use its per-scan threat model and candidate set from `../../references/scan-artifacts.md`. Preserve supplied input paths. If a required scan artifact is unavailable, report the missing input.

For standalone analysis, use the supplied finding, repository, threat model or security policy, and context. A per-scan artifact is not required. State material assumptions and ask for missing context only when it prevents a meaningful assessment.

1. Establish the in-scope attacker, affected product surface, entry point, controlled input, security boundary, and sensitive operation. Trace the path from repository evidence.
2. Identify relevant controls and the strongest counterevidence. Explain what they establish, which prerequisites remain, and whether the exact claimed boundary is crossed.
3. Assess impact and likelihood from those facts. Apply the [reportability rules](references/severity-policy.md#reportability) and grade reportable findings with the scan's rubric when supplied. Otherwise use the [default severity criteria](references/severity-policy.md). For a candidate with no security impact, record an `ignore` decision with severity `ignore`.
4. Return an explicit decision for every eligible candidate, including ignored or deferred candidates. Do not replace a supported instance with a neighboring finding or lose its root-control location.

Use repository evidence and explicitly supplied context. Access the network only when the user has expressly authorized it; an offline scan never accesses the network. Do not invent unsupported attack chains. Missing deployment or public-ingress evidence can limit confidence without defeating an otherwise supported finding.

## Scan integration

Standard scans and Deep Scan workers assess attack paths within their ordinary Standard scan workflow; neither invokes this separate phase skill.

### Compact Workbench Diff

When a workbench-backed `$security-diff-scan` has a `scanId`:

- Load the per-scan threat model and all validated candidates with `list_codex_security_candidates({ scanId, cursor?, limit? })`.
- Analyze every `reportable` or `deferred` validation candidate. Preserve candidate identity and existing discovery and validation fields.
- Submit every decision together with `record_candidate_attack_paths({ scanId, attackPaths: [{ candidateId, attackPath }] })`. Submit `attackPaths: []` when no candidate enters this phase. The tool preserves the stored candidate order.
- These nested decisions are the complete phase output. Do not create duplicate reports, receipts, or manual ledgers.

### Other phase-based scans

Use the active workflow's report and receipt paths in `../../references/scan-artifacts.md`. Every candidate entering this phase must have an explicit decision and a receipt with its ID, facts or exact proof gap, and report reference. Record ignored candidates before excluding them from the surviving finding set.

For repository-wide or scoped-path scans, include validation closure rows marked `reportable` or `survives: yes`, even if discovery did not assign a polished finding number. Preserve affected entrypoint/wrapper, root-control, sink, and concrete-implementation locations supplied by validation.

## Output

For standalone analysis, follow the caller's format or return a concise assessment per finding. Scan phases use their output contract above. Include:

- title and supplied candidate, instance, and ledger identities;
- precise affected locations and attacker-to-impact steps;
- relevant facts from [references/attack-path-facts.md](references/attack-path-facts.md);
- controls, counterevidence, prerequisites, and material proof gaps;
- impact, likelihood, calibrated severity, and final policy decision with their reasons.

Retain enough evidence to explain both surviving and suppressed findings. Apply the severity policy to the established facts rather than reopening discovery or substituting a different attack story.
