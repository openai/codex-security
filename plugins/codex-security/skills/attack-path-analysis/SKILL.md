---
name: attack-path-analysis
description: Use when Codex is already in the attack-path-analysis phase of a security scan or the user explicitly asks to trace a security finding from source to sink and calibrate severity. Do not use as the primary trigger for full PR, commit, branch, patch, or repository scans.
---

# Security Attack Path Analysis

Determine whether each supplied finding has a supported attacker path, what impact it has, and whether it is reportable. Before creating or retaining files, read `../../references/artifact-storage.md`.

## Establish the attack path

Use the supplied candidates, target, threat model or security policy, and context. Preserve input paths and the per-scan model when running a scan phase. State material assumptions, and identify a missing required input when its absence prevents a meaningful assessment.

1. Establish the in-scope attacker, affected product surface, entry point, controlled input, security boundary, and sensitive operation. Trace the path from repository evidence.
2. Identify relevant controls and the strongest counterevidence. Explain what they establish, which prerequisites remain, and whether the exact claimed boundary is crossed.
3. Assess impact and likelihood from those facts. Apply [references/severity-policy.md](references/severity-policy.md) for the final decision. When the scan supplies a severity rubric, use it to grade reportable findings and retain `ignore` for candidates without security impact. Keep facts, severity calibration, and the final policy decision distinguishable in the result.
4. Return an explicit decision for every eligible candidate, including ignored or deferred candidates. Do not replace a supported instance with a neighboring finding or lose its root-control location.

Use repository evidence and explicitly supplied context. Access the network only when the user has expressly authorized it; an offline scan never accesses the network. Do not invent unsupported attack chains. Missing deployment or public-ingress evidence can limit confidence without defeating an otherwise supported finding.

## Output

Submit the decisions through the caller's result contract. For a retained phase report and receipts, follow the [attack-path artifact contract](../../references/scan-artifacts.md#attack-path-analysis-phase-4-paths). A standalone request without a supplied format receives a concise assessment per finding. Include:

- title and supplied candidate, instance, and ledger identities;
- precise affected locations and attacker-to-impact steps;
- relevant facts from [references/attack-path-facts.md](references/attack-path-facts.md);
- controls, counterevidence, prerequisites, and material proof gaps;
- impact, likelihood, calibrated severity, and final policy decision with their reasons.

Retain enough evidence to explain both surviving and suppressed findings. Apply the severity policy to the established facts rather than reopening discovery or substituting a different attack story.
