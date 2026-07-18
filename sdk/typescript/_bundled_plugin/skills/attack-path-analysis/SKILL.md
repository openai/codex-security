---
name: attack-path-analysis
description: Use when Codex is already in the attack-path-analysis phase of a security scan or the user explicitly asks to trace a security finding from source to sink and calibrate severity. Do not use as the primary trigger for full PR, commit, branch, patch, or repository scans.
---

# Security Attack Path Analysis

## Objective

Turn validated or still-plausible findings into explicit attacker stories, structured attack-path analysis facts, severity calibration, and a final reportability decision grounded in the threat model.

## Artifact Resolution

The path references in this skill are the default locations for this phase.
If the user explicitly provides a different path for a required input or output, use the user-provided path instead of the corresponding default path referenced in this skill.
If a required input is still missing, stop and ask the user for it before continuing.
Use the shared scan artifact path conventions in `../../references/scan-artifacts.md`.

## Workflow

1. Load the per-scan threat model path from `../../references/scan-artifacts.md` as the repo-specific threat-model source of truth. Start from this along with the potential findings. Both inputs are required for this workflow.
   - For repository-wide and scoped-path scans, include validation closure rows marked `reportable` or `survives: yes` even if they were not assigned polished candidate numbers during discovery.
2. Determine whether the affected code is in scope for the repository threat model and whether it belongs to a real product surface or real production workflow.
3. Build a factual attack path using repository evidence only:
   - service mapping
   - exposure and entry points
   - identity, privilege, and trust boundaries
   - secrets handling and sensitive-data flow
   - reachability
   - existing controls and mitigations
4. Before finalizing scope or reportability-driving facts, identify the strongest repository counterevidence against the key scoping fields and explain why it is or is not dispositive.
5. Calibrate impact and likelihood from the repository evidence.
6. Apply a separate final policy-adjustment pass mechanically using those facts and the calibrated severity.
7. Drop any candidate whose final policy decision is `ignore`.
8. Save that finding's visible attack-path report to its per-finding attack-path analysis report path from `../../references/scan-artifacts.md`.
9. Append one attack-path receipt per candidate id to that finding's candidate ledger path from `../../references/scan-artifacts.md`. The receipt must record the candidate id, attack-path reportability decision, attack-path facts or exact proof gap, and attack-path artifact/report reference for that candidate finding.

## Scope and Attack Path Checklist

Use this checklist before finalizing the attack-path facts or policy decision:

- Determine whether the finding is actually a real security vulnerability rather than a correctness bug or false positive.
- Determine whether the affected code belongs to a real product surface or meaningful production workflow.
- Map the relevant service, component, or workflow context from repository evidence.
- Establish exposure and entry points from repository evidence such as listeners, ingress, load balancers, service ports, manifests, routing, or network policy.
- Establish identities, privileges, and trust boundaries that matter for the path.
- Establish whether sensitive data, secrets references, or privileged control paths are involved.
- Determine whether a realistic attacker can actually reach and use the issue from an in-scope attack surface.
- Identify the strongest repository counterevidence against the scoping and reportability-driving fields before finalizing them.
- Lower confidence or keep fields unknown when repository evidence is incomplete; do not automatically suppress a finding solely because deployment evidence is missing.

## Counterevidence Checklist

For the most interpretive fields, explicitly ask what repository evidence suggests the opposite and why it does or does not defeat the finding:

- In-Scope Status According to the Threat Model
- Vector
- Auth Scope
- Exposure
- Cross-Boundary Behavior
- Preconditions
- Impact Surface

Look specifically for repository evidence that the path is:

- out of scope
- internal-only
- admin-only
- not cross-boundary
- not attacker-reachable
- not meaningfully reportable

## Severity and Policy Checklist

Apply severity and policy calibration using `references/severity-policy.md`.

## Output Contract

For each surviving finding include:

- title
- candidate id, instance key, and ledger row id when provided
- affected lines from validation, preserving labeled entrypoint/wrapper, root_control, sink, and concrete_implementation locations
- attack path steps
- rendered attack-path facts
- counterevidence summary and challenges
- severity calibration
- final policy decision
- enough reasoning that a later reader can understand why the finding survived or was suppressed

Render attack-path facts using `references/attack-path-facts.md`.

## Hard Rules

- Prefer repository evidence first, but use network connectivity when it materially helps confirm deployment context, reachable surfaces, or other reportability-relevant facts.
- Do not invent attack chains that the code does not support.
- Do not leave candidate coverage implicit. Every candidate finding that reaches attack-path analysis must leave an attack-path receipt in its candidate-ledger path from `../../references/scan-artifacts.md`, even when the final policy decision is `ignore` or the path remains deferred.
- Do not drop exact affected locations while converting validated findings into attack paths. Repository-wide seeded/root-control rows that survive validation must keep their root-control file:line even when a wrapper, route, or transport is easier to explain.
- Do not skip a reportable validation row because a neighboring same-family finding has a cleaner story. Either produce attack-path facts for that exact row or make an explicit final policy decision with repository counterevidence.
- Missing public-ingress evidence is not by itself dispositive counterevidence.
- Keep attack-path analysis, severity calibration, and final policy suppression as separate sub-stages.
- Use the final policy-adjustment matrix mechanically rather than re-arguing severity from scratch after the facts are set.
- Save a final visible report for each candidate finding using that finding's attack-path analysis report path from `../../references/scan-artifacts.md`.

-- Considerations for attack path --
- A finding should count as a real security issue if a realistic attacker could use it from a reasonable attack surface relevant to the product, especially if it is something that is part of the thread model.
- The attack surface should generally be one that is plausibly exposed to end users / external actors (or another actor explicitly in scope in the threat model), not an arbitrary internal-only or contrived path.
