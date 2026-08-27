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

Standard scans and Deep Scan workers assess attack paths within their ordinary Standard scan workflow; neither invokes this separate phase skill.

### Compact Workbench-Backed Diff Mode

When a workbench-backed `$security-diff-scan` has a `scanId`, load the per-scan threat model and read the validated candidates with `list_codex_security_candidates({ scanId, cursor?, limit? })`. Analyze every `reportable` or `deferred` candidate, preserve every discovery and validation field and the original candidate order, and submit all decisions together with one `record_candidate_attack_paths({ scanId, attackPaths: [{ candidateId, attackPath }] })` call. Submit `attackPaths: []` when no candidate enters this phase. The existing tool atomically updates the stored candidates; do not create per-finding reports, receipts, or manual candidate ledgers in this compact diff mode. Keep attack-path facts, counterevidence, severity calibration, and policy adjustment as separate reasoning steps. Other scan and standalone workflows retain their existing artifact behavior.

## Workflow

1. Load the per-scan threat model path from `../../references/scan-artifacts.md` as the repo-specific threat-model source of truth. Start from this along with the potential findings. Both inputs are required for this workflow.
   - For repository-wide and scoped-path scans, include validation closure rows marked `reportable` or `survives: yes` even if they were not assigned polished candidate numbers during discovery.
2. Determine whether the affected code is in scope for the repository threat model and whether it belongs to a product surface or production workflow.
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
7. Record final policy decision `ignore` explicitly; in compact diff mode, retain its candidate record for coverage, and otherwise drop it from the surviving finding set.
8. For a durable diff scan, submit the nested decision for every eligible candidate in the single compact tool call. Otherwise, save that finding's visible attack-path report and append one attack-path receipt per candidate id at the default paths from `../../references/scan-artifacts.md`. The receipt must record the candidate id, attack-path reportability decision, attack-path facts or exact proof gap, and attack-path artifact/report reference for that candidate finding.

## Scope and Attack Path Checklist

Use this checklist before finalizing the attack-path facts or policy decision:

- Determine whether the finding is actually a real security vulnerability rather than a correctness bug or false positive.
- Determine whether the affected code belongs to a product surface or production workflow.
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

In compact diff mode, every candidate with validation disposition `reportable` or `deferred` must receive exactly one nested attack-path decision. The recorded decisions are the complete phase output; do not also create narrative reports or receipts. Otherwise, use the following report contract.

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

- Use repository evidence and explicitly supplied context. Access the network only when the user has expressly authorized that access; an offline scan never accesses the network.
- Do not invent attack chains that the code does not support.
- Do not leave candidate coverage implicit. In compact diff mode, record a nested attack-path decision for every eligible candidate, even when the final policy decision is `ignore` or `deferred`. Otherwise, every candidate that reaches attack-path analysis must leave an attack-path receipt in its candidate-ledger path from `../../references/scan-artifacts.md`.
- Do not drop exact affected locations while converting validated findings into attack paths. Repository-wide seeded/root-control rows that survive validation must keep their root-control file:line even when a wrapper, route, or transport is easier to explain.
- Do not skip a reportable validation row because a neighboring same-family finding has a cleaner story. Either produce attack-path facts for that exact row or make an explicit final policy decision with repository counterevidence.
- Missing public-ingress evidence is not by itself dispositive counterevidence.
- Keep attack-path analysis, severity calibration, and final policy suppression as separate sub-stages.
- Use the final policy-adjustment matrix mechanically rather than re-arguing severity from scratch after the facts are set.
- Outside compact diff mode, save a final visible report for each candidate finding using that finding's attack-path analysis report path from `../../references/scan-artifacts.md`.

-- Considerations for attack path --
- A bug matters if evidence shows an attacker could exploit it.
- The attack surface should generally be one that is plausibly exposed to end users / external actors (or another actor explicitly in scope in the threat model).
