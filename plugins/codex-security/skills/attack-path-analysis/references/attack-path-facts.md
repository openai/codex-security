# Attack Path Facts

Use these fields to explain the path and the reportability decision. Record unknowns explicitly when they matter. Follow the calling workflow's schema; in narrative output, use concise bullets or paragraphs rather than repeating the same evidence under several headings.

- **Scope and context:** the affected component, applicable threat-model boundary, whether the impact is self-only or crosses a meaningful boundary, and the evidence.
- **Attack path:** attacker-controlled input, numbered attacker steps, sensitive operation, and the evidence connecting them.
- **Exposure and vector:** public, internal, or admin-only access; `remote`, `local_network`, `localhost`, `none`, or `unknown`; relevant routing or deployment evidence when available.
- **Identity and preconditions:** effective privileges, required attacker position or capabilities, plausibility of those prerequisites, and assumptions.
- **Impact:** vulnerability category, affected runtime/data/identity/build/network surface, target reach, and any involved secret type or reference chain.
- **Controls and counterevidence:** effective mitigations, the strongest evidence against the claimed path or scope, and why it does or does not defeat the finding.
- **Uncertainty:** confidence, missing facts, and conditions that would change the assessment.
- **Decision:** impact and likelihood reasoning, calibrated severity, and final policy decision.

Keep attack-path facts distinct from severity and suppression decisions. Preserve precise source locations and identifiers supplied by validation.
