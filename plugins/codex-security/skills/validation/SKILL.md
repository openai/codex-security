---
name: validation
description: Use when Codex is already in the validation phase of a security scan or the user explicitly asks to determine whether one or more candidate security findings are valid. Do not use as the primary trigger for full PR, commit, branch, patch, or repository scans.
---

# Security Validation

Determine whether each supplied candidate is supported by evidence. Follow [references/validation-guidance.md](references/validation-guidance.md) for evidence selection, instance coverage, and confidence. Use the caller's candidate set, reviewer feedback, and result contract. Preserve candidate identities and discovery fields. Before creating or retaining files, read `../../references/artifact-storage.md`.

## Assess the candidates

1. Identify the claimed attacker input, security boundary, relevant control, sensitive operation, and preconditions. Use supplied context and repository evidence; ask for missing information only when it prevents a meaningful assessment.
2. Seek evidence that supports or defeats the claim. Choose focused source analysis or an authorized reproduction according to what would resolve the uncertainty. Use runtime checks when feasible and proportionate; a particular language or tool does not determine evidence quality.
3. Check supplied false-positive feedback against the current code and controls. Treat it as reviewer evidence. Suppress a matching candidate only when the stated reason still holds.
4. Record a disposition for every candidate, including exact affected locations, observed evidence, counterevidence or proof gaps, and confidence. Preserve independently vulnerable instances and the supplied scope.

Do not access the network or execute a PoC beyond the user's authorization and the active scan's permissions. An offline scan remains offline. For scans that leave the target unchanged, run builds, generated harnesses, and PoCs in the disposable workspace provided by the storage policy. Prefer testing the original code over a separate reimplementation.

## Output

Submit the assessments through the caller's result contract. For a retained phase report and receipts, follow the [validation artifact contract](../../references/scan-artifacts.md#validation-phase-3-paths). A standalone request without a supplied contract receives a concise assessment per candidate. Include:

- identifier and title, plus supplied instance and ledger identities;
- affected locations, preserving root-control and distinct seed anchors;
- disposition and the security property assessed;
- validation method, commands actually run, and observed results;
- evidence, counterevidence or proof gaps, confidence and its rationale;
- remaining uncertainty, the next useful step if needed, and retained evidence paths.

Distinguish static conclusions from executed tests. Missing setup or deployment evidence is a limitation, not proof that a candidate is safe. Never invent product assumptions or imply validation succeeded when it did not.
