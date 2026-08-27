---
name: verify-fix
description: Use when the user asks whether an existing security fix, patch, finding, or completed issue actually remediates the original vulnerability without modifying the repository. Do not use to validate candidate findings, implement patches, or run full repository scans.
---

# Verify Fix

## Objective

Determine whether each supplied security finding has been fixed in the current checkout. Operate in standalone verification-only mode; do not create, modify, or delete repository files, apply patches, commit changes, write artifacts, or modify issue trackers.

## Assessment Method

Use `../../references/static-finding-assessment.md` to identify the original attacker-controlled source, security control, sensitive sink, reachable path, trust boundary, counterevidence, and proof gaps. If the caller already supplied that reference in the prompt, use the supplied contents without reading it again.

## Verification Workflow

1. Establish the original vulnerability, its preconditions, affected security boundary, and legitimate behavior that must continue to work.
2. Confirm the current checkout contains the affected component. Follow moved or refactored code rather than treating a missing file, removed line, or changed function name as proof of remediation.
3. Trace the original exploit path through the current implementation and check the nearest relevant control, equivalent paths, and plausible bypasses.
4. Run the original reproducer, focused regression checks, or legitimate-behavior checks only when they can run without modifying the repository. Preserve exact static evidence when runtime checks are unavailable.
5. Return one result per supplied finding, in the requested order. Treat closed tickets, unrelated passing tests, and the absence of a new scan finding as insufficient proof.

## Result Contract

Return exactly one JSON object:

```json
{
  "results": [
    {
      "id": "finding-or-issue-id",
      "status": "fixed|still_vulnerable|inconclusive",
      "evidence": "specific current source, exploit, test, or proof-gap evidence"
    }
  ]
}
```

- Use `fixed` only when evidence proves the original security boundary is closed and legitimate behavior remains intact.
- Use `still_vulnerable` only when evidence proves the original vulnerable path remains reachable.
- Use `inconclusive` for a repository mismatch, missing original context, unavailable relevant checks, an unproven legitimate control, or another material proof gap.

Never infer a stronger verdict by weakening the read-only boundary, substituting a different vulnerability, or hiding missing evidence.
