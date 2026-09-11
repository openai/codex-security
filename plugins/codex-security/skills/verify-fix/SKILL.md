---
name: verify-fix
description: Use only when the user explicitly requests verification that a security fix remediates a reported vulnerability. Do not invoke automatically while implementing fixes, reviewing ordinary code changes, or running tests. Do not use for non-security fixes, candidate finding validation, or full repository scans.
---

# Verify Fix

## When to Use

Invoke this skill only for an explicit request to verify a security fix, including a direct `$verify-fix` invocation. A request to implement a fix or run its tests does not by itself request this skill. For other tasks, follow the user's requested workflow and response format without applying this skill's JSON result contract.

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
