---
name: fix-finding
description: Use when the user explicitly asks to fix and verify a validated or plausible security finding. Do not use as the primary trigger for full PR, commit, branch, patch, or repository scans.
---

# Fix Finding

## Objective

Turn a current security finding into a minimal, validated code change. If the code is already safe, prove that and report that no change was needed.

Judge the result in this order:

1. the current state is correctly classified as vulnerable, already safe, or unproven
2. any fix completely closes the broken security boundary
3. legitimate behavior and compatibility are preserved
4. relevant repository checks pass
5. the implementation follows repository conventions
6. the patch contains only the scope necessary for the earlier properties

Never trade an earlier property for a later one. Minimal means the smallest repository-native change that satisfies all earlier properties, not the fewest lines.

## Patch Contract

Before editing, establish from repository evidence:

- affected component and current source-to-sink path or broken control
- attacker-controlled input and required preconditions
- security invariant and narrowest plausible enforcement boundary
- legitimate behavior, APIs, error semantics, and compatibility constraints to preserve or intentionally change with supporting product evidence
- available PoC, reproducer, tests, evidence, and affected locations
- nearest relevant helpers and implementation, error-handling, and test precedents

Inspect the repository to fill gaps. Ask the user only when a material product, security, or compatibility decision remains.

## Runtime Validation

Use this guidance whenever reproducing the finding, running tests, or validating the fix:

- Complete the patch contract before broad setup; start with the smallest high-signal check through the real vulnerable boundary.
- Use repository-supported setup commands. Keep repair effort bounded so it does not displace path analysis, patching, or focused verification.
- Do not stop a progressing command merely because it is slow. Inspect process state, logs, artifacts, or resource use first.
- If runtime validation remains unavailable, use the strongest targeted static or harness-based artifact that preserves the real integration boundary. Do not substitute a simplified harness that removes the behavior being protected. Record every unrun check as unknown.

## Workflow

1. Revalidate and scope the finding.
   - Inspect repository instructions, affected code, direct callers, and only the context needed to prove the vulnerable path.
   - Establish concrete reachability in the current checkout; generic weakness labels, file anchors, and suspicious-looking code are not proof.
   - If the same broken security boundary cannot be shown after a bounded investigation, do not patch an adjacent weakness or add speculative defense in depth. Return `no_change` when evidence shows the path is already safe; otherwise return `blocked` with the missing proof.
   - Complete the patch contract and inspect relevant helpers, controls, and implementation and test precedents.
2. Reproduce or encode the issue before fixing when feasible.
   - Prefer a failing regression test, unit test, integration test, property test, or realistic-interface reproduction.
   - Capture the malicious condition and at least one legitimate control through the same boundary before implementation.
   - Keep an unsafe-behavior test only when it is safe, deterministic, and appropriate for the repository. Otherwise use the strongest repeatable validation artifact available and record the gap.
   - If the issue no longer reproduces before any code changes, investigate whether it was already fixed and preserve the validation evidence.
3. Choose the patch strategy.
   - Determine whether a narrow tactical change can close the boundary while preserving the patch contract.
   - Consider broader remediation only when the narrow option cannot close the boundary without breaking supported behavior. Remove or disable functionality only when repository or product evidence supports that mitigation.
   - If the only complete fix requires an unresolved decision about product policy, public-API compatibility, or cross-subsystem ownership, return `blocked` with the options, security tradeoff, and likely owner or codeowner when available.
   - Use nearby variants to test the chosen boundary. Report unrelated sibling findings or longer-term architectural work separately instead of expanding this patch.
4. Implement the fix and its proof.
   - Make the smallest repository-native change that fully enforces the invariant.
   - Prefer existing helpers and abstractions. Preserve APIs, legitimate inputs, and error semantics unless changing them is required by the security contract.
   - Handle unsafe state explicitly; do not silently accept, truncate, or reinterpret it.
   - Avoid unrelated refactors and preserve user changes outside the candidate patch.
   - Add focused regression coverage that fails on the vulnerable behavior and passes after the fix.
   - Include positive coverage for the legitimate control. Test at the lowest level that proves the invariant and through the realistic interface when feasible.
5. Verify in order.
   - **Applicability and buildability**: inspect the final diff for unrelated changes, then run the narrowest relevant syntax, import, build, type, or focused test check.
   - **Security closure**: rerun the original PoC, trigger, or strongest exploit check. Re-trace the source-to-sink or broken-control path in the patched code.
   - **Change-aware bypass review**: reread the finding and final diff without relying on the original rationale. Trace changed branches from direct callers, check equivalent sinks, and exercise an alternate malicious input class when practical.
   - **Preserved behavior**: rerun the legitimate control and confirm the recorded APIs, error semantics, and compatibility constraints remain intact.
   - **Repository checks**: run the focused regression tests, the owning package's relevant tests, and applicable formatter, linter, type checker, dependency, and integration checks.
   - Confirm the regression check would fail if the security change were removed, when practical.
   - Treat a failed earlier gate as disqualifying. Revise only the candidate changes or return `blocked`; never compensate for failed security closure or behavior preservation with style, smaller scope, or additional reporting.
6. Report the outcome with exact commands, results, changed files, and remaining risk.

## Workbench Remediation Stages

When a Codex Security workbench request includes a scan ID, occurrence ID, remediation request ID, action token, and expected version, follow only the requested remediation stage. The stage boundary changes when code may be written, but it does not weaken the validation requirements above.

- **Generate**: Keep the selected target checkout unchanged. Use an isolated worktree or temporary copy when edits are needed to develop or test the fix. Apply the patch contract and strategy gates above, write one canonical unified diff containing the complete source and regression-test change, then record `generated` or `failed` using the supplied workbench identity.
- **Apply**: Verify the recorded base revision and patch digest, then apply exactly that patch to the selected working tree without unrelated edits. Record `applied` or `failed`. Do not verify or close the finding in this stage.
- **Verify**: Do not modify source. Run the ordered verification gates above against the recorded patch. Record `verified` only when the original issue no longer reproduces, legitimate behavior remains intact, and relevant repository checks pass; preserve exact commands and results in the verification summary. Otherwise record `failed` and state the failing gate or proof gap. Do not close the finding.

When a parent thread delegates a remediation stage, the worker owns that stage through its terminal workbench update. The parent remains an orchestrator and must not duplicate the worker's edits or treat a chat response as completion.

## Outcome and Output Contract

In the final response, include:

- outcome: `fixed`, `no_change`, or `blocked`
- the concrete vulnerable path, security invariant, and legitimate behavior that had to remain
- the selected patch strategy and why it was the narrowest complete repository-native option, or the unresolved product decision when blocked
- files changed
- tests or validation artifacts added
- commands run and their pass, fail, or unknown results, grouped by the ordered verification gates
- explicit statement of how the original issue was shown not to reproduce
- explicit statement of how legitimate behavior was shown to remain intact
- remaining uncertainty or skipped validation, if any

If using a scan artifact directory, resolve it using `../../references/scan-artifacts.md`, then write a visible report to the fix report path. If there is no existing scan directory, a final chat summary is sufficient unless the user asks for a file.

## Hard Rules

- Do not report `fixed` until every ordered verification gate has passed. Omit a check only when repository evidence shows it is irrelevant; an unavailable relevant check makes verification `blocked` and must be reported.
- Do not rely only on code inspection when a focused test or reproducer is feasible.
- Do not broaden the patch into unrelated cleanup, sibling findings, or architectural redesign without evidence that the broader change is required for complete closure.
- Do not remove user changes or unrelated local modifications.
- Do not weaken authentication, authorization, tenant isolation, input validation, sandboxing, or logging to make tests pass.
- Do not hide proof gaps. If the environment blocks validation, say exactly which command or setup failed and what evidence is still missing.
