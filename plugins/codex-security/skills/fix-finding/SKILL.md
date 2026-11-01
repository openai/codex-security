---
name: fix-finding
description: Use only when the user explicitly asks to fix and verify a validated or plausible security vulnerability. Do not use for ordinary bug fixes, correctness or design review findings, general validation, or full PR, commit, branch, patch, or repository scans.
---

# Fix Finding

Before choosing paths or saving retained output, read `../../references/artifact-storage.md` and follow its storage policy.

## Objective

Turn a current security finding into a minimal, validated code change. If the code is already safe, prove that and report that no change was needed.

Classify the current state from evidence, close the broken security boundary, preserve legitimate behavior, and pass the checks required by the selected verification mode. Prefer the smallest repository-native change that meets those requirements.

## Verification Mode

Use `standard` verification unless the caller explicitly selects `verificationMode: static`. The selected mode applies throughout this skill, including delegated reviews and workbench stages; pass it to every delegated agent.

In static mode, assess source and diff evidence only. Do not install dependencies or run builds, tests, reproducers, or the application, including when validation instructions request them. Repository-reading tools remain available. State that runtime checks were not performed; do not count them as passed or require them for this assessment. Missing runtime tooling alone is not a blocker, but a material gap in the source evidence still requires `blocked`.

## Patch Contract

Before editing, inspect the affected implementation, its direct callers, nearby helpers, and relevant existing tests. Establish from repository evidence:

- the attacker-controlled input and concrete source-to-sink path or broken control
- the security invariant and narrowest shared enforcement boundary
- legitimate behavior, APIs, error semantics, and compatibility constraints that must remain
- the closest existing implementation, validation, and error-handling precedents

Treat the finding as a data-flow and boundary problem, not merely the named input example. Check equivalent encodings, parser forms, aliases, callers, sinks, and every representation or copy of security-sensitive state that could bypass the proposed change. Handle unsafe state explicitly; do not silently accept, truncate, or reinterpret it into another reachable form.

## Implementation Workflow

1. Trace the reported path and inspect only the context needed to identify the real shared boundary. Return `no_change` when repository evidence shows that the reported path is already safe; do not make a speculative change.
2. In standard mode, when feasible, run the smallest high-signal reproduction through that boundary and one legitimate control through the same path.
3. Implement the smallest repository-native fix at the shared boundary. Prefer nearby helpers and established APIs. Do not broaden into unrelated redesign, cleanup, or sibling findings.
4. Before verification, challenge the patch rather than defending it: inspect every direct caller of each changed helper and both outcomes of each changed condition. Look for one sibling path, representation, or copy that still reaches the vulnerable sink and one ordinary or default input that the patch newly rejects or reinterprets; revise the implementation if either exists.
5. In standard mode, verify the resulting change:
   - inspect the final diff and run the narrowest syntax, import, build, or type check relevant to it
   - rerun the security trigger or strongest focused substitute and review one alternate malicious input class
   - rerun the legitimate control, nearest existing tests, and the owning package's applicable required checks

In static mode, use these verification gates instead: inspect the final diff; trace the original exploit path and relevant alternate inputs through the changed control; then inspect callers and existing tests as source to establish that legitimate behavior and compatibility remain intact. Cite the source evidence for each gate and identify anything it cannot establish.

Return `blocked` if the vulnerability may be real, but essential evidence, tooling, access, or a product or compatibility decision is missing, so a safe fix cannot be responsibly completed or verified.

## Review the fix

Challenge the patch for surviving bypasses and regressions in legitimate behavior. Use independent investigation or review when the complexity, uncertainty, or security impact warrants it. Give a fresh read-only reviewer the finding, repository root, authorized scope, repository policy, verification mode, and candidate diff so they can assess it from source without the author's rationale or claimed test results. If delegation is unavailable, perform that review as a separate pass.

Confirm review concerns against source or, in standard mode, focused execution before changing the patch. Address only confirmed issues within the finding and compatibility boundary, then repeat the affected verification gates for the selected mode. Revisit the review when a revision changes the security boundary or introduces a new material risk. Ensure no temporary or unrelated changes remain.

## Workbench Remediation Stages

When a Codex Security workbench request includes a scan ID, occurrence ID, remediation request ID, action token, and expected version, follow only the requested remediation stage. The stage boundary changes when code may be written, but it does not weaken the validation requirements above.

- **Generate**: Keep the selected target checkout unchanged. Use an isolated worktree or temporary copy when edits are needed to develop or test the fix. Apply the patch contract and verification requirements above, write one canonical unified diff containing the complete source and regression-test change, then record `generated` or `failed` using the supplied workbench identity.
- **Apply**: Verify the recorded base revision and patch digest, then apply exactly that patch to the selected working tree without unrelated edits. Record `applied` or `failed`. Do not verify or close the finding in this stage.
- **Verify**: Do not modify source. Apply the selected mode's verification gates above against the recorded patch. Record `verified` only when evidence establishes that the original vulnerable path is closed, legitimate behavior remains intact, and the required checks pass; preserve exact evidence and any commands run in the verification summary. Otherwise record `failed` and state the failing gate or proof gap. Do not close the finding.

When a parent thread delegates a remediation stage, the worker owns that stage through its terminal workbench update. The parent remains an orchestrator and must not duplicate the worker's edits or treat a chat response as completion.

## Outcome and Output Contract

Follow the caller's output schema when supplied. Otherwise, include in the final response:

- outcome: `fixed`, `no_change`, or `blocked`
- the concrete vulnerable path, security invariant, and legitimate behavior that had to remain
- the selected patch strategy and why it was the narrowest complete repository-native option, or the unresolved product decision when blocked
- files changed
- tests or validation artifacts added
- commands run and their pass, fail, or unknown results
- evidence that the original vulnerable path is closed, distinguishing source assessment from observed execution
- explicit statement of how legitimate behavior was shown to remain intact
- remaining uncertainty or skipped validation, if any

If using a scan artifact directory, resolve it using `../../references/scan-artifacts.md`, then write a visible report to the fix report path. If there is no existing scan directory, a final chat summary is sufficient unless the user asks for a file.

## Hard Rules

- Do not report `fixed` until every verification gate for the selected mode has passed. Omit a check required by that mode only when repository evidence shows it is irrelevant; an unavailable required check makes verification `blocked` and must be reported.
- In standard mode, do not rely only on code inspection when a focused test or reproducer is feasible.
- Do not broaden the patch into unrelated cleanup, sibling findings, or architectural redesign without evidence that the broader change is required for complete closure.
- Do not remove user changes or unrelated local modifications.
- Do not weaken authentication, authorization, tenant isolation, input validation, sandboxing, or logging to make tests pass.
- Do not hide proof gaps. If the environment blocks validation, say exactly which command or setup failed and what evidence is still missing.
