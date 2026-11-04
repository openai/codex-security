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

Use the bundled verification method included in the request. When its contents are not supplied, read [standard verification](references/verification-standard.md) unless the caller explicitly selects [static verification](../../references/verification-static.md). Pass the selected mode to delegated reviewers and workbench workers.

For a workbench handoff with a scan ID, occurrence ID, remediation request ID, action token, and expected version, read [workbench remediation](references/workbench.md) before any action. The authorized stage governs writes and the terminal state update.

## Patch Contract

Before editing, inspect the affected implementation, its direct callers, nearby helpers, and relevant existing tests. Establish from repository evidence:

- the attacker-controlled input and concrete source-to-sink path or broken control
- the security invariant and narrowest shared enforcement boundary
- legitimate behavior, APIs, error semantics, and compatibility constraints that must remain
- the closest existing implementation, validation, and error-handling precedents

Treat the finding as a data-flow and boundary problem, not merely the named input example. Check equivalent encodings, parser forms, aliases, callers, sinks, and every representation or copy of security-sensitive state that could bypass the proposed change. Handle unsafe state explicitly; do not silently accept, truncate, or reinterpret it into another reachable form.

## Implementation Workflow

1. Trace the reported path and inspect only the context needed to identify the real shared boundary. Return `no_change` when repository evidence shows that the reported path is already safe; do not make a speculative change.
2. Establish the baseline using the selected verification instructions.
3. Implement the smallest repository-native fix at the shared boundary. Prefer nearby helpers and established APIs. Do not broaden into unrelated redesign, cleanup, or sibling findings.
4. Before verification, challenge the patch: inspect every direct caller of each changed helper and both outcomes of each changed condition. Look for one sibling path, representation, or copy that still reaches the vulnerable sink and one ordinary or default input that the patch newly rejects or reinterprets. Revise the implementation if either exists.
5. Assess the final diff and complete the selected verification gates.

Return `blocked` if the vulnerability may be real, but essential evidence, tooling, access, or a product or compatibility decision is missing, so a safe fix cannot be responsibly completed or verified.

## Review the fix

Challenge the patch for surviving bypasses and regressions in legitimate behavior. Use independent investigation or review when the complexity, uncertainty, or security impact warrants it. Give a fresh read-only reviewer the finding, repository root, authorized scope, repository policy, verification mode, and candidate diff so they can assess it from source without the author's rationale or claimed test results. If delegation is unavailable, perform that review as a separate pass.

Confirm review concerns using the selected verification method before changing the patch. Address only confirmed issues within the finding and compatibility boundary, then repeat the affected verification gates for the selected mode. Revisit the review when a revision changes the security boundary or introduces a new material risk. Ensure no temporary or unrelated changes remain.

## Outcome and Output Contract

Use the caller's supplied output contract. For a standalone request without a specified format, follow [the fix summary](references/summary.md).

## Hard Rules

- Do not report `fixed` until every verification gate for the selected mode has passed. Omit a check required by that mode only when repository evidence shows it is irrelevant; an unavailable required check makes verification `blocked` and must be reported.
- Do not broaden the patch into unrelated cleanup, sibling findings, or architectural redesign without evidence that the broader change is required for complete closure.
- Do not remove user changes or unrelated local modifications.
- Do not weaken authentication, authorization, tenant isolation, input validation, sandboxing, or logging to make tests pass.
- Do not hide proof gaps. If the environment blocks validation, say exactly which command or setup failed and what evidence is still missing.
