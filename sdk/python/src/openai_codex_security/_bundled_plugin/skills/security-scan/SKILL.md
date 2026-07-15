---
name: security-scan
description: "Use for a standard, single-pass security audit of an entire repository or a scoped path, package folder, or submodule with no diff to review.  This is the default repository scan.  Do not use for PR/commit/branch/working-tree diffs, or for deep, multi-pass, or variance-reducing scans."
---

# Security Scan

Used when a user wants to audit an entire repository or a user-specified path, package, folder, or submodule-like scope for security vulnerabilities. Keep the scan phases separate and produce the final markdown report.

## Setup Workspace Routing

When this skill is the active top-level workflow, use the setup workspace only when the host context explicitly says it is running inside the Codex desktop app and both required setup continuation tools are available. Tool availability alone does not identify the app host. Otherwise, including Codex CLI interactive and headless runs, use the prompt-only terminal/chat workflow: do not call Codex Security app setup tools, ask the user to press Start scan, or wait for an app-generated `scanId`.

Scanbench and Promptfoo evaluations are headless runs even when MCP app tools are listed. On those paths, never call `open_codex_security_workspace` or `await_codex_security_scan_start`; use the prompt-only terminal/chat workflow.

Treat goal creation as scan execution, not setup. In the app setup path, do not create or adopt scan goals before the user presses Start scan, the authoritative scan context has been loaded from a `status: "started"` wait result or a direct continuation with a `scanId`, and the capability preflight has returned `ready`.

For an app continuation that already includes a `scanId` and optional `handoffClaimToken`, do not open another workspace: call `get_codex_security_scan_context` with the `scanId`, pass its `handoffClaimToken` when present, route elsewhere only if its validated mode differs, and use its target, scope, optional `userContext`, and `scanDir`.

Otherwise, in a host that renders MCP Apps and exposes the Codex Security setup continuation tools:

1. Resolve setup arguments directly from the user's initial prompt and known thread context: local `targetPath`, `mode: "standard"`, target-relative `scope` (`"."` for the whole target), and only user-supplied security focus as `userContext`.
2. Perform only the minimal path resolution needed to construct those arguments. Do not run capability preflight, inspect the repository, threat model, discover findings, or create workers before setup opens.
3. Immediately call `open_codex_security_workspace` with the resolved arguments. Do not search for or substitute a separate scan command.
4. Immediately call `await_codex_security_scan_start` with the `sessionId` from the workspace returned by `open_codex_security_workspace`. A returned workspace with `setup.submitted=false` is the expected wait state. Keep the tool call pending while waiting for the user to review setup and press Start scan; do not create or adopt a scan goal, run preflight, or pivot to terminal/chat fallback while waiting.
5. If the wait returns `status: "started"`, require its `scanId`, call `get_codex_security_scan_context` with that `scanId`, and pass its `handoffClaimToken` when present. Then run the preflight in `../../references/config-preflight.md` for the selected target and `security_scan` profile before goal setup, threat modeling, or other substantive scan work.
6. If the wait returns `status: "already_delivered"`, end the current turn without loading scan context or starting scan work. Another continuation already owns the scan.
7. If the wait returns `status: "timed_out"`, end the current turn and tell the user to finish setup and use **Continue in Codex** after pressing Start scan. Do not run preflight, create or adopt a scan goal, open another workspace, or pivot to terminal/chat fallback.
8. Continue after a `ready` result, explaining material warn or suggest limitations. If preflight is `blocked` or `incomplete` with actionable remediation, present the exact reasons and config delta, ask whether to apply the remediation, and stop for the user's answer before creating or adopting a scan goal or calling `fail_codex_security_scan`. Do not fail automatically for declined or unavailable remediation, helper errors, or a non-ready rerun. Preserve the running scan and retry or hand off while recovery may still be possible. If the user declines required remediation, ask whether to cancel or leave the scan running for a later retry. Call `fail_codex_security_scan` with the exact reason only after documented recovery is exhausted and the blocker is confirmed unrecoverable, or when the user explicitly cancels.

In Codex CLI, including interactive and headless runs, or hosts without those capabilities, use the existing prompt-only terminal/chat preflight and scan workflow and shared artifact paths. Do not call `open_codex_security_workspace` or `await_codex_security_scan_start` on this path. Once `open_codex_security_workspace` succeeds in an MCP Apps-capable host, remain on the app path: immediately call `await_codex_security_scan_start`; a `status: "timed_out"` result means end the turn and point the user to **Continue in Codex**, while `status: "already_delivered"` means stop because another continuation owns the scan. Do not start a terminal/chat fallback for either result.

## Capability Preflight

Read `../../references/config-preflight.md` and dispatch and await the preflight execution described there with the `security_scan` capability profile before substantive scan work, including after an app wait or direct continuation has produced a `scanId` and loaded its authoritative scan context. Follow the returned block/warn/suggest results. For an app-generated scan, ask before applying actionable remediation and wait without creating a scan goal or calling `fail_codex_security_scan`. Do not fail automatically for declined or unavailable remediation, helper errors, or a non-ready rerun; preserve the running scan and retry or hand off while recovery may still be possible. Call `fail_codex_security_scan` only after documented recovery is exhausted and the blocker is confirmed unrecoverable, or when the user explicitly cancels. Do not treat a config value that differs from a suggested patch as a warning unless the capability requirement itself is unmet.

## Phase Sequence

Keep these phases distinct and run them in linear order:

1. `$threat-model`
2. `$finding-discovery`
3. `$validation`
4. `$attack-path-analysis`
5. Generate final output

Treat this skill as the top-level orchestrator for the four skills plus the final report assembly step. Do not collapse the phases together.

For each phase:
1. Read that phase's skill.
2. Load only the inputs required for that phase.
3. Complete that phase's workflow and checklist.
4. Only then read the next phase's skill.

Do not read ahead into later-phase skills until the current phase has completed.
Do not amortize effort across phases: complete each phase to the full depth expected by that phase before moving on.
For repository-wide and scoped-path scans, treat explicit invocation of this exhaustive scan workflow as the user's authorization to use the subagents required by the workflow. If subagents are unavailable in the current environment, explain the limitation instead of claiming exhaustive scan coverage.

## Goal Setup

After the app wait or direct continuation has provided a `scanId`, the authoritative scan context has been loaded, and the `security_scan` capability preflight has returned `ready`, or after the same preflight is `ready` in Codex CLI or terminal/chat hosts without the setup app, create a Codex goal for the scan if the runtime exposes goal tools and no active goal already covers this scan. The objective should state that the scan must not stop until the resolved files in scope have been covered and the required coverage artifacts prove that closure.

Use objective wording shaped like:

`Run the Codex Security repository/scoped-path scan for <resolved target>; do not stop until every in-scope file/worklist row has a completion receipt or explicit deferred closure, every candidate has required ledger receipts, and the final report is written.`

If a compatible active goal already exists, continue under it instead of creating a duplicate. If goal tools are unavailable, state the same coverage objective in the first visible scan update and continue.

Do not mark the goal complete until:

- every file or worklist row in the resolved scope has a completion receipt, or an explicit `deferred`, `not_applicable`, or `suppressed` closure with exact reason
- every candidate that reached discovery has the required discovery, validation, and attack-path ledger receipts, or an explicit deferred reason for the missing proof
- the final markdown report has been written to the resolved scan path

## Artifact Resolution

The path references in this skill are the default locations for this phase.
If the user explicitly provides a different path for a required input or output, use the user-provided path instead of the corresponding default path referenced in this skill.
If a required input is still missing, stop and ask the user for it before continuing.
Use the shared scan artifact path conventions in `../../references/scan-artifacts.md`.

## Execution Plan

Start this plan only after `Setup Workspace Routing` has either loaded the app-generated scan context with a `scanId`, or determined that the host is using the non-app terminal/chat workflow, and the `security_scan` capability preflight has returned `ready`.

Follow this plan in order. Do not skip ahead to a later phase until the current phase has produced its intended output.

1. Resolve the scan target, `repo_name`, `security_scans_dir`, `scan_id`, `scan_dir`, and `artifacts_dir` using `../../references/scan-artifacts.md`.
2. Create or adopt the scan goal described in `Goal Setup` for that active scan context.
3. Read `../../references/security-guidance.md`, compile the resolved scan target's policy to `<context_dir>/security_guidance.md`, and read it before threat modeling or inspecting source code.
4. Run `$threat-model` first.
  - Copy the repository-scoped threat model to the per-scan threat model path without alteration for auditability.
  - Treat the per-scan threat model path as the source of truth threat model for later phases.
5. Run `$finding-discovery` as the second step, against the resolved repository or scoped path and using the per-scan threat model as context.
  - Stop at discovery only when the ranked runtime-surface worklist exists and the coverage ledger has closed every applicable high-impact and seeded root-control row as `suppressed`, `not_applicable`, or `deferred` with exact reasons. Open, reportable, or unresolved seeded rows continue to validation even when they are not yet numbered as findings.
6. Run `$validation` as the third step, for each candidate that came out of discovery and each open, reportable, or deferred seeded/root-control ledger row that still needs closure.
  - Pass the resolved scan scope, discovery notes, and candidate inventory to validation. Validation should preserve or suppress the provided instances; it should not independently broaden or narrow the requested repository or scoped-path scan.
  - Each candidate finding's candidate-ledger path from `../../references/scan-artifacts.md` is part of the validation input for every scan scope. Every candidate finding that came out of discovery must have a discovery receipt before validation starts and a validation receipt before the scan can proceed to final reporting.
  - For repository-wide and scoped-path scans, the discovery worklists, work ledger, raw candidates, per-finding candidate ledgers, deduped candidates, and discovery coverage ledger from `../../references/scan-artifacts.md` are part of the validation input; the ledger is a coverage artifact, not just a findings tracker. Raw candidates should already include the discovering file-review subagent's or parent agent's candidate-local validation evidence and attack-path facts before dedupe, and each per-finding candidate ledger should prove that its raw candidate finding received both checks or has an explicit deferred reason. Validation should preserve checked surfaces with not_applicable, suppressed, deferred, and reportable dispositions, reconcile cross-file proof gaps, and continue the ledger's high-impact sibling checks when needed rather than narrowing to one representative finding.
  - When multiple candidates or coverage-ledger rows need validation and subagents are available under the resolved scan authorization, divide validation across validation subagents by candidate, deduped candidate, or ledger row. Each validation subagent must receive the candidate or row, discovery evidence, artifact paths, and candidate-ledger path it owns, then write or return the validation report update and validation receipt for that assignment.
  - As coverage-ledger rows are validated, keep the saved per-finding validation reports current enough that reportable, suppressed, not_applicable, and deferred closure rows survive interruption or later phase summarization, including exact root-control file:line and seed-anchor file:line when distinct.
7. Run `$attack-path-analysis` as the fourth step, for findings and validation closure rows that still need reportability, attack-path, and severity analysis after validation.
  - Each candidate finding's candidate-ledger path from `../../references/scan-artifacts.md` is part of the attack-path input for every scan scope. Every candidate finding that reaches attack-path analysis must have an attack-path receipt before final reporting, even when the final decision is `ignore`, suppressed, or deferred.
  - When multiple validated candidates or validation closure rows need attack-path analysis and subagents are available under the resolved scan authorization, divide attack-path work across attack-path subagents by candidate or row. Each attack-path subagent must receive the validation evidence, affected root-control and sink lines, artifact paths, and candidate-ledger path it owns, then write or return attack-path facts, severity/policy analysis, and the attack-path receipt for that assignment.
8. Assemble the complete canonical JSON contract last using `../../references/final-report.md`; do not author `report.md`.
  - For a whole-repository Deep scan, keep `coverage.inventoryStrategy` as `repository`; repeated discovery is workflow metadata, not a different inventory strategy.
  - Populate the optional structured details in `../../references/finding-detail-fields.md` from the same validated evidence used in the generated report.
  - For every reportable finding, run `$vulnerability-writeup` with exactly one dedicated write-up sub-agent. Give it only that finding, its validation and attack-path evidence, relevant source paths and revision, PoC inputs, and the target output directory.
  - Write the derived report to `findings/<slug>/<slug>.md` with supporting PoC files under `findings/<slug>/poc/`. Verify the report is a regular file, then set that finding's `writeup.reportPath` to the matching safe relative path. Do not add the derived report to the sealed artifact list.
  - After every write-up is ready, run `$propose-security-hardening` once over the complete finding collection, detailed write-ups, threat model, coverage, and relevant source. Write its portfolio to `hardening/hardening.md`, its structured analysis to `hardening/hardening.json`, and any proposals and diagrams below `hardening/`. Verify `hardening/hardening.md` is a regular file, then set `scan.hardening.portfolioPath` to the fixed relative path `hardening/hardening.md`. Do not add these derived files to the sealed artifact list. Skip this step and omit `scan.hardening` when there are no reportable findings.
  - Complete the scan once, after all write-ups, hardening guidance, and canonical JSON are ready, so finalization projects the validated JSON and derived-document links into `report.md`. In the terminal/chat workflow without `complete_codex_security_scan`, run `python <plugin_dir>/scripts/finalize_scan_contract.py --scan-dir <scan_dir> --source-root <repo_root>` directly.

## Completion Boundary

Completion is finalization only for every scan mode. Before calling `complete_codex_security_scan` or the terminal/chat finalizer, verify on disk that the completed canonical `scan-manifest.json`, `findings.json`, and `coverage.json` exist at the workflow-owned scan path. Completion validates and seals those already-authored files and generates `report.md`; it does not create missing artifacts or run skipped validation, attack-path, or reporting-assembly phases.

If a required phase, canonical-artifact write, or on-disk existence check fails before completion, stop the current response and surface that exact workflow blocker. Do not call completion with missing artifacts, emit a final report, return a no-findings result, satisfy a structured output schema, or emit benchmark JSON. Leave the durable scan available for a later continuation unless an independent unrecoverable blocker or explicit cancellation requires a terminal action.

If `complete_codex_security_scan` or the terminal/chat finalizer fails, stop the current response and surface the exact MCP or finalizer error. Do not retry completion in the same response, emit a final report, return a no-findings result, satisfy a structured output schema, or emit benchmark JSON. Do not call `cancel_codex_security_scan` or `fail_codex_security_scan` solely because completion failed; leave the durable scan available for a later continuation unless an independent unrecoverable blocker or explicit cancellation requires a terminal action.

## Scan Scope

- Phase 1 (threat model generation) is repository-scope by default, unless the user explicitly asks for narrower scope or provides an authoritative threat model or sufficiently repository-specific security scan guidance such as `AGENTS.md`.
- Phase 2 onward (finding discovery, validation, attack path analysis) remain within the resolved repository or scoped path. For repository-wide scans, the entire checked-out repository is in scope. For scoped-path scans, the requested path, package, folder, or submodule-like boundary is in scope together with directly supporting files needed to understand concrete findings.
- Before the `$finding-discovery` phase, read `references/repository-wide-scan.md` and every required reference it lists, then use them for finding discovery, validation, and attack path analysis.

## Scan Target

Resolve the requested audit scope before starting:

- repository-wide: scan the entire checked-out repository
- scoped path: scan the user-specified path, package, folder, or submodule-like boundary inside the checked-out repository

Treat the resolved repository or scoped path as the in-scope codebase for the later phases of this workflow.

## Scoped Exhaustive Mode

For repository-wide and scoped-path scans, follow `references/repository-wide-scan.md` and every required reference it lists.

Treat explicit invocation of this repository-wide or scoped-path exhaustive scan workflow as the user's authorization to use the subagents required by the workflow. If subagents are unavailable, do not claim exhaustive coverage; explain the limitation and offer the narrower parent-agent-only path only if it can still satisfy the requested scope honestly.

Use the per-scan artifact directory layout from `../../references/scan-artifacts.md`.

## Final Output

Populate all final report semantics in the canonical manifest, findings, and coverage JSON using `../../references/final-report.md`. Generate one detailed `vulnerability-writeup` for every reportable finding, then run `propose-security-hardening` once over the complete collection and record the safe derived-document paths. Complete the scan once after both stages; finalization owns `report.md` generation. Emit Codex app review directives from the completed canonical findings.

## Hard Rules

Read `../../references/shared-hard-rules.md` before applying scan-mode-specific hard rules.

- After any app setup handoff has provided a `scanId`, or in the non-app terminal/chat workflow, create or adopt the scan goal only after the capability preflight has returned `ready`, and before substantive scan work. Do not complete it until the resolved in-scope files/worklist rows, candidate ledgers, and final reports meet the `Goal Setup` closure criteria.
- For repository-wide and scoped-path scans, do not equate broad sink counts with completed coverage. The coverage ledger must close each applicable high-impact shard row as `reportable`, `suppressed`, `not_applicable`, or `deferred`.
- For every scan scope, candidate-finding coverage is required. Do not finalize a candidate finding until its candidate-ledger path from `../../references/scan-artifacts.md` shows discovery, validation, and attack-path receipts for that exact candidate, or an explicit deferred reason for the missing proof.
- For repository-wide and scoped-path scans, subagent dispatch must have explicit ownership: each of no more than six ranking subagents owns one static `rank_worker_assignments.json` pool slot containing one or more generated `rank_shards/*.input.jsonl` shards of at most 150 rows, processes its ordered list sequentially, and writes only the matching worker-local `.output.jsonl` files; file-review subagents own one assessed file or tiny shard and return full-file receipts plus pre-dedupe finding objects with candidate-local validation evidence and attack-path facts; validation subagents own one candidate or ledger row that needs validation closure; attack-path subagents own one validated candidate or validation closure row; the parent agent owns bounded worker orchestration, ledger reconciliation, aggregation, cross-file dedupe, and final closure.
- For repository-wide and scoped-path scans, candidate-finding coverage is separate from file coverage. Do not dedupe or finalize a raw candidate finding until its candidate-ledger path from `../../references/scan-artifacts.md` shows candidate-local validation and candidate-local attack-path receipts, or an explicit deferred reason for missing proof.
- Candidate ids are optional links from coverage rows to findings; a not_applicable, suppressed, or deferred row is still required when the surface was in scope.
- For repository-wide and scoped-path scans, the ranked runtime-surface worklist must exist before discovery is considered complete, and the coverage ledger must be materially broader than the promoted candidate list.
- For repository-wide and scoped-path scans with CVE, GHSA, advisory, issue, release, or package-version identifiers, `seed_research.md` must exist before discovery is considered complete. It should record authoritative sources searched, candidate files/functions/classes/hunks, and failed lookup attempts. Missing seed research means advisory-led discovery is incomplete unless the scan explicitly states that no network/local-history source was available.
- In large repository-wide scans, checkpoint the ranked runtime-surface worklist and initial coverage ledger to disk before deep sink review or validation. A run that is interrupted after frontier mapping should still leave auditable coverage artifacts.
- In large monorepos, top product/runtime areas by file count or deployment significance must appear as ledger shards or be explicitly excluded with repository evidence; global sink counts and `no top candidate surfaced` do not close coverage.
- User/advisory/tag-seeded packages, class families, or vulnerability families remain open until the exact seeded row is closed as `reportable`, `suppressed`, `not_applicable`, or `deferred`. A neighboring same-family finding does not close the seeded row.
- For large repository-wide scans, make one reachability pass across every applicable high-impact shard before prolonged validation of any single shard. A row becomes a validation candidate only when it has a concrete entrypoint or privileged boundary, closest relevant control, sink or broken control, and plausible impact.
- Discovery is incomplete when a shard has a promoted finding but still has unclosed sibling packages, concrete implementations, or reusable root-control rows that could be independently vulnerable. Finish those rows or mark them explicitly deferred before final reporting.
- Final assembly must start from reportable validation closure rows and surviving candidates. Do not drop a reportable seeded/root-control row because attack-path analysis or discovery spent more prose on a neighboring same-family finding.
- Final reporting is incomplete when a promoted high-impact finding's affected lines omit the concrete root-control file/line discovered or seeded during discovery, such as a codec, converter, parser feature setup, class filter, resource-path control, protocol state transition, or self-service update guard. Add the root-control affected line or explicitly suppress/defer it with exact counterevidence before finalizing.
- In repository-wide and scoped-path scans, preserve independently reachable sibling instances through final reporting. Repeated vulnerable templates, query builders, parser operations, auth/object endpoints, or shared-helper callers need separate finding entries, affected lines, and dispositions; put grouping in summary prose only after the individual instances are emitted.
- For query/parser injection, do not suppress syntax-control evidence solely because a later business check appears to limit impact. Carry the injection candidate until validation proves the exact query API and post-query guard defeat semantic change for that instance.
- If large-repository scope forces deferral, make the final report explicit about which deployed or privileged areas and vulnerability families remain deferred.
