---
name: security-diff-scan
description: "Use when the user asks for a security review of a pull request, commit, branch diff, working-tree patch, or other Git-backed change set."
---

# Security Diff Scan

Used when a user wants to review a Git-backed change set for security regressions. Keep the scan phases separate and produce the final markdown report.

## Setup Workspace Routing

When this skill is the active top-level workflow, use the setup workspace only when the host context explicitly says it is running inside the Codex desktop app and both required setup continuation tools are available. Tool availability alone does not identify the app host. Otherwise, including Codex CLI interactive and headless runs, use the prompt-only terminal/chat workflow: do not call Codex Security app setup tools, ask the user to press Start scan, or wait for an app-generated `scanId`.

Treat goal creation as scan execution, not setup. In the app setup path, do not create or adopt scan goals before the user presses Start scan, the authoritative scan context has been loaded from a `status: "started"` wait result or a direct continuation with a `scanId`, and the capability preflight has returned `ready`.

For an app continuation that already includes a `scanId` and optional `handoffClaimToken`, do not open another workspace: call `get_codex_security_scan_context` with the `scanId`, pass its `handoffClaimToken` when present, route elsewhere only if its validated mode differs, and use its target, `diffTarget`, optional `userContext`, and `scanDir`.

Otherwise, in a host that renders MCP Apps and exposes the Codex Security setup continuation tools:

1. Resolve setup arguments directly from the user's initial prompt and known thread context: checked-out Git repository `targetPath`, `mode: "diff"`, `scope: "."`, user-supplied security focus as `userContext`, and `diffTarget` only when the prompt unambiguously identifies uncommitted changes against current `HEAD`, one commit, or a locally resolved PR, branch comparison, or revision range.
2. Perform only the minimal path or revision resolution needed to construct those arguments. Do not run capability preflight, inspect the repository beyond that minimal resolution, threat model, discover findings, or create workers before setup opens.
3. Immediately call `open_codex_security_workspace` with the resolved arguments. Do not search for or substitute a separate scan command.
4. Immediately call `await_codex_security_scan_start` with the `sessionId` from the workspace returned by `open_codex_security_workspace`. A returned workspace with `setup.submitted=false` is the expected wait state. Keep the tool call pending while waiting for the user to review setup and press Start scan; do not create or adopt a scan goal, run preflight, or pivot to terminal/chat fallback while waiting.
5. If the wait returns `status: "started"`, require its `scanId`, call `get_codex_security_scan_context` with that `scanId`, and pass its `handoffClaimToken` when present. Then run the preflight in `../../references/config-preflight.md` for the selected target and `security_diff_scan` profile before goal setup, threat modeling, or other substantive scan work.
6. If the wait returns `status: "already_delivered"`, end the current turn without loading scan context or starting scan work. Another continuation already owns the scan.
7. If the wait returns `status: "timed_out"`, end the current turn and tell the user to finish setup and use **Continue in Codex** after pressing Start scan. Do not run preflight, create or adopt a scan goal, open another workspace, or pivot to terminal/chat fallback.
8. Continue after a `ready` result, explaining material warn or suggest limitations. If preflight is `blocked` or `incomplete` with actionable remediation, present the exact reasons and config delta, ask whether to apply the remediation, and stop for the user's answer before creating or adopting a scan goal or calling `fail_codex_security_scan`. Do not fail automatically for declined or unavailable remediation, helper errors, or a non-ready rerun. Preserve the running scan and retry or hand off while recovery may still be possible. If the user declines required remediation, ask whether to cancel or leave the scan running for a later retry. Call `fail_codex_security_scan` with the exact reason only after documented recovery is exhausted and the blocker is confirmed unrecoverable, or when the user explicitly cancels.

Before opening setup, use the existing terminal/chat preflight and scan workflow for local changes against another requested base because the setup app cannot represent that working-tree diff target. Codex CLI, including interactive and headless runs, and hosts without the required app capabilities use the same prompt-only fallback. Do not call `open_codex_security_workspace` or `await_codex_security_scan_start` on this path. Once `open_codex_security_workspace` succeeds in an MCP Apps-capable host, remain on the app path: immediately call `await_codex_security_scan_start`; a `status: "timed_out"` result means end the turn and point the user to **Continue in Codex**, while `status: "already_delivered"` means stop because another continuation owns the scan. Do not start a terminal/chat fallback for either result.

## Capability Preflight

Read `../../references/config-preflight.md` and dispatch and await the preflight execution described there with the `security_diff_scan` capability profile before substantive scan work, including after an app wait or direct continuation has produced a `scanId` and loaded its authoritative scan context. Follow the returned block/warn/suggest results. For an app-generated scan, ask before applying actionable remediation and wait without creating a scan goal or calling `fail_codex_security_scan`. Do not fail automatically for declined or unavailable remediation, helper errors, or a non-ready rerun; preserve the running scan and retry or hand off while recovery may still be possible. Call `fail_codex_security_scan` only after documented recovery is exhausted and the blocker is confirmed unrecoverable, or when the user explicitly cancels. Do not treat a config value that differs from a suggested patch as a warning unless the capability requirement itself is unmet.

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
Treat explicit invocation of this exhaustive diff-scan workflow as the user's authorization to use the subagents required by the workflow. If subagents are unavailable in the current environment, explain the limitation instead of claiming exhaustive diff coverage.

## Goal Setup

After the app wait or direct continuation has provided a `scanId`, the authoritative scan context has been loaded, and the `security_diff_scan` capability preflight has returned `ready`, or after the same preflight is `ready` in Codex CLI or terminal/chat hosts without the setup app, create a Codex goal for the scan if the runtime exposes goal tools and no active goal already covers this scan. The objective should state that the scan must not stop until the resolved diff-scoped files have been covered and the required coverage artifacts prove that closure.

Use objective wording shaped like:

`Run the Codex Security diff scan for <resolved target>; do not stop until every diff-scoped file/worklist row has a completion receipt or explicit deferred closure, every candidate has required ledger receipts, and the final report is written.`

If a compatible active goal already exists, continue under it instead of creating a duplicate. If goal tools are unavailable, state the same coverage objective in the first visible scan update and continue.

Do not mark the goal complete until:

- every `deep_review_input.jsonl` row has a completion receipt in `work_ledger.jsonl`, or an explicit `deferred`, `not_applicable`, or `suppressed` closure with exact reason
- every candidate that reached discovery has the required discovery, validation, and attack-path ledger receipts, or an explicit deferred reason for the missing proof
- the final markdown report has been written to the resolved scan path

## Artifact Resolution

The path references in this skill are the default locations for this phase.
If the user explicitly provides a different path for a required input or output, use the user-provided path instead of the corresponding default path referenced in this skill.
If a required input is still missing, stop and ask the user for it before continuing.
Use the shared scan artifact path conventions in `../../references/scan-artifacts.md`.

## Execution Plan

Start this plan only after `Setup Workspace Routing` has either loaded the app-generated scan context with a `scanId`, or determined that the host is using the non-app terminal/chat workflow, and the `security_diff_scan` capability preflight has returned `ready`.

Follow this plan in order. Do not skip ahead to a later phase until the current phase has produced its intended output.

1. Resolve the Git-backed scan target, `repo_name`, `security_scans_dir`, `scan_id`, `scan_dir`, and `artifacts_dir` using `../../references/scan-artifacts.md`.
2. Create or adopt the scan goal described in `Goal Setup` for that active scan context.
3. Read `../../references/security-guidance.md`, compile the repository's policy to `<context_dir>/security_guidance.md`, and read it before threat modeling or inspecting source code.
4. Run `$threat-model` first.
  - Copy the repository-scoped threat model to the per-scan threat model path without alteration for auditability.
  - Treat the per-scan threat model path as the source of truth threat model for later phases.
5. Run `$finding-discovery` as the second step, against the resolved diff and using the per-scan threat model as context.
  - If discovery produces no technically plausible candidates, stop there, skip validation and attack-path analysis, complete the canonical JSON contract, and finalize the scan.
6. Run `$validation` as the third step, for each candidate that came out of discovery.
  - Pass the resolved diff scope, discovery notes, and candidate inventory to validation. Validation should preserve or suppress the provided instances; it should not independently broaden the review into a repository-wide scan.
  - Each candidate finding's `findings/<candidate_id>/candidate_ledger.jsonl` is part of the validation input. Every candidate finding that came out of discovery must have a discovery receipt before validation starts and a validation receipt before the scan can proceed to final reporting.
7. Run `$attack-path-analysis` as the fourth step, for findings that still need reportability, attack-path, and severity analysis after validation.
  - Each candidate finding's `findings/<candidate_id>/candidate_ledger.jsonl` is part of the attack-path input. Every candidate finding that reaches attack-path analysis must have an attack-path receipt before final reporting, even when the final decision is `ignore`, suppressed, or deferred.
8. Assemble the complete canonical JSON contract last using `../../references/final-report.md`; do not author `report.md`.
  - Populate the optional structured details in `../../references/finding-detail-fields.md` from the same validated evidence used in the generated report.
  - For every reportable finding, run `$vulnerability-writeup` with exactly one dedicated write-up sub-agent. Give it only that finding, its validation and attack-path evidence, relevant source paths and revision, PoC inputs, and the target output directory.
  - Write the derived report to `findings/<slug>/<slug>.md` with supporting PoC files under `findings/<slug>/poc/`. Verify the report is a regular file, then set that finding's `writeup.reportPath` to the matching safe relative path. Do not add the derived report to the sealed artifact list.
  - After every write-up is ready, run `$propose-security-hardening` once over the complete finding collection, detailed write-ups, threat model, coverage, and relevant source. Write its portfolio to `hardening/hardening.md`, its structured analysis to `hardening/hardening.json`, and any proposals and diagrams below `hardening/`. Verify `hardening/hardening.md` is a regular file, then set `scan.hardening.portfolioPath` to the fixed relative path `hardening/hardening.md`. Do not add these derived files to the sealed artifact list. Skip this step and omit `scan.hardening` when there are no reportable findings.
  - Complete the scan once, after all write-ups, hardening guidance, and canonical JSON are ready, so finalization projects the validated JSON and derived-document links into `report.md`. In the terminal/chat workflow without `complete_codex_security_scan`, run `python <plugin_dir>/scripts/finalize_scan_contract.py --scan-dir <scan_dir> --source-root <repo_root>` directly.

## Phase Scope

- Phase 1 (threat model generation) is repository-scope by default, unless the user explicitly asks for narrower scope or provides an authoritative threat model or sufficiently repository-specific security scan guidance such as `AGENTS.md`.
- Phase 2 onward (finding discovery, validation, attack path analysis) are diff-focused and should follow the changed code and its supporting files.

Treat this asymmetry as intentional:

- use the diff to locate the scan target for later phases
- do not let the diff bias Phase 1 threat model generation, if applicable
- do not let the touched subsystem become the repository threat model unless the user explicitly asks for that narrower scope

## Scan Target

Resolve the exact Git-backed diff before starting:

- PR: compare base branch against current `HEAD`
- commit: scan the target commit against its parent or requested baseline
- branch diff: scan the requested merge-base to head range
- local patch: scan staged and unstaged working-tree changes against the requested base

## Diff-Scoped Discovery

Use `../security-scan/references/scan-artifacts-and-ledger.md` for the shared scoped file-review, candidate-ledger, subagent, and dedupe rules.

Diff scans should:

- generate `rank_input.jsonl` deterministically from changed source-like files with `<python_command> <plugin_dir>/scripts/generate_rank_input.py make-diff-rank-input --repo <repo_root> --base <base> --mode revisions --head <head> --out <discovery_dir>/rank_input.jsonl` for PR, commit, and branch diffs, or `<python_command> <plugin_dir>/scripts/generate_rank_input.py make-diff-rank-input --repo <repo_root> --base <base> --mode local-patch --out <discovery_dir>/rank_input.jsonl` for a local patch
- copy every diff row into `deep_review_input.jsonl` with `<python_command> <plugin_dir>/scripts/generate_rank_input.py copy-deep-review-input --rank-input <discovery_dir>/rank_input.jsonl --out <discovery_dir>/deep_review_input.jsonl`
- deep-review every file in `deep_review_input.jsonl`
- add directly supporting files only when repository evidence shows they are needed to understand the changed security behavior
- stay anchored to the changed code and directly supporting files rather than broadening into unrelated repository-wide enumeration

## Diff-Scoped Sibling Coverage

For PR, commit, branch, and local-patch scans, stay diff-focused but preserve repeated vulnerable instances that are created or affected by the same changed pattern.

Diff scans should:

- start from the changed files and the supporting files needed to understand the changed behavior
- expand from a changed route, handler, shared helper, guard, template pattern, query builder, serializer/deserializer, filesystem/network sink, config block, or wrapper to sibling instances that the diff also changes, newly reaches, or affects through the same modified shared dependency
- when the diff adds, removes, or reshapes a guard around an existing parser, deserializer, expression evaluator, filesystem/path helper, archive utility, or auth/authz helper, use the adjacent pre-existing sink/control as supporting context for the changed behavior; keep the candidate anchored to the changed guard or newly exposed path unless the user explicitly asks for wider instance expansion
- when a changed wrapper, guard, or API delegates to a shared parser/deserializer/path/archive/auth helper, keep both the wrapper call site and the underlying shared sink/control line addressable; do not replace the root sink/control evidence with wrapper-only evidence
- carry each vulnerable sibling instance through discovery and validation with its own affected location, source, closest control, sink, impact, and suppression evidence
- use unchanged siblings as context and negative controls, but report them only when the diff makes them newly vulnerable or changes the shared control or sink they depend on
- stop when the diff-linked pattern family is exhausted, rather than broadening into repository-wide enumeration

This keeps diff scans precise while avoiding the common failure mode where one representative route or sink hides additional vulnerable siblings introduced by the same patch.

## Final Output

Populate all final report semantics in the canonical manifest, findings, and coverage JSON using `../../references/final-report.md`. Generate one detailed `vulnerability-writeup` for every reportable finding, then run `propose-security-hardening` once over the complete collection and record the safe derived-document paths. Complete the scan once after both stages; finalization owns `report.md` generation. Emit Codex app review directives from the completed canonical findings. Commit scans use this same final-output contract because they are a diff-scan target type.

## Hard Rules

Read `../../references/shared-hard-rules.md` before applying scan-mode-specific hard rules.

- After any app setup handoff has provided a `scanId`, or in the non-app terminal/chat workflow, create or adopt the scan goal only after the capability preflight has returned `ready`, and before substantive scan work. Do not complete it until the resolved diff-scoped files/worklist rows, candidate ledgers, and final report meet the `Goal Setup` closure criteria.
- Do not claim diff coverage until every `deep_review_input.jsonl` row has a completion receipt in `work_ledger.jsonl`.
