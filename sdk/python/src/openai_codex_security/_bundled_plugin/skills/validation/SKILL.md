---
name: validation
description: Use when Codex is already in the validation phase of a security scan or the user explicitly asks to determine whether one or more candidate security findings are valid. Do not use as the primary trigger for full PR, commit, branch, patch, or repository scans.
---

# Security Validation

## Objective

Take candidate findings from discovery and produce the strongest evidence-backed validation assessment you can. Prefer targeted, non-interactive reproduction or falsification when it is feasible and proportionate, but use focused code tracing when dynamic execution is blocked by missing services, unavailable infrastructure, or excessive setup relative to the candidate and scan scope.

## Artifact Resolution

The path references in this skill are the default locations for this phase.
If the user explicitly provides a different path for a required input or output, use the user-provided path instead of the corresponding default path referenced in this skill.
If a required input is still missing, stop and ask the user for it before continuing.
Use the shared scan artifact path conventions in `../../references/scan-artifacts.md`.

## Workflow

1. Before starting, create a detailed validation rubric with up to five criteria for the candidate.
2. For each candidate finding, identify the claimed attacker input, vulnerable sink, and preconditions.
3. Choose the validation path using the strongest realistic method available:
   - crash: for crash, memory-corruption, parser-confusion, or denial-of-service candidates, attempt to compile a debug variant and produce a crashing PoC when the project can be built with bounded effort.
   - valgrind or ASan: if a memory-safety or crash candidate does not immediately reproduce and the build supports it, attempt valgrind and/or ASan.
   - debugger: if runtime execution is available but the chain is unclear, attempt a non-interactive debugger trace with gdb/lldb that shows the source-to-sink path.
   - unit or integration test: if the vulnerable path is covered by an existing test harness, add or adapt the smallest focused test that exercises the vulnerable code and asserts the vulnerable behavior.
   - realistic interface reproduction: if the code exposes a real user-reachable interface such as HTTP, CLI, file parser, RPC, message queue, plugin hook, or package API, attempt a minimal end-to-end reproduction through that interface using crafted input that reaches the suspected sink.
   - code understanding: if dynamic reproduction is not feasible or proportionate after bounded attempts, follow the static finding assessment reference in `../../references/static-finding-assessment.md` to trace source, control, sink, reachability, boundary evidence, counterevidence, and proof gaps.
   - large internal repository mode: for repository-wide or scoped-path scans where runtime reproduction requires unavailable internal services, secrets, cloud accounts, service meshes, or local production data, use the static finding assessment reference plus existing tests and deploy/config evidence once the candidate has a complete source/control/sink/impact tuple. Missing internal runtime setup is not suppression evidence.
4. For non-compiled stacks, attempt to generate PoCs or targeted commands that exercise the vulnerable path and trigger the vulnerability.
5. For compiled stacks, prefer dynamic validation when it is feasible with bounded setup: build a debug variant or targeted test harness when available, reproduce the vulnerable behavior with a small PoC, then use valgrind, ASan, or a non-interactive debugger trace when those tools materially improve confidence.
6. Save any PoC files, inputs, or logs under that finding's validation artifacts path from `../../references/scan-artifacts.md`.
7. If validation is not feasible, document what was tried, what remains uncertain, and the exact proof gap.
8. Return a clear validation assessment per finding grounded in the evidence, proof gaps, and remaining uncertainty.
9. Save that finding's visible validation report to its per-finding validation report path from `../../references/scan-artifacts.md`.
10. Append one validation receipt per candidate id to that finding's candidate ledger path from `../../references/scan-artifacts.md`. The receipt must record the validation method, evidence or exact proof gap, disposition, and validation artifact/report reference for that candidate finding.

## Usage Guidance

- Prefer short, bounded commands (git, grep -nI within changed dirs, build/test runners, minimal PoCs).
- Avoid interactive editors (vi), long-running repo-wide scans, and network access unless essential.
- If you need to use debuggers, invoke them non-interactively (gdb: "-q -batch -ex run -ex bt -ex quit"; lldb: "-b -o run -o bt -o quit").
- When creating PoCs to validate the vulnerability, you should attempt to trigger them against the actual application/library directly. Ideally this shows how an attacker would trigger the bug.

## Validation Guidance

Follow the instance-preserving validation rules, validation checklist, and confidence guidance in `references/validation-guidance.md`.
When validation falls back to static code understanding, or when static evidence is proportionate for large internal repositories, use the shared source/control/sink, boundary, counterevidence, and proof-gap guidance in `../../references/static-finding-assessment.md`.

## Output Contract

For each candidate finding, include:

- finding title
- candidate id, instance key, and ledger row id when provided
- root-control file:line and affected-location labels from discovery when provided
- advisory/source reference and seed anchor file:line when provided, especially when distinct from the root-control line
- confidence level
- validation method used or recommended
- rubric checklist with `- [x]` or `- [ ]` items
- evidence observed
- concise notes on what was tested
- remaining uncertainty
- minimal next step if more proof is needed
- artifact paths when validation files or logs were created
- enough detail that a later reader can tell whether the finding survived validation without relying on a separate status label

For repository-wide and scoped-path scans, also include a validation closure table with columns:

- ledger row id
- instance key
- advisory/source reference when available
- seed anchor file:line when distinct from the root-control
- root-control file:line
- entrypoint/source
- sink/control
- disposition: `reportable`, `suppressed`, `not_applicable`, or `deferred`
- counterevidence or proof gap
- survives: `yes`, `no`, or `uncertain`

## Hard Rules

- Do not imply validation happened when it did not.
- Do not leave candidate coverage implicit. Every candidate finding that enters validation must leave a validation receipt in its candidate-ledger path from `../../references/scan-artifacts.md`, even when the result is suppressed, uncertain, or deferred.
- Prefer realistic local reproduction paths over contrived setups.
- If a finding depends on missing product assumptions, state the question clearly instead of fabricating the answer.
- Keep commands short, bounded, and non-interactive.
- Use stronger validation methods such as crashing PoCs, valgrind, ASan, debugger traces, focused tests, or realistic interface reproduction before falling back to code understanding when the stack and scan scope make that feasible.
- Calibrate confidence from the validation method and evidence, not from how dangerous the bug class sounds.
- Keep validation artifacts and the final visible report in that finding's validation paths from `../../references/scan-artifacts.md` so the full scan bundle lives together.
- Make a serious, bounded effort to get runtime validation working when it would materially change reportability, confidence, or severity. Consult repository guidance such as `AGENTS.md`, `README.md`, setup docs, test docs, build files, and package-manager metadata to identify the required dependencies, generated files, services, and setup steps.
- For scans that should not modify the target tree, use a disposable copy or generated-artifact directory under that finding's validation artifacts path for builds, generated clients, patched test harnesses, and PoC files. A no-edit target rule does not forbid output-only build copies when they are needed to validate the original code.
- For repository-wide and scoped-path scans, update each affected finding's validation report and closure table as each reportable, suppressed, not_applicable, or deferred row is decided. Do not leave validated rows only in transient notes, terminal logs, or validation artifacts; later phases must be able to reconstruct surviving findings from the saved per-finding validation reports if the scan is interrupted.
- For large repository-wide scans, keep setup/build/debug effort proportionate to the candidate and the remaining high-impact coverage ledger. Do not spend the review budget trying to fully reproduce one internal service when static trace, existing tests, and deploy/config evidence are enough to validate or suppress the candidate.
- In repository-wide and scoped-path validation, once one candidate in a repeated high-impact pattern has a strong proof tuple, switch to sibling candidates from the coverage ledger and validate each by checking the same source, closest control, sink, and impact. Only continue deeper runtime work when it would materially change reportability, severity, or confidence.
- If a repository-wide shard has a promoted same-family finding plus unresolved seeded or root-control rows, close those sibling rows next as reportable, suppressed, or deferred before replacing the review with a more dramatic neighboring finding. Representative proof improves confidence, but it does not close sibling root controls without exact counterevidence.
- If the project or code does not compile/build, diagnose the failure enough to know whether a targeted build, existing test, package API harness, or disposable validation copy can still exercise the original code. Prefer validating the original target over a separate reimplementation.
- Do not treat setup errors, compilation errors, or missing dependencies as immediate counterevidence. Record what blocked runtime proof, then use static trace plus existing tests/config/deploy evidence when setup becomes disproportionate.
- Do not abandon a build, test, or validation command just because it takes time when there is output, resource usage, generated artifacts, or other evidence of progress and no hard evidence of failure. If a long-running command appears inconclusive, check process status, recent logs, output file timestamps, resource usage, or test runner status before stopping or weakening validation.
