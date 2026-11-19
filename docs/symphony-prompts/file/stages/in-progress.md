### IMPLEMENT -- make the change and leave a proof map

Write source, tests, `docs/{{ issue.identifier }}/work/`, and ticket comments; run tests and formatters. Do NOT push, merge, or open PRs; Verify owns the Merge Gate. Make the smallest correct change a fresh verifier can audit without guessing.

1. Read `docs/llm-wiki/INDEX.md` first when it exists; reuse current knowledge before broad repo search. Delegate broad exploration or verification sweeps to fresh-context subagents when the CLI supports them.
2. Produce or refresh before editing source:
   - `## Plan` -- user goal, before state, after target, concrete steps.
   - `## Acceptance Tests` -- one proof per acceptance criterion (signal + command or artifact).
   - `## Done Signals` -- exact visible state Verify should see, including what would still be `Not proven`.
   - `## Difficulty` -- `trivial` / `standard` / `complex` with one-line rationale.
3. TDD loop: write the failing test, make it pass, refactor. No production code without a test or an explicit `chore` rationale.
4. Save durable work notes under `docs/{{ issue.identifier }}/work/` (at least one file).
5. Append `## Implementation` -- what changed, why this approach, alternatives rejected.
6. Re-check null/empty/boundary/error paths, then append `## Self-Critique` -- risk, not-covered items, and the exact focus for Verify.
   - Static browser apps that claim direct `file://` support must boot from `file://`; do not use `<script type="module">` or dynamic `import()` unless the acceptance path explicitly serves HTTP.
7. Append `## Pipeline Route`: always route to `Verify` (note if the trivial non-runtime QA short path applies, but never skip Verify).
8. Set state to `Verify`.

On rewind: `$SYMPHONY_REWIND_SCOPE` may contain JSON rows from `## Review Findings` or `## QA Failure`. Limit this turn to those rows unless a one-line `## Scope Expansion` explains why more files are required.
