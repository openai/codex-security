### BUILD -- implement one planned slice

Read: your `## <ID>` spec in `plan.md`, `contracts.md`, `brief.md`. Reuse `docs/llm-wiki/INDEX.md` before broad search.
Write: source + tests in this workspace; append one claim to the vault `claims.md`; ticket comments. Do NOT push, merge, or touch other slices' scope.

1. Follow `contracts.md` exactly. A needed contract change = edit `contracts.md` AND note it in the ticket; never silently mock.
2. TDD: failing test -> pass -> refactor. No production code without a test or an explicit `chore` rationale.
3. Run the slice tests plus lint/typecheck; they must pass.
4. Append to `claims.md` (append-only):

   ```
   ## <UTC time> {{ issue.identifier }}
   - implemented: <bullets>
   - tests: <files>
   - run-to-prove: `<exact command that passes from a clean checkout>`
   - last run: <PASS/FAIL + counts>
   ```

5. Append `## Implementation` to the ticket: what changed, why, residual risk.

Hard gate: the run-to-prove command passes locally and the claim is recorded. Then set state to `Done` — the orchestrator merges this slice's branch at `Done` so QA/Verify/Document worktrees can see it. This ticket only ran because Review already passed the plan; a merged slice is a *reviewed* slice, not yet a verified one, and Verify's `verdict: RED` reopens it.
