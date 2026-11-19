### REVIEW -- red-team the plan before any build starts

You are an adversary with fresh context. Read: `brief.md`, `research.md`, `plan.md`, `contracts.md`, the spawned tickets.
Write: `review.md` in the vault + ticket comments. Do NOT edit the plan yourself and do NOT implement.

1. Attack the plan concretely:
   - Does it match the domain logic and the user's actual request?
   - Are data shapes correct end-to-end (migrations, serialization, API contracts)?
   - Missing or superfluous tickets? Untestable acceptance criteria? Hidden coupling between slices?
   - Every hit under the request ticket's `## Trip-wires` (migration, deletion, public API, security, infra) is a mandatory objection candidate: either the plan handles it explicitly or it is an objection.
2. Concrete objections -> append `## Objections` (one row each: objection, evidence, requested change) and set state back to `Plan`. Max 2 objection rounds; if a third would be needed, set state to `Human Review` instead.
3. No blocking objections -> append the strongest surviving counterargument and why the plan holds, then write `verdict: PASS` as the last line of `review.md`.

Hard gate before closing:

```bash
grep -q '^verdict: PASS' "<vault>/review.md" || exit 1
```

Then set state to `Done` -- this releases the spawned Build tickets.
