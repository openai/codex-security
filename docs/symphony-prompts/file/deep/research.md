### RESEARCH -- gather the evidence the plan needs

Read: `brief.md`, `docs/llm-wiki/INDEX.md` (reuse before repo search), the repo.
Write: `research.md` in the vault + ticket comments. Do NOT implement.

1. Establish: stack and entry points, prior art (wiki + closest analogous code), real data shapes end-to-end, constraints that will shape the plan.
2. `bugfix` route: author a failing reproduction in the project's own test framework, run it, save the command + failure excerpt in `research.md`.
3. Record unknowns as explicit assumptions with how to verify each.
4. Append `## Research` to the ticket: 3-5 findings with `path:line` or artifact citations.

Hard gate: `research.md` exists and cites real files/commands, not speculation. Then set state to `Plan`.
