You are picking up ticket {{ issue.identifier }}: {{ issue.title }}.
Current lane: {{ issue.state }}.
{% if attempt %}Retry attempt {{ attempt }}. Read the previous `## Resolution` / `## Blocker` / `## Objections` section first; fix the root cause, not the symptom.{% endif %}
{% if issue.full_ticket_path %}Full ticket: {{ issue.full_ticket_path }}{% endif %}

{% if issue.description %}
## Description

{{ issue.description }}
{% endif %}

{% if issue.labels %}Labels: {{ issue.labels | join: ", " }}{% endif %}

{% if issue.blocked_by %}
This ticket depends on:
{% for blocker in issue.blocked_by %}- {{ blocker.identifier }} ({{ blocker.state }})
{% endfor %}
{% endif %}

## Deep pipeline (8 lanes)

Each spawned ticket completes its own lane at `Done`; the request reaches
`Done` after Review PASS. `Done` is intentionally
unprompted in this preset — the lane gates live in the lane prompts.

- A request ticket walks `Intake -> Research -> Plan -> Review`. Plan spawns the downstream `Build`/`QA`/`Verify`/`Document` tickets as a DAG (`--blocked-by`); Review red-teams the plan before any Build dispatches. Review's `verdict: PASS` moves the request ticket to `Done`, which is what releases the spawned Build tickets.
- Merge contract: each ticket owns one `symphony/<ID>` branch in its own worktree. **The orchestrator merges a ticket's branch when that ticket reaches `Done` — no lane merges by hand.** Your worktree is cut from the merge target branch, so an earlier slice's code is present only because its ticket already reached `Done`. If you need a slice that is not yet merged, say so in the ticket and set `Blocked`; never cherry-pick or merge another ticket's branch yourself.
- Vault: `docs/req/{{ issue.request }}/` when this ticket has a `request` group, else `docs/{{ issue.identifier }}/`. Lane outputs (`brief.md`, `research.md`, `plan.md`, `contracts.md`, `claims.md`, `qa-report.md`, `verification.md`, `delivery.md`) live there. `claims.md` and `verification.md` are append-only.
- `docs/llm-wiki/` is the reusable knowledge base: read `INDEX.md` before broad repo search; Document writes back.
- Ticket file: `kanban/{{ issue.identifier }}.md`. Transition = edit the frontmatter `state:` field; narrative = append body sections.
- The request ticket's description is the approved intent: the cycle's single human gate. It is the source of truth for scope. Do not reopen the ask with the operator; record assumptions in the vault instead.
- Honour the hard gate of your lane before closing. Never silence failing tests or invent evidence; use `Not proven` and cite the artifact path for every claim. Fix root cause or set `Blocked`.
- The orchestrator re-checks your lane's gate at the transition (vault file present, verdict line present, ticket section appended). A missing output appends `## Contract Failure` and rewinds the ticket to your lane.
- Use `Human Review` only for a real critical/manual intervention.
{% if token_budget %}
- Token budget: keep this turn under {{ token_budget }} completion tokens (stage EMA: {{ token_ema }}).
{% endif %}
