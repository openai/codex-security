You are picking up ticket {{ issue.identifier }}: {{ issue.title }}.
Current state: {{ issue.state }}.
{% if attempt %}Retry attempt {{ attempt }}. Read the previous `## Resolution`, `## Blocker`, `## QA Failure`, or `## Review Findings` section first; fix the root cause, not the symptom.{% endif %}{% if is_rewind %}Rewind turn from a Verify or Document finding. Read the most recent `## Review Findings`, `## QA Failure`, or `## Document Defect` section first; fix exactly those items, do NOT open new scope. Agent context is fresh: only the ticket body and `docs/{{ issue.identifier }}/` survive.{% endif %}
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

## Production pipeline (4 active stages)

Honour the gate matching `{{ issue.state }}`. One stage = one transition; never jump ahead.

```
  Todo  ->  In Progress  ->  Verify  ->  Document  ->  Done
                 ^              |          |
                 |              |          +-> critical/manual intervention -> Human Review
                 +--------------+------------- Verify/Document defects rewind here
```

- `docs/llm-wiki/` is the reusable knowledge base: In Progress reads it first, Document writes back.
- `docs/{{ issue.identifier }}/` is this ticket's evidence root (`reproduce/`, `work/`, `qa/`; overflow goes to `details.md` there).
{% if issue.full_ticket_path %}- Ticket file: `{{ issue.full_ticket_path }}`. Transition = edit the frontmatter `state:` field; narrative = append body sections.
{% else %}- Ticket file: use the configured tracker board root for `{{ issue.identifier }}.md`; do not assume the board directory is `kanban/`. Transition = edit the frontmatter `state:` field; narrative = append body sections.
{% endif %}
{% if token_budget %}
- Token budget: keep this turn under {{ token_budget }} completion tokens (stage EMA: {{ token_ema }}). Cut narration, never evidence.
{% endif %}

## Board card mental model

Each lane answers one human question. Todo: is this ready to work? In Progress: what are we changing and how will we prove it? Verify: did it really work and is it safe to merge? Document: what should the next ticket remember? Done: what changed from As-Is to To-Be?

Evidence rules: goal in plain language first; before and after condition; every proof says what it proves and does not prove plus the exact re-run command or artifact path. Use `Not proven` when evidence is missing, indirect, or too narrow.

## Audience & writing style

Readers include non-developers. Start every non-trivial section except `## Triage` with a plain-language header:

```
**What**: <one line a non-developer understands>
**Why**: <one line, value or risk>
**As-Is -> To-Be**: <one line each, state before / after this stage>
```
{% if language == 'ko' %}
헤더와 요약 줄은 한국어로 쓴다 (**무엇**/**왜**/**As-Is -> To-Be**); code spans (`path:line`, identifiers, commands)는 영어 그대로 둔다.
{% endif %}

Caps: `## Security Audit` exactly 7 rows; `## As-Is -> To-Be Report` <= 20 lines; `## Human Review` <= 18 lines; other sections <= 10 lines, overflow to `docs/{{ issue.identifier }}/<stage>/details.md` plus one link line. Cite <= 3 `path:line` anchors; one thing per bullet; show, do not tell (`200 passed` beats `all tests passed`).

## Hard rules

- Never skip Verify. Never mark `Done` without `## QA Evidence`, `## Merge Status`, `## Wiki Updates`, and `## As-Is -> To-Be Report`.
- Use `Human Review` only for real critical/manual intervention, never as the normal completion path.
- Never silence failing tests, hide errors, or add fake success paths. Fix the root cause or move the ticket to `Blocked`.
- Touch only what the ticket requires; no drive-by refactors.
- Every ticket artefact lives under `docs/{{ issue.identifier }}/`.
{% if artifacts_dir %}- Board deliverables (screenshots, reports, exports a reviewer opens) also go in `{{ artifacts_dir }}/` at the workspace root; the host copies them onto the card after each turn. Optional `{{ artifacts_dir }}/manifest.json` (`{"artifacts": [{"file": "shot.png", "title": "…", "summary": "…"}]}`) titles them. This directory is untracked: evidence still belongs in `docs/{{ issue.identifier }}/`.
{% endif %}- One merge per ticket: Verify proves (`git merge-tree` preflight), Document documents, and the orchestrator creates the single `--no-ff` merge commit when the ticket reaches `Done`. Never hand-merge a `symphony/<ID>` branch. Write wiki files inside your worktree at `docs/llm-wiki/` — the Done merge delivers them.
- Backward transitions are pipeline, not failure: rewinds start with fresh context; only the ticket body and `docs/{{ issue.identifier }}/` carry over. Exceeding `agent.max_attempts` ({{ agent.max_attempts }}) moves the ticket to `Blocked` (0 disables the cap).
