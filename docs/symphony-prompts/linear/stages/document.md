### DOCUMENT -- document the change and make the next ticket easier

Read `docs/{{ issue.identifier }}/{work,qa}/`, prior sections, and `docs/llm-wiki/`. Read-only inspection of history is expected -- `git log`, `git show`, `git diff` are how you compare brief vs reality.

Write scope: `docs/llm-wiki/`, the user-facing docs this change touched (README / CHANGELOG / config and policy references), the vault under `docs/{{ issue.identifier }}/`, and ticket comments. Do not change behavior: no source or test edits. Do not create commits, tags, branches, or pushes -- the host gate owns delivery history -- and do not merge; the orchestrator merges once, at `Done`.

1. Read `## Plan`, `## Implementation`, `## Self-Critique`, `## QA Evidence`, `## AC Scorecard`, and `## Merge Status`. Compare brief vs reality: assumptions that held or broke, constraints that surfaced, misleading wiki entries, evidence still `Not proven`.
2. Update every user-facing doc the change touched: README, CHANGELOG, config references, policies. Cite the verification evidence; do not restate hope. Nothing touched -> say so in `## Wiki Updates`.
3. Update `docs/llm-wiki/` (relative to your workspace, not the host tree -- the Done merge delivers it): append a Decision-log row or create/update `docs/llm-wiki/<topic-slug>.md`, then add/refresh its row in `INDEX.md`.
4. Real defect found while comparing brief vs reality (the change does not do what the ticket promised, evidence contradicts a claim, a shipped doc is now wrong about behavior)? Append `## Document Defect` -- what is wrong, the evidence path, and the exact scope to fix -- set state to `In Progress`, and stop. Do not fix it here; this lane does not change behavior.
5. Append `## Learnings` -- 3-4 bullets future work should not rediscover.
6. Append `## Wiki Updates` -- paths created/modified/removed, one line each.
7. Append `## As-Is -> To-Be Report` with subsections: `### Goal`, `### As-Is`, `### To-Be`, `### Reasoning`, `### Evidence` (commands/proofs with pass/fail, top evidence path), `### Not Covered`, `### How To Re-run`.
8. Only if a real critical/manual intervention remains, append `## Human Review` with: `### Intervention Required`, `### What Changed`, `### Why It Matters`, `### Evidence`, `### Risks`, `### Human Checklist` (3-5 quickly verifiable checkboxes), `### Decision Needed` (exactly one line: `Confirm Done` or `Do not confirm; move back to <state> because <reason>`).
9. Final History Gate -- Symphony runs it, not you:
   - Update the ticket to `Done` for normal success, or `Human Review` only for the intervention branch. Do not stage, commit, or publish the delivery record yourself.
   - After this stage exits, the orchestrator commits the workspace, publishes the branch, re-reads the remote tip with `git ls-remote`, and writes the SHAs into the ticket. Record what you produced and where; leave SHAs to the host gate.
   - Never set `Blocked` because a local git command failed -- a sandbox that refuses `.git/objects` writes is an environment limit, not lost work; the host gate records the same delivery moments later.
10. Set state to `Done` for normal success. Set state to `Human Review` only for the recorded critical/manual intervention branch.

Operator skip: the TUI/web skip action may append `## Document Skipped` and move an idle Document ticket to `Human Review`; agents must not simulate that skip themselves.
{% if board_health %}
Board health (orchestrator stats, last 30 days). Recurring rewinds or contract misses are lessons: fold them into `## Learnings` and the wiki instead of rediscovering them.
{{ board_health }}
{% endif %}
