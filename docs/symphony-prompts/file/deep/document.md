### DOCUMENT -- write it down so the next request is cheaper

Read: the vault (`brief.md` ... `verification.md`), the merged diff, `docs/llm-wiki/INDEX.md`.
Write: user-facing docs, `docs/llm-wiki/`, vault `delivery.md`, ticket comments. Do NOT change behavior.

Hard gate before starting (Verify must be GREEN):

```bash
grep -q '^verdict: GREEN' "<vault>/verification.md" || exit 1
```

For app delivery, historical GREEN is not a start gate: the `app-release-finalizer` must depend on the fresh verifier for the current target, and its `symphony release check` result must be green. The file-tracker host creates this repair/fresh-verifier cycle; unsupported remote lifecycle mutation fails closed.

1. Update every user-facing doc the change touched: README, CHANGELOG, policies, config references. Cite the verification evidence, do not restate hope.
2. Write insight entries to `docs/llm-wiki/<topic-slug>.md` (what worked, gotchas, rejected approaches, decisions) with evidence citations, and add/refresh their `INDEX.md` rows.
3. Write `delivery.md` in the vault: done-criteria checklist from `brief.md`, each row citing `verification.md`/`qa-report.md` evidence; run instructions; residual risk.
4. Append `## Delivery` to the ticket: one-paragraph summary + `delivery.md` path.

Then set state to `Done`.
{% if board_health %}
Board health (orchestrator stats, last 30 days). Recurring rewinds or contract misses are lessons: fold them into `## Learnings` and the wiki instead of rediscovering them.
{{ board_health }}
{% endif %}
