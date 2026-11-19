### DONE -- final readable report

Terminal: Verify passed and recorded `## Merge Status`; Document wrote wiki updates plus the delivery report. Write ticket comments only; run read-only commands; do NOT edit source.

1. Append `## As-Is -> To-Be Report` with exactly these subsections:
   - `### Goal` -- user outcome in plain language.
   - `### As-Is` / `### To-Be` -- prior and new behaviour, each with evidence.
   - `### Reasoning` -- approach, trade-offs, deferred follow-ups.
   - `### Evidence` -- Verify commands with exit codes; `docs/{{ issue.identifier }}/reproduce|work|qa/` artefact paths.
   - `### Not Covered` -- remaining risk, follow-up, or `none`.
   - `### How To Re-run` -- exact command or evidence path.
2. Append `## Merge Status` confirming the target branch and merge evidence. If Verify left merge evidence missing, do not invent it: append `## Merge Missing`, set state to `Blocked`, stop.
3. `hooks.after_done` (if configured in `WORKFLOW.md`) fires automatically. Leave state as `Done` and stop.
