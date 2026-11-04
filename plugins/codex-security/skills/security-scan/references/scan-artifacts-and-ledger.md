# Standalone Diff Worklists and Artifacts

Use this reference only for standalone or legacy diff discovery without a compact host inventory. Standard, Deep, and compact Workbench Diff scans do not use it. Follow `../../../references/artifact-storage.md` for managed temporary and retained files, and `../../../references/scan-artifacts.md` for paths.

## Changed-file Worklist

Generate `rank_input.jsonl` from every changed text file, including deleted files. Tracked changes remain in scope regardless of ignore rules; local patches also include non-ignored untracked files.

Request the generation command from `get_codex_security_skill_instructions` with topic `diff-revisions` for a PR, commit, or branch diff, or `diff-local-patch` for a local patch. Run it against the authorized repository using the full, resolved baseline commit ID and, for revisions, the full target commit ID.

Then request topic `copy-worklist` and run its command to copy every row from `rank_input.jsonl` to `deep_review_input.jsonl` without ranking or dropping changed files. For all three topics, use the prepared helper-output directory in managed temporary storage and import retained output through the artifact tool. Standalone callers without the instruction tool can load each topic using [skill-runtime.md](../../../references/skill-runtime.md).

## Scoped Deep Review

Review each worklist file, using its baseline contents when deleted. Read supporting files only as needed to explain changed security behavior, and record why they were included. Cover the file's security-relevant behavior rather than treating a search hit as completed review.

Use available subagents for independent assignments when useful. Size assignments around coherent behavior and review complexity, within the runtime's available capacity. Give workers a fresh context and a self-contained assignment. If delegation fails, the parent reviews unstarted work.

Each assignment needs the target and diff range, assigned paths, applicable security policy and threat model, relevant user seeds, and output locations. Workers return reviewed paths and limitations, candidates with source/control/sink/impact evidence, counterevidence, and open validation questions. Discovery does not require validation or attack-path results before a candidate can be returned or deduplicated.

For a caller requesting worker status markers, emit `CODEX_SECURITY_WORKER_STATUS {"phase":"file_review","planned":6,"started":3}` after dispatch with the actual phase and counts. Do not add worker IDs, paths, prompts, or errors to this marker, and never report a worker as started without a successful spawn.

## Coverage and Phase Handoff

The parent reconciles assigned paths against the worklist. Retain a concise completion or limitation for each row in `work_ledger.jsonl`; do not manufacture coverage for unread files. Preserve explicit advisory seeds and their evidence or unresolved questions in `seed_research.md` when seed research is part of the request. Supplied context does not authorize additional source access.

For retained candidates, use stable IDs and a discovery receipt in `<findings_dir>/<candidate_id>/candidate_ledger.jsonl`. Each receipt identifies the scope, locations, evidence, and discovery status. Save the discovery result in `finding_discovery_report.md`. These files use the managed storage tool; do not append directly to retained files.

When combining several reviewers, retain `raw_candidates.jsonl` if needed to preserve their results. Merge duplicate observations before further analysis, preserving raw IDs and affected locations in `deduped_candidates.jsonl`; use `dedupe_report.md` only when the merge needs explanation. Independently vulnerable instances remain addressable.

Validation and attack-path analysis belong to their respective phases. Their owners add the method, evidence or proof gap, disposition, and phase receipt to the existing candidate record. Reuse completed analysis rather than rerunning it to satisfy another ledger. Final reporting must account for every candidate as resolved or explicitly deferred; a standalone discovery request ends at the discovery handoff.
