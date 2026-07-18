# Exhaustive Review Guidance

Use this guidance when the security scan target is the entire checked-out repository or a user-specified scoped path, package, folder, or submodule-like boundary.

## Required References

Before exhaustive repository or scoped-path discovery or validation, read this file and all of these same-directory references in order. They are mandatory extensions of this workflow, not optional background:

1. `scan-artifacts-and-ledger.md` for shared artifact, seed, subagent, scoped file-review, candidate-ledger, and dedupe rules.
2. `repo-wide-artifacts-and-ledger.md` for rank input, subagent ranking, deep-review selection, and repository coverage-ledger rules.
3. `repo-wide-high-impact-families.md` for high-impact vulnerability family heuristics and exact suppression boundaries.
4. `repo-wide-instance-expansion.md` for child-instance splitting, wrapper/root-control preservation, and per-operation reporting.
5. `repo-wide-validation-closure.md` for validation/report closure, deferred rows, secondary issue ordering, and false-positive controls.

Do not treat `repository-wide-scan.md` alone as the complete exhaustive scan procedure.

## Exhaustive Mode

Use an exhaustive instance-finding workflow rather than the diff-scan workflow's representative-finding bias.

Repository-wide and scoped-path scans must:

- Load the per-scan threat model path from `../../../references/scan-artifacts.md` as the repo-specific threat-model source of truth.
- Build or consume an authoritative parent-provided `rank_input.jsonl` before validation so the in-scope candidate file inventory covers routes, handlers, templates, serializers, deserializers, query builders, shell/process calls, file/path APIs, network fetches/callbacks, auth/authz middleware, session/cookie config, secret/config sources, IaC or policy resources, and agent/tool boundaries.
- Create `seed_research.md` when seed hints exist, `rank_input.jsonl`, `rank_output.jsonl` when ranking applies, `deep_review_input.jsonl`, `work_ledger.jsonl`, `raw_candidates.jsonl`, per-finding candidate ledgers, `dedupe_report.md`, `deduped_candidates.jsonl`, and `repository_coverage_ledger.md` using the artifact paths from `../../../references/scan-artifacts.md`.
- Create a high-impact coverage ledger before deep validation. The ledger is a coverage artifact, not a list of potential findings, and must include rows without candidates as well as reportable candidates.
- Keep every applicable high-impact, user-seeded, advisory-seeded, or tag-seeded row open until that exact area is closed as `reportable`, `suppressed`, `not_applicable`, or `deferred` with exact evidence or proof-gap reasons.
- When seed research or the prompt provides a concrete advisory id, snapshot URL, file, line, source, sink, or missing-control hint, create an anchored ledger row for that exact tuple. Sibling findings in the same repository, CWE, or subsystem are additional rows; they do not close the anchored row unless they fix the same vulnerable control and effect.
- Enumerate every technically distinct high-impact vulnerable instance discovered under those families, not just one representative example per class.
- Keep file-impact families open independently from auth, secret, or config findings in the same subsystem. A reportable auth bypass, credential issue, or sensitive-data exposure does not close a separate path traversal, archive extraction, export/import, backup/restore, file copy/move, or resource-serving row unless it defeats the exact same path-control proof tuple.
- Preserve the line where the security control actually fails, including unsafe split/parse/canonicalize/normalize/compare/regex/selection/object-binding lines that create a bypass or feed a sink.
- Suppress a candidate only with exact counterevidence for that instance, such as a specific sanitizer, permission check, tenant filter, escaping context, safe parser/loader, path canonicalization check, egress allowlist, or deployment constraint that defeats the claimed source/sink path.

## Discovery Execution

During finding discovery, apply this exhaustive repository or scoped-path workflow instead of the diff-centered discovery workflow. Use `../../finding-discovery/SKILL.md` for the candidate output contract and `../../../references/scan-artifacts.md` for artifact paths.

Run this broader but still bounded workflow:

For a durable workspace scan with a `scanId` and the Codex Security progress tool available, use `update_codex_security_scan_progress` as follows:

- Keep `reviewItemsTotal` at zero while ranking. Ranking rows are not completed review items.
- After `deep_review_input.jsonl` is final, publish its row count as `reviewItemsTotal` with `reviewItemsCompleted` set to zero.
- Dispatch file-review work in bounded batches instead of one blocking all-rows batch. After each batch, reconcile unique completed worklist receipts and publish that count as `reviewItemsCompleted` before dispatching the next batch. Do not wait for all file reviews to finish before publishing partial progress.

1. Read the required references listed above.
2. Resolve `rank_input.jsonl` before subagent dispatch:
   - if an upstream parent orchestrator explicitly provided authoritative in-scope worklists and both `<discovery_dir>/rank_input.jsonl` and `<discovery_dir>/deep_review_input.jsonl` already exist, consume that `rank_input.jsonl` as supplied
   - otherwise generate `rank_input.jsonl` using `<python_command> <plugin_dir>/scripts/generate_rank_input.py make-repo-rank-input --repo <repo_root> --scope <scope> --out <discovery_dir>/rank_input.jsonl`; this is the deterministic candidate file inventory for the resolved repository or scoped path
3. Resolve `deep_review_input.jsonl`:
   - if an upstream parent orchestrator explicitly provided authoritative in-scope worklists and both standard worklist files already exist, consume that `deep_review_input.jsonl` as supplied without reranking or overwrite
   - otherwise apply the `top-percent` flow from `repo-wide-artifacts-and-ledger.md`: for `top-percent` below 100, run bounded shard-based subagent ranking over `rank_input.jsonl` using the runtime-surface scoring guidance and select `deep_review_input.jsonl`; for `top-percent` 100 or higher, copy every candidate row directly into `deep_review_input.jsonl`
4. Run advisory/seed research when the user or scan context includes CVE, GHSA, advisory, issue, release, package-version, or vulnerability-family identifiers. Save `seed_research.md` and create exact seed-target ledger rows.
5. Build and save `repository_coverage_ledger.md` with one row per applicable boundary and serious vulnerability family before deep validation begins; include any exact anchored rows from seed research as their own rows even if another candidate in the same subsystem already exists.
6. Run one frontier pass across every applicable high-impact shard before prolonged validation or build/debug work on any single shard.
7. Run targeted control-hazard searches for parser/helper, deserializer, auth/token/assertion, protocol/version, and polymorphic-operation shards using `repo-wide-high-impact-families.md`.
8. For path-sensitive filesystem review, enumerate exported or deployed static/resource handlers, download/open helpers, upload/extract/import flows, export flows, backup/restore flows, file copy/move helpers, and archive entry writers/readers before deepening any one hotspot. Give each independently reachable operation its own ledger row.
9. Run high-impact sibling-expansion passes before any secondary review. When one vulnerable pattern is found, the file-review subagent or parent agent that owns that candidate must search sibling files, routes, templates, handlers, models, and config variants before moving on.
10. When a high-impact instance flows through a wrapper into a shared parser, deserializer, path/archive helper, expression evaluator, or auth/authz control, record both the reachable wrapper and the underlying shared sink/control.
11. If a filesystem/path row and an auth/authz/config row both survive in the same product area, carry both forward until the exact control for each row is closed. Do not let the louder or easier-to-explain issue replace the sibling row.
12. Dispatch file-review subagents over `deep_review_input.jsonl` using the shared ownership rules in `scan-artifacts-and-ledger.md`. Each file-review subagent owns its assigned file or tiny shard, performs full-file review, and returns pre-dedupe finding objects with candidate-local validation evidence and attack-path facts for findings it discovered.
13. Aggregate file-review-subagent outputs into `raw_candidates.jsonl` and append one candidate-ledger row per raw candidate finding.
14. Do not continue until each raw candidate finding's candidate-ledger path from `../../../references/scan-artifacts.md` shows validation and attack-path coverage, or an explicit deferred reason for any missing proof.
15. Split broad families and repeated same-family operations into child instances using `repo-wide-instance-expansion.md` before cross-file dedupe whenever the child instances are already visible in subagent output.
16. Run cross-file dedupe into `dedupe_report.md` and `deduped_candidates.jsonl` without dropping independently reachable sibling instances, and preserve the raw candidate ids absorbed into each deduped candidate.
17. Use post-dedupe validation and attack-path work for exhaustive-scan reconciliation, unresolved proof gaps, and final closure, not as the first review pass for raw findings. When multiple deduped candidates or coverage-ledger rows remain open and subagents are available under the resolved scan authorization, divide validation and attack-path work across candidate/row-scoped subagents using `scan-artifacts-and-ledger.md`.
18. Treat data exposure, hardcoded secrets, weak session/cookie/security config, CSRF, rate limits, and plaintext storage as secondary. Include them only after the high-impact ledger and file list are exhausted or when they directly enable code execution, injection, privilege escalation, meaningful auth bypass, or sensitive cross-boundary impact.
19. Preserve each validated or suppressed instance through validation, attack-path analysis, and final reporting using `repo-wide-validation-closure.md`.
