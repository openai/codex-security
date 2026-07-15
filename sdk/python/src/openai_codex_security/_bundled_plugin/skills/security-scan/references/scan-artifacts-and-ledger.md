# Scan Artifacts And Ledger

Use this reference whenever the scan needs auditable candidate coverage or a scoped file-review worklist.

## Artifact Requirements

- Load the per-scan threat model path from `../../../references/scan-artifacts.md` as the repo-specific threat-model source of truth.
- Use the artifact paths from `../../../references/scan-artifacts.md` for `seed_research.md`, `deep_review_input.jsonl` when a scoped file-review worklist is needed, `work_ledger.jsonl` when a scoped file-review worklist is needed, `raw_candidates.jsonl` when multiple file-review results are aggregated, `dedupe_report.md` and `deduped_candidates.jsonl` when cross-file dedupe is needed, and per-finding `05_findings/<candidate_id>/candidate_ledger.jsonl`.

## Seed Research

- First capture user-provided scope hints such as CVE/GHSA/advisory identifiers, package versions, named vulnerability families, or release/security-test references.
- When the user request or scan context includes CVE, GHSA, advisory, issue, release, package-version, or explicit vulnerability-family identifiers, run an advisory seed pass before deep frontier scanning and save it to the advisory seed research path from `../../../references/scan-artifacts.md`.
- Use authoritative advisory text, project security notes, release notes, fix commits, pull requests, issue trackers, and security tests when network access or local history is available. Record the sources searched, candidate files/functions/classes/hunks, expected vulnerable behavior, and any failed lookup attempts.
- Treat those candidates as seed rows only: validate the vulnerable behavior against the checked-out repository before reporting. Do not let the seed lane replace the scan's primary scope.
- When CVE/advisory context has a generic or unhelpful category, prioritize advisory, fix-commit, release-note, and security-test lookup before broad sink hotspot scanning. If external lookup is unavailable or inconclusive, run a local regression-seed pass over project-specific protocol, parser, validator, and utility names plus the CVE/advisory terms; do not assume obvious REST/upload/XML hotspots are the intended security regression.
- When the seed pass or local search opens a candidate file, class, package, or hunk, create an exact seed-target row for that area before opportunistic same-family scanning. Run a short seed-first triage over that file/package and its immediate shared helper or caller chain, then close the row as `reportable`, `suppressed`, `not_applicable`, or `deferred`. A more obvious neighboring issue can be reported too, but it does not replace the seed-target row.
- Keep every user/advisory/tag-seeded boundary package or class family open until that exact area is closed as `reportable`, `suppressed`, `not_applicable`, or `deferred`. A broader same-family finding in a neighboring parser, auth flow, deserializer, or template engine does not implicitly close the seeded row.
- In advisory-led scans, treat the advisory, fix hunk, release note, or security test as evidence for the intended root cause, not as an exclusivity filter and not as a bare finding. Keep the exact seed row open until checked-out repository evidence independently supports or disproves the same source, broken control, and impact tuple.

## Subagent Requirements

- When a scan uses subagent-dispatch phases and subagents are available in the current tool set, use subagents for those phases.
- For exhaustive repository-wide, scoped-path, and diff scans, explicit invocation of the applicable top-level exhaustive scan workflow is the required user authorization for these subagent-dispatch phases. For other scan modes, use subagents only when the applicable top-level workflow or the user has authorized them.
- Ranking JSONL uses the static bounded worker-pool plan in `repo-wide-artifacts-and-ledger.md`: one spawn per planned pool slot, one ordered multi-shard assignment per worker, and no refill or follow-up assignment. For other JSONL worklist phases, use the ordinary delegated-worker lifecycle: spawn no more workers than the runtime's usable slots, wait for the specific worker ids, validate each owned result, and then refill available slots. On native v2, spawn self-contained workers with `fork_turns=none`; completed workers are idle and do not need interruption, and `interrupt_agent` is only for stopping a still-running non-ranking worker before a retry. Do not use `spawn_agents_on_csv` or any host CSV, batch-import, or fanout shortcut for a JSONL worklist.
- File-review-subagent ownership: one file-review subagent owns one `deep_review_input.jsonl` row or one very small tightly coupled shard, max 5 files, and returns full-file receipts plus pre-dedupe finding objects for that assignment.
- File-review subagents are read-only with respect to the target code under review, but they are allowed and expected to write scan artifacts under the resolved numbered artifact directories, including `<discovery_dir>/work_ledger.jsonl`, raw candidate snippets in `<discovery_dir>/raw_candidates.jsonl`, and per-candidate ledger receipts under `<findings_dir>/<candidate_id>/` when those artifact paths are provided in the prompt.
- Validation-subagent ownership: one validation subagent owns one candidate finding, one deduped candidate, or one repository coverage-ledger row that needs validation closure. It writes or returns validation artifacts, the visible validation report update, and the validation candidate-ledger receipt for that assignment.
- Attack-path-subagent ownership: one attack-path subagent owns one validated candidate finding or one reportable/deferred validation closure row. It writes or returns attack-path facts, severity/policy analysis, the visible attack-path report update, and the attack-path candidate-ledger receipt for that assignment.
- Parent-agent ownership: the parent agent owns `deep_review_input.jsonl` generation, bounded subagent dispatch, work-ledger and candidate-ledger reconciliation, aggregation of subagent outputs, cross-file dedupe when needed, and final scan closure.
- Subagent prompts must carry the exact current scan instructions they are expected to follow. Do not rely on the subagent implicitly inheriting this skill, another phase skill, previous parent context, or a summarized reference name.

### File-Review Subagent Handoff

The parent agent should give each file-review subagent enough concrete context to execute its assigned row without relying on implicit parent context. Keep the prompt concise, but include:

- the assigned `deep_review_input.jsonl` row or tiny shard
- the scan target, scan mode, `repo_name`, `scan_id`, `artifacts_dir`, the relevant numbered artifact directories, and per-scan threat model path or summary
- the writable artifact paths for `<discovery_dir>/work_ledger.jsonl`, `<discovery_dir>/raw_candidates.jsonl`, and per-candidate ledger receipts under `<findings_dir>/<candidate_id>/`
- any user-provided comparison or seed artifact that should affect coverage, such as an HTML/markdown report, prior security-review output, advisory text, CVE/GHSA, release note, issue, or separate audit directory
- the expectation to read assigned files in full, read only the supporting files needed for concrete findings, and return or write full-file receipts, raw candidates, suppressions/deferred rows, and ledger receipts

The parent agent must reject or re-prompt any file-review subagent result that lacks full-file receipts, omits source/control/sink/impact for candidates, omits candidate-local validation or attack-path facts for reported candidates, or returns only "no bugs found" without closing the assigned row with evidence.

### Validation And Attack-Path Subagent Handoff

After discovery and dedupe, divide validation and attack-path work across subagents when multiple candidates or coverage-ledger rows need closure and subagents are available under the resolved scan authorization.

For validation subagents, include the candidate or ledger row, discovery evidence, relevant raw/deduped candidate ids, affected files, threat-model context, validation artifact/report paths, and the candidate-ledger path that needs the validation receipt. The validation subagent should preserve or suppress the assigned instance only; it does not own final report assembly or unrelated candidates.

For attack-path subagents, include the validated candidate or validation closure row, validation report path or summary, affected root-control and sink lines, threat-model context, attack-path report path, and the candidate-ledger path that needs the attack-path receipt. The attack-path subagent should produce reachability, counterevidence, severity/policy analysis, and final reportability facts for the assigned instance only.

The parent agent must reconcile validation and attack-path subagent outputs before final reporting. Do not finalize while any reportable, suppressed, not_applicable, or deferred candidate/ledger row lacks the required receipt or explicit proof-gap reason.

## Scoped Deep Review

- Use `deep_review_input.jsonl` as the canonical scoped deep-review worklist for every diff-scoped, repository-wide, and scoped-path scan.
- For diff-scoped scans, generate `rank_input.jsonl` deterministically from changed source-like files with `<python_command> <plugin_dir>/scripts/generate_rank_input.py make-diff-rank-input --repo <repo_root> --base <base> --mode revisions --head <head> --out <discovery_dir>/rank_input.jsonl` for PR, commit, and branch diffs, or `<python_command> <plugin_dir>/scripts/generate_rank_input.py make-diff-rank-input --repo <repo_root> --base <base> --mode local-patch --out <discovery_dir>/rank_input.jsonl` for a local patch, then copy every row into `deep_review_input.jsonl` with `<python_command> <plugin_dir>/scripts/generate_rank_input.py copy-deep-review-input --rank-input <discovery_dir>/rank_input.jsonl --out <discovery_dir>/deep_review_input.jsonl`.
- Diff-scoped scans do not rank or drop changed files before deep review. Every row in diff `rank_input.jsonl` must be copied into `deep_review_input.jsonl` and receive a full-file review receipt.
- Add directly supporting files required to understand the changed security behavior only when repository evidence shows they are needed; record the add-back reason in the work ledger or per-file result.
- For repository-wide and scoped-path scans, `deep_review_input.jsonl` is selected from the ranked in-scope inventory.
- Deep-review every file selected into `deep_review_input.jsonl`.
  - Use `<discovery_dir>/work_ledger.jsonl` as the append-only record of claims and completions, and reconcile it against `deep_review_input.jsonl` so rows are not skipped or double-counted.
  - Use subagents when available under the resolved scan authorization.
    - A file-review subagent must read every assigned file in full, update the ledger receipt for those files, and return the raw finding results for that assignment.
    - When a file-review subagent finds a plausible finding in its assigned file or shard, that same subagent should carry that finding through candidate-local validation and candidate-local attack-path analysis before handing it back. The raw result should include the source or privileged boundary, closest relevant control, sink or broken control, impact, validation method/evidence or exact proof gap, attack-path facts, and disposition.
    - A file-review subagent may read the minimum supporting files needed to validate or explain a finding it discovered, but it does not own unrelated rows or final scan closure.
  - If subagents are not available, iterate through `deep_review_input.jsonl` yourself with the same full-file standard.
  - A file is not covered because it appeared in searches. It is covered only when the responsible subagent or parent agent returns a receipt showing the file was read in full.
  - Record file-level completion, disposition, and a concise evidence note in `<discovery_dir>/work_ledger.jsonl`; do not create a separate per-file findings directory.
  - Append normalized, pre-dedupe candidate objects to `<discovery_dir>/raw_candidates.jsonl` when multiple file-review results are being aggregated or cross-file dedupe is needed.
  - Do not stop until every `deep_review_input.jsonl` row has a completion receipt.

## Candidate Finding Coverage

- Track candidate-finding coverage separately from file coverage.
  - Use `<findings_dir>/<candidate_id>/candidate_ledger.jsonl` as the append-only record for each candidate finding.
  - Every candidate finding must have a stable candidate id plus candidate-ledger receipts for discovery, validation, and attack-path analysis before final reporting.
  - When the finding is emitted during a scoped file-review pass, candidate-local validation and candidate-local attack-path analysis should be recorded before the finding is eligible for cross-file dedupe.
  - Validation coverage must record the validation method, evidence or exact proof gap, and disposition for that candidate finding.
  - Attack-path coverage must record the source or privileged boundary, closest relevant control, sink or broken control, impact path, and severity-relevant facts for that candidate finding.
  - A candidate finding is not covered because it appears in a report or `raw_candidates.jsonl`. It is covered only when its candidate ledger shows the required receipts, or an explicit deferred reason for the missing proof.
- When multiple raw candidate streams need cross-file dedupe, dedupe only after the relevant candidate ledgers prove the required coverage. Write `<reconciliation_dir>/dedupe_report.md` and `<reconciliation_dir>/deduped_candidates.jsonl`, preserving independently reachable sibling instances.
- Dedupe must preserve candidate-ledger traceability: every deduped candidate must list the raw candidate ids and per-finding candidate ledgers it absorbed, and independently reachable sibling instances must remain separate.
