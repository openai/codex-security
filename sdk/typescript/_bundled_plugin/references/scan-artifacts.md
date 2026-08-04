# Scan Artifact Paths

Use these shared path conventions for Codex Security scan workflows unless the user explicitly provides different input or output paths.

## Base Paths

- `plugin_dir=<codex-security plugin root>`
- `repo_name=<basename of repo_root>`
- `target_id=<stable scan target identity from references/scan-contract.md>`
- `system_temp_dir=<platform temporary directory>`
- `security_scans_dir=<system_temp_dir>/codex-security-scans/<repo_name>`
- `scan_id=<commit>_<scan timestamp>`
- `scan_dir=<security_scans_dir>/<scan_id>`
- `target_paths_file=$CODEX_SECURITY_TARGET_PATHS_FILE` for SDK scoped-path scans; this read-only scope input lives outside the model-writable scan directory. The SDK uses it to prepare the standard inventory before the model starts. Pass it to `make-repo-rank-input --scopes-file` only for deep or diff workflows that explicitly require ranking, and to `bind-repo-scopes --scopes-file` before finalization. Do not print, evaluate, modify, or treat its contents as shell syntax.
- `scope_inventory_file=$CODEX_SECURITY_SCOPE_INVENTORY_FILE` for SDK standard scans; this read-only, host-attested snapshot is the authoritative inventory for review and candidate normalization. Do not regenerate, rank, filter, modify, or replace it.
- `artifacts_dir=<scan_dir>/artifacts`
- `context_dir=<artifacts_dir>/01_context`
- `discovery_dir=<artifacts_dir>/02_discovery`
- `coverage_dir=<artifacts_dir>/03_coverage`
- `reconciliation_dir=<artifacts_dir>/04_reconciliation`
- `findings_dir=<artifacts_dir>/05_findings`

The MCP app resolves the platform temporary directory automatically. For a manual workflow, use the active process temporary directory (for example, `%TEMP%` on Windows or `$TMPDIR` when configured on Unix-like hosts) instead of hardcoding `/tmp`.

Resolve `<python_command>` to the configured Python interpreter (`$PYTHON` when one is provided), otherwise use `python` on Windows and `python3` on Unix-like hosts.

## Threat Model (Phase 1) Paths

- Resolved SECURITY.md guidance: `<context_dir>/security_guidance.md`
- Repository-scoped threat model: `<security_scans_dir>/threat_model.md`
- Per-scan threat model copy: `<context_dir>/threat_model.md`
- Later scan phases should treat `<context_dir>/threat_model.md` as the source of truth.
- When a repository-scoped threat model already exists, copy it to `<context_dir>/threat_model.md` without alteration for auditability.

End each repository-scoped threat model with these two lines:

- `Repository: <target_id>`
- `Version: <revision for an immutable Git tree; snapshot digest otherwise>`

## Finding Discovery (Phase 2) Paths

### Standard Repository Or Scoped-Path Scan

- Deterministic exhaustive scope inventory: `<discovery_dir>/scope_inventory.jsonl`
  - Each JSONL row contains exactly one JSON-encoded repository-relative `path`.
  - For SDK scans, read and normalize against the host-attested `$CODEX_SECURITY_SCOPE_INVENTORY_FILE` snapshot of this artifact.
  - Preserve literal colon and backslash filename characters on POSIX without treating them as Windows drive letters or separators. Windows drive and separator protections, portable scan-artifact paths, and repository traversal checks remain unchanged.
  - Review every row without ranking, scoring, sharding, or filtering.
- Exhaustive scope-review receipt: `<coverage_dir>/scope_review.jsonl`
  - Write exactly one JSONL row for every path in the authoritative inventory. A reviewed row has `path` and `disposition: "reviewed"`; a deferred row has `path`, `disposition: "deferred"`, and a nonempty `reason`. Preserve the inventoried path and defer it when its source disappears after inventory creation; mark the receipt-bearing coverage surface `needs_follow_up` and the scan coverage `partial`.
  - Include `artifacts/03_coverage/scope_review.jsonl`, `artifacts/02_discovery/scope_inventory.jsonl`, and `artifacts/02_discovery/candidate_ledger.jsonl` in a coverage surface's `receiptRefs` so finalization seals all three. Prompt-only scans must successfully run `generate_rank_input.py verify-scope-coverage` against the authoritative inventory before finalizing.
  - Empty inventories still require an empty receipt, an empty candidate ledger, and no findings.
- Compact combined candidate ledger: `<discovery_dir>/candidate_ledger.jsonl`
  - The combiner reads one or more temporary raw candidate sources, validates them against the authoritative scope inventory, merges rows with the same CWE ids, locations, and optional instance, preserves their text, and assigns deterministic `candidate_id` values. This is the sole durable standard candidate artifact.
  - After normalization, compact validation adds exactly one `validation` object to every row with `disposition` (`reportable`, `suppressed`, `not_applicable`, or `deferred`), `method`, `confidence` (`high`, `medium`, or `low`), `confidence_rationale`, concise `rubric` and `evidence`, `counterevidence_or_proof_gap`, `remaining_uncertainty`, and optional `artifact_paths`. Add `source`, `control`, `sink`, or `preconditions` only when they clarify or differ from the discovery fields.
  - Compact attack-path analysis adds exactly one `attack_path` object to each validation row marked `reportable` or `deferred`, with `decision` (`reportable`, `ignore`, or `deferred`), `dataflow`, `reachability`, `counterevidence`, `impact` and `likelihood` (`high`, `medium`, `low`, `ignore`, or `unknown`), `severity` (`critical`, `high`, `medium`, `low`, `ignore`, or `unknown`), `severity_rationale`, `change_conditions`, and `proof_gap` when deferred. A `reportable` decision requires severity `critical`, `high`, `medium`, or `low`; `ignore` requires severity `ignore`; `deferred` uses a provisional reportable severity or `unknown`.
  - For a deferred candidate, write exactly one `coverage.deferred` row with its unique candidate id. Copy its exact attack-path `proof_gap` into `coverage.deferred[].reason`; when validation alone is deferred, copy its exact recorded `counterevidence_or_proof_gap` or `remaining_uncertainty`. Do not invent a different explanation, repeat the deferred candidate id, or add a deferred row for a reported, rejected, or nonexistent candidate.
  - Preserve all discovery fields and row order during enrichment, rewrite atomically, and do not pass the enriched ledger back to `normalize_candidates.py`.
  - Bind every resulting finding's `extensions.candidateId`, coverage surface `id`, and deferred coverage `id` to the exact `candidate_id` so the host can reconcile all phase decisions before finalization. Preserve the candidate's exact CWE ids and locations, including shared sinks and supporting locations outside the scan scope; split independently reachable candidate locations into distinct child findings when appropriate, and preserve every candidate location across those children. Copy compact validation `confidence`, `confidence_rationale`, `method`, and `evidence` into canonical finding `confidence.level`, `confidence.rationale`, `validation.method`, and `validation.summary`; copy attack-path `severity`, text `severity_rationale`, and `change_conditions` into `severity.level`, `severity.rationale`, and `severity.changeConditions`, joining list-valued change conditions with newlines. Preserve `dataflow`, `reachability`, `counterevidence`, `impact`, and `likelihood` in `attackPath`.
- Optional compact validation evidence: `<discovery_dir>/validation_artifacts/<candidate_id>/`
  - Create this directory only for actual PoCs, crafted inputs, or logs and reference those paths from the row's `validation` object. Do not create placeholder per-candidate directories or narrative reports.

The legacy ranking, raw/deduped candidate, per-finding receipt, and phase-report paths below are for diff/deep or resumed legacy workflows. A compact standard scan uses the enriched ledger instead.

### Coverage Planning

- Advisory seed research: `<context_dir>/seed_research.md`
- Scoped ranking input: `<discovery_dir>/rank_input.jsonl` if applicable
- Scoped ranking shards: `<discovery_dir>/rank_shards/rank-shard-NNNN.input.jsonl` and matching worker-local `.output.jsonl` files if ranking applies
- Scoped ranking worker assignments: `<discovery_dir>/rank_worker_assignments.json` if ranking applies
- Scoped ranking output: `<discovery_dir>/rank_output.jsonl` if applicable
- Scoped deep-review input: `<discovery_dir>/deep_review_input.jsonl` if applicable
- Finding discovery report: `<discovery_dir>/finding_discovery_report.md`

### Deep Review

- Scoped work ledger: `<discovery_dir>/work_ledger.jsonl` if applicable
- Scoped raw candidates: `<discovery_dir>/raw_candidates.jsonl` if applicable

### Candidate Reconciliation

- Candidate findings directory: `<findings_dir>/`
- Per-finding directory: `<findings_dir>/<candidate_id>/`
- Per-finding candidate ledger: `<findings_dir>/<candidate_id>/candidate_ledger.jsonl`
- Scoped dedupe report: `<reconciliation_dir>/dedupe_report.md` if applicable
- Scoped deduped candidates: `<reconciliation_dir>/deduped_candidates.jsonl` if applicable

### Coverage

- Repository-wide coverage ledger: `<coverage_dir>/repository_coverage_ledger.md`
  - This is a coverage artifact, not a findings list: it should include checked surfaces with not_applicable, suppressed, deferred, or reportable dispositions.
- Reviewed surfaces summary: `<coverage_dir>/reviewed_surfaces.md` if applicable

## Validation (Phase 3) Paths

Compact standard scans use the nested `validation` record and optional compact evidence path above. Other scan modes use these paths:

- Scan-level validation summary: `<findings_dir>/validation_summary.md` if applicable
- Per-finding validation report: `<findings_dir>/<candidate_id>/validation_report.md`
- Per-finding validation artifacts: `<findings_dir>/<candidate_id>/validation_artifacts/`

## Attack-Path Analysis (Phase 4) Paths

Compact standard scans use the nested `attack_path` record above. Other scan modes use these paths:

- Scan-level attack-path analysis report: `<findings_dir>/attack_path_analysis_report.md` if applicable
- Per-finding attack-path analysis report: `<findings_dir>/<candidate_id>/attack_path_analysis_report.md`

## Final Report Paths

- Final scan report: `<scan_dir>/report.md`
- Detailed vulnerability write-up: `<scan_dir>/findings/<slug>/<slug>.md`
- Per-finding PoC and supporting files: `<scan_dir>/findings/<slug>/poc/...`
- Structural hardening portfolio: `<scan_dir>/hardening/hardening.md`
- Hardening analysis, proposals, and diagrams: `<scan_dir>/hardening/...`
- Final report validation notes, when validation fails: `<scan_dir>/report_validation.md`

## Fix Finding Paths

- Fix report, when using an existing scan artifact directory: `<artifacts_dir>/fix_report.md`

## Placement Rules

- Put scan phase outputs and supporting evidence under the numbered artifact subdirectories above.
- Keep fix-finding outputs outside the numbered scan phases because fix-finding can run standalone or against an existing scan.
- Do not author the final `report.md` directly. Put complete scan-level report semantics in the canonical JSON files. Detailed per-finding prose in `findings/<slug>/<slug>.md` and derived design guidance under `hardening/` are optional for a standard scan. Finalization deterministically writes the unsealed `report.md` projection and links any recorded write-ups and hardening portfolio. Do not add these derived documents to the sealed artifact list.
- Keep the full scan bundle together under `scan_dir`.
