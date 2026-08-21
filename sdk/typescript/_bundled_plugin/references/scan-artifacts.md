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
- `target_paths_file=<CODEX_SECURITY_TARGET_PATHS_FILE>` for SDK scoped-path scans; reference it as `"$CODEX_SECURITY_TARGET_PATHS_FILE"` in POSIX shells or `"$env:CODEX_SECURITY_TARGET_PATHS_FILE"` in PowerShell. This read-only scope input lives in the isolated Codex home outside the model-writable scan directory. Pass it directly to `make-repo-scope-input --scopes-file` and `bind-repo-scopes --scopes-file` before finalization, and do not print, evaluate, modify, or treat its contents as shell syntax.
- `artifacts_dir=<scan_dir>/artifacts`
- `context_dir=<artifacts_dir>/01_context`
- `discovery_dir=<artifacts_dir>/02_discovery`
- `coverage_dir=<artifacts_dir>/03_coverage`
- `reconciliation_dir=<artifacts_dir>/04_reconciliation`
- `findings_dir=<artifacts_dir>/05_findings`

The plugin resolves the platform temporary directory automatically. For a manual workflow, use the active process temporary directory (for example, `%TEMP%` on Windows or `$TMPDIR` when configured on Unix-like hosts) instead of hardcoding `/tmp`.

Resolve `<python_command>` to the configured Python interpreter (`"$PYTHON"` in POSIX shells or `& "$env:PYTHON"` in PowerShell), otherwise use `python` on Windows and `python3` on Unix-like hosts.

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

### Compact Deep And Workbench-Backed Diff Discovery

Workbench-owned Standard scans submit findings and coverage through `record_codex_security_scan_draft`; SDK-owned Standard scans write unsealed canonical files directly. Deep scans run complete Standard scan workers, each of which submits its validated findings, coverage, threat model, and optional scope through its bound `record_codex_security_scan_draft` tool. The coordinator semantically reduces those complete results and writes the parent scan's unsealed `scan-manifest.json`, `findings.json`, and `coverage.json`. The parent does not list candidates, rerun validation or attack-path phases, or submit another draft. Workbench-backed diff scans retain the compact artifacts described below.

- A workbench-backed diff scan records all candidates once with `record_codex_security_discovery_candidates({ scanId, candidates })` and reads the canonical candidates with `list_codex_security_candidates({ scanId, cursor?, limit? })`.
  - The writer validates candidates against assigned source paths, merges rows with the same CWE ids, locations, and optional instance, preserves their text, and assigns deterministic `candidate_id` values.
  - After normalization, compact validation adds exactly one `validation` object to every row with `disposition` (`reportable`, `suppressed`, `not_applicable`, or `deferred`), `method`, `confidence` (`high`, `medium`, or `low`), `confidence_rationale`, concise `rubric` and `evidence`, `counterevidence_or_proof_gap`, `remaining_uncertainty`, and optional `artifact_paths`. Add `source`, `control`, `sink`, or `preconditions` only when they clarify or differ from the discovery fields.
  - Compact attack-path analysis adds exactly one `attack_path` object to each validation row marked `reportable` or `deferred`, with `decision` (`reportable`, `ignore`, or `deferred`), `dataflow`, `reachability`, `counterevidence`, `impact` and `likelihood` (`high`, `medium`, `low`, `ignore`, or `unknown`), `severity` (`critical`, `high`, `medium`, `low`, `ignore`, or `unknown`), `severity_rationale`, `change_conditions`, and `proof_gap` when deferred. A `reportable` decision requires severity `critical`, `high`, `medium`, or `low`; `ignore` requires severity `ignore`; `deferred` uses a provisional reportable severity or `unknown`.
  - Record all validations through `record_codex_security_candidate_validations` and all eligible attack-path decisions through `record_candidate_attack_paths`. The tools atomically preserve all discovery fields and candidate order.
- Optional compact validation evidence: `<discovery_dir>/validation_artifacts/<candidate_id>/`
  - Create this directory only for actual PoCs, crafted inputs, or logs and reference those paths from the row's `validation` object. Do not create placeholder per-candidate directories or narrative reports.

The worklist, per-finding receipt, and phase-report paths below apply only to standalone or legacy Diff workflows. Compact Workbench Diff scans use one shared `<discovery_dir>/candidate_ledger.jsonl`, written by `record_codex_security_discovery_candidates` and updated by the bound batch tools `record_codex_security_candidate_validations` and `record_candidate_attack_paths`; they do not create per-finding ledgers, reports, or receipts. Standard and Deep scans assemble validated findings directly without persisted source inventories or candidate ledgers.

### Diff Discovery And Coverage

- Advisory seed research: `<context_dir>/seed_research.md`
- Changed source input: `<discovery_dir>/rank_input.jsonl`
- Scoped deep-review input: `<discovery_dir>/deep_review_input.jsonl` if applicable
- Finding discovery report: `<discovery_dir>/finding_discovery_report.md`

### Deep Review

- Scoped work ledger: `<discovery_dir>/work_ledger.jsonl` if applicable
- Scoped raw candidates: `<discovery_dir>/raw_candidates.jsonl` if applicable

### Candidate Reconciliation

- Compact Diff candidate ledger: `<discovery_dir>/candidate_ledger.jsonl`
- Standalone or legacy Diff candidate findings directory: `<findings_dir>/`
- Standalone or legacy Diff per-finding directory: `<findings_dir>/<candidate_id>/`
- Standalone or legacy Diff per-finding candidate ledger: `<findings_dir>/<candidate_id>/candidate_ledger.jsonl`
- Scoped dedupe report: `<reconciliation_dir>/dedupe_report.md` if applicable
- Scoped deduped candidates: `<reconciliation_dir>/deduped_candidates.jsonl` if applicable

### Coverage

- Repository-wide coverage ledger: `<coverage_dir>/repository_coverage_ledger.md`
  - This is a coverage artifact, not a findings list: it should include checked surfaces with not_applicable, suppressed, deferred, or reportable dispositions.
- Reviewed surfaces summary: `<coverage_dir>/reviewed_surfaces.md` if applicable

## Validation (Phase 3) Paths

Standard scans and Deep Standard scan workers include validation directly in their final finding semantics. Compact workbench-backed diff scans record validation through their bound batch tool and may use the optional compact evidence path above. Standalone or legacy diff workflows may use these paths:

- Scan-level validation summary: `<findings_dir>/validation_summary.md` if applicable
- Per-finding validation report: `<findings_dir>/<candidate_id>/validation_report.md`
- Per-finding validation artifacts: `<findings_dir>/<candidate_id>/validation_artifacts/`

## Attack-Path Analysis (Phase 4) Paths

Standard scans and Deep Standard scan workers include attack-path analysis directly in their final finding semantics. Compact workbench-backed diff scans record attack-path decisions in each candidate's nested `attack_path` record through their bound batch tool. Standalone or legacy diff workflows may use these paths:

- Scan-level attack-path analysis report: `<findings_dir>/attack_path_analysis_report.md` if applicable
- Per-finding attack-path analysis report: `<findings_dir>/<candidate_id>/attack_path_analysis_report.md`

## Final Report Paths

- Workbench-owned Standard or workbench-backed diff draft: `record_codex_security_scan_draft({ scanId, handoffClaimToken?, scope?, threatModel?, findings, coverage })`
- Bound Deep Standard worker result: `record_codex_security_scan_draft({ scanId, scope?, threatModel?, findings, coverage })`; the Deep coordinator writes the aggregated parent draft
- SDK-owned Standard draft: unsealed `scan-manifest.json`, `findings.json`, and `coverage.json` under the SDK-provided scan directory
- Deep, workbench-backed diff, or explicitly requested Standard completed results: `get_codex_security_completed_scan({ scanId, handoffClaimToken? })`
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
- Do not author the final `report.md` directly. Put complete scan-level report semantics in the canonical JSON files. Detailed per-finding prose in `findings/<slug>/<slug>.md` and derived design guidance under `hardening/` are optional for every scan mode. Finalization deterministically writes the unsealed `report.md` projection and links any recorded write-ups and hardening portfolio. Do not add these derived documents to the sealed artifact list.
- Keep the full scan bundle together under `scan_dir`.
