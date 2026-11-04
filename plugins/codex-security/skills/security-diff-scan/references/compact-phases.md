# Compact diff phase contracts

Use the saved scan ID, per-scan threat model, and authorized diff. Pass each phase its inputs and the contract below. The parent submits each batch once, after reconciling any delegated assignments. The batch records are the phase outputs. Skip ranked worklists, per-finding ledgers, duplicate reports and receipts.

## Discovery

Use every page of the prepared inventory from `list_codex_security_review_items`. Review every assigned changed text file, including deletions at the baseline. Give workers their assigned files and ask them to return candidate evidence and coverage limitations. Account for unassigned files in the parent. Submit all candidates, including an empty list, through `record_codex_security_discovery_candidates({ scanId, candidates })`. The writer checks assigned paths, merges rows with matching CWE IDs, locations and optional instance, preserves their text, and assigns stable candidate IDs for subsequent phases.

## Validation

Read every page from `list_codex_security_candidates({ scanId, cursor?, limit? })`. Use the reviewer feedback supplied by the caller or scan context (`reviewerFeedbackPath`) as evidence. Submit one disposition for each candidate through `record_codex_security_candidate_validations({ scanId, validations: [{ candidateId, validation }] })`. The [validation schema](../../../schemas/tools/candidate-validations.schema.json) requires a `rubric` naming the security property assessed. Include `source`, `control`, `sink`, or `preconditions` only when they clarify or differ from discovery. Use `artifacts/02_discovery/validation_artifacts/<candidate_id>/` only for actual retained evidence and reference those files from the validation. A validation phase invoked with no candidates submits `validations: []`.

## Attack-path analysis

Use the retained threat model and read every page of validated candidates from `list_codex_security_candidates({ scanId, cursor?, limit? })`. Analyze every candidate marked `reportable` or `deferred`. Submit one decision for each through `record_candidate_attack_paths({ scanId, attackPaths: [{ candidateId, attackPath }] })`, following the [attack-path schema](../../../schemas/tools/candidate-attack-paths.schema.json). A phase invoked with no eligible candidates submits `attackPaths: []`. Both validation and attack-path tools preserve the previous fields and candidate order.
