# Standard Repository Or Scoped-Path Review

Use this procedure for a Standard repository or scoped-path scan and independent Deep discovery workers. Review every file, record the complete candidate set once, then validate and check reachability in two compact passes over those candidates. Deep discovery workers perform only the discovery pass.

## File Inventory And Progress

Prepare the file list before a Standard review:

```text
prepare_codex_security_review_items({ scanId, handoffClaimToken? })
list_codex_security_review_items({ scanId, handoffClaimToken?, cursor?, limit? })
```

Follow `nextCursor` until every repository-relative review item has been returned. An independent Deep discovery worker uses its context-bound `list_codex_security_review_items({ cursor?, limit? })`; its coordinator has already prepared the inventory. Do not skip a file just because it is educational, an example, a demo, a fixture, or a test. Include it when it contains runnable behavior such as a route, parser, or template. Account for binary or generated files that could not be reviewed. Because every file is reviewed, do not create ranking or deep-review worklists.

For an app scan, keep `reviewItemsTotal` at zero while building the file list. Then publish the file count, review files in batches, and update `reviewItemsCompleted` after each batch.

For an SDK or terminal scan with `CODEX_SECURITY_SCAN_ID`, emit this standalone line in an agent message or completed command output after building the file list, after each completed review batch, and when entering validation, attack-path analysis, or reporting:

```text
CODEX_SECURITY_SCAN_PROGRESS {"phase":"discovery","filesCompleted":3,"filesTotal":8}
```

Use the actual phase (`discovery`, `validation`, `attack_path`, or `reporting`), the number of fully reviewed files, and the total from `in_scope_files.txt`. Start discovery at zero completed files. Never count a searched, assigned, or partially reviewed file as completed. Do not include paths, findings, credentials, or other fields.

When delegating, include this rule in each worker prompt and have workers report their own completed and assigned file counts after each small review batch.

## Discover And Combine Once

Review every listed file from start to finish. Read nearby code when needed to understand it. Look for unsafe command execution, unsafe parsing, XSS, attacker-controlled network requests, unsafe file access, and missing permission checks. Do not ignore a clear bug because another issue seems more important.

Do not stop reviewing a file after finding one bug.

Collect all semantic discovery candidates, then record the complete set in one call:

```text
record_codex_security_discovery_candidates({ scanId, candidates })
```

An independent Deep discovery worker omits `scanId` because its artifact context is already bound. This operation replaces the complete candidate set: call it once after discovery with all candidates, or with `candidates: []` when none are found.

Each semantic candidate uses only these fields:

- `cwe_ids`: an array of `CWE-<positive integer>` strings, which may be empty.
- `locations`: an array of repository-relative `path`, positive `start_line`, optional `end_line`, and `role`. The role is one of `entrypoint`, `entrypoint/wrapper`, `source`, `root_control`, `sink`, `concrete_implementation`, or `evidence`. At least one location must be an assigned review item; supporting locations may be elsewhere in the repository.
- `summary` and `evidence`: concise text describing the possible bug and the code path.
- optional `context`: concise text that may help the review.
- optional `instance`: a short label for separate bugs that share the same locations, such as different request parameters or operations.

The tool validates this shape and merges candidates with the same CWE ids, locations, and optional instance. It preserves their text and assigns deterministic `candidate_id` values. It does not infer a status or decide whether a candidate is a bug. Read recorded candidates through `list_codex_security_candidates({ scanId, cursor?, limit? })`; a bound Deep worker omits `scanId`. Do not create one report per candidate, validation or attack-path queues, duplicate reports, or repeated receipts.

After normalization, freeze every discovery field, including `candidate_id`, `locations`, and `instance`. The two compact phase passes below may only add their nested records. The phase tools preserve candidate order and atomically replace the stored candidate set.

## Validate And Check Reachability

Run `$validation` once over the complete candidate set in compact standard-scan mode. Submit exactly one validation per candidate through `record_codex_security_candidate_validations({ scanId, validations })`. Preserve separate bugs, including bugs reachable through different routes or code paths. Do not dismiss a real bug just because the code is a demo, test, or only runs locally.

Then run `$attack-path-analysis` once in compact standard-scan mode over candidates with validation disposition `reportable` or `deferred`. Submit exactly one attack-path decision per eligible candidate through `record_candidate_attack_paths({ scanId, attackPaths })`, preserve exact affected locations, and use the threat model to decide realistic reachability and severity. A neighboring finding does not close the current candidate.

Build semantic findings and coverage from the review items and enriched candidate decisions using the ordered mapping in `../../../references/final-report.md`. Include all relevant code locations in each finding, then record the completed canonical draft with `record_codex_security_scan_draft`.
