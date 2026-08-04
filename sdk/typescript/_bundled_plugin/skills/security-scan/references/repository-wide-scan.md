# Standard Repository Or Scoped-Path Review

Use this procedure for a standard repository or scoped-path scan. Review every file, collect candidates in one ledger, then validate and check reachability in two compact passes over that ledger. Do not use ranking or multi-stage queues from deep scans.

## File Inventory And Progress

Create the file list before review:

```text
mkdir -p "<discovery_dir>"
(cd "<repo_root>" && rg --files --hidden --glob '!.git/**' -- "<scope>" | LC_ALL=C sort) > "<discovery_dir>/in_scope_files.txt"
```

Keep repository-relative paths in artifacts. Do not skip a file just because it is educational, an example, a demo, a fixture, or a test. Include it when it contains runnable behavior such as a route, parser, or template. List binary or generated files that could not be reviewed. Because every file is reviewed, do not create ranking or deep-review worklists.

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

Write raw candidates to one or more temporary JSONL files, then combine them:

```text
<python_command> <plugin_dir>/scripts/normalize_candidates.py --input <candidate-source> [<candidate-source> ...] --out <discovery_dir>/candidate_ledger.jsonl --repo-root <repo_root> --in-scope-files <discovery_dir>/in_scope_files.txt
```

Each raw candidate row uses only these fields:

- `cwe_ids`: an array of `CWE-<positive integer>` strings, which may be empty.
- `locations`: an array of repository-relative `path`, positive `start_line`, optional `end_line`, and `role`. The role is one of `entrypoint`, `entrypoint/wrapper`, `source`, `root_control`, `sink`, `concrete_implementation`, or `evidence`. At least one location must be in `in_scope_files.txt`; supporting locations may be elsewhere in the repository.
- `summary` and `evidence`: concise text describing the possible bug and the code path.
- optional `context`: concise text that may help the review.
- optional `instance`: a short label for separate bugs that share the same locations, such as different request parameters or operations.

The combiner validates this shape and merges rows with the same CWE ids, locations, and optional instance. It preserves their text and writes deterministic rows with a stable `candidate_id`. It does not infer a status or decide whether a candidate is a bug. `candidate_ledger.jsonl` is the sole durable candidate artifact for a standard scan. Do not create one ledger or report per candidate, validation or attack-path queues, duplicate reports, or repeated receipts.

After normalization, freeze every discovery field, including `candidate_id`, `locations`, and `instance`. The two compact phase passes below may only add their nested records. Rewrite the ledger atomically and preserve its row order. Never feed an enriched ledger back through `normalize_candidates.py`; that script accepts raw discovery rows only.

## Validate And Check Reachability

Run `$validation` once over the complete ledger in compact standard-scan mode. It must add a `validation` record to every row and preserve separate bugs, including bugs reachable through different routes or code paths. Do not dismiss a real bug just because the code is a demo, test, or only runs locally.

Then run `$attack-path-analysis` once in compact standard-scan mode over validation rows with disposition `reportable` or `deferred`. It must add an `attack_path` record to every row that enters the phase, preserve exact affected locations, and use the threat model to decide realistic reachability and severity. A neighboring finding does not close the current candidate.

Build canonical findings and coverage from the file list and enriched candidate decisions using the ordered mapping in `../../../references/final-report.md`. Include all relevant code locations in each finding.
