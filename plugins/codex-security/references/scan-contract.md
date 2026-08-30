# Sealed Scan Contract

This contract defines the canonical machine-readable documents for scans that reached a sealed terminal outcome and their readable markdown report projection.

## Canonical Documents

A sealed terminal bundle contains these files under `<scan_dir>`:

- `scan-manifest.json`: immutable terminal scan receipt after finalization
- `findings.json`: semantic finding records retained when the scan reached its terminal outcome
- `coverage.json`: structured coverage summary with detailed receipt references

Canonical UTF-8 document sizes are bounded consistently by the producer and SDK: `scan-manifest.json` is limited to 16 MiB, `findings.json` to 128 MiB, and `coverage.json` to 32 MiB. Finalization rejects oversized inputs or generated documents before sealing or changing scan outputs. Keep detailed evidence in scan-local artifacts and reference it from the canonical summaries.

Optional structured finding details used by rich consumers are documented in `finding-detail-fields.md`. They remain part of each semantic finding record, not a projection parsed from a readable report.

The existing `report.md` output remains a readable projection. Generated exports such as SARIF are also downstream projections, not part of the canonical semantic source of truth.

Deep-scan SARIF results and CSV rows preserve their existing instance-level presentation and add only the canonical candidate id needed to group child reports. Standard-scan CSV presentation remains unchanged.

This bundle records immutable scan observations. It is not a workflow-state database. Consumers must store mutable annotations, lifecycle decisions, external links, retention policy, and synchronization state separately.

Retention is an explicit consumer decision. Producing a sealed bundle must not silently copy it into an archive.

## Manifest Semantics

A sealed manifest records the terminal timestamp and hashes for the canonical documents and immutable evidence receipts included in that bundle. Readable reports and generated exports are projections and are not included in the canonical seal. Later adapters may read the sealed bundle to create projections, but must not mutate the sealed manifest or canonical documents. Store projections separately. Every sealed manifest includes exactly one artifact record for each canonical JSON document, and artifact paths must not repeat.

`scan.status` records why the bundle was sealed:

| Status | Meaning |
| --- | --- |
| `completed` | The requested scan reached normal completion. |
| `failed` | The scan stopped after an unrecoverable failure; retained artifacts may be partial. |
| `canceled` | The scan stopped after an explicit cancellation; retained artifacts may be partial. |
| `interrupted` | The scan stopped before normal completion because execution was interrupted; retained artifacts may be partial. |

Only `completed` supports a completed-scan conclusion. For every stopped outcome, consumers must preserve retained findings and coverage while treating absence of findings as inconclusive.

### Stopped Result Recovery

To validate and republish retained checkpoints for a failed, non-canceled workbench scan, run:

```text
<python_command> <plugin_dir>/scripts/workbench_db.py recover-scan-results --scan-id <scan_id>
```

Recovery can add only checkpoints that pass the stopped-scan source-integrity checks. It is not available for running, completed, or canceled scans. After cancellation, the owning continuation may retry publication only from the source set frozen at cancellation through `preserve-scan-results`; it cannot admit later checkpoints.

## Target Snapshots

Choose the target kind based on the reviewed content, not the scan invocation:
`git_worktree` for a checked-out Git workspace, `directory_snapshot` for a non-Git directory, `git_diff` for a Git-backed change set, and `git_revision` for an exact immutable Git tree.

For a workbench-backed scan, use the recorded target contract instead of inferring the kind from the checkout.
A clean Git checkout has `allowedKinds: ["git_revision"]`: use its recorded revision and omit `snapshotDigest`.
A dirty checkout has `allowedKinds: ["git_worktree"]`: copy `requiredSnapshotDigest` exactly.

| Kind | Required snapshot fields |
| --- | --- |
| `git_revision` | `revision` |
| `git_worktree` | `revision` when available and `snapshotDigest` |
| `git_diff` | `snapshotDigest`; include `baseRevision` and `headRevision` when available |
| `directory_snapshot` | `snapshotDigest` |

`targetId` identifies the stable repository or workspace. Prefer a digest of a sanitized canonical absolute remote URL when one exists. Otherwise use a digest of a stable local workspace identity. Never persist remote URL credentials, query parameters, fragments, or tokens.

For dirty worktrees and working-tree diffs, calculate `snapshotDigest` from a deterministic representation of the reviewed content, including staged changes and reviewed untracked files where applicable. For committed or revision-range diffs, derive it from the exact authoritative diff kind and immutable base/head revisions. For directory snapshots, hash a sorted relative-path and file-hash inventory of the reviewed scope. Encode the result as `codex-security-snapshot/v1:sha256:<64 lowercase hex characters>`.

## Finding Identity

Each authored finding includes:

- stable `ruleId`: vulnerability class or generated rule family
- stable `identity.anchor`: semantic root-control anchor
- optional `identity.instance`: independently attackable sibling instance

Use lowercase slugs for all three values. Keep them stable across nearby line movement and file renames. Finalization derives:

- `fingerprints.primary` from target ID, rule ID, anchor, and instance
- `findingId` from the fingerprint
- `occurrenceId` from scan ID and fingerprint

Do not put line numbers in `identity.anchor`. When two sibling vulnerabilities share a rule and semantic anchor, give them distinct stable `identity.instance` values.

Fingerprint matching is a reconciliation signal, not proof that two findings are equivalent. Treat ambiguous matches as unresolved.

When a finding has multiple affected locations, label the vulnerable control location `root_control` when one is known. Adapters keep the first `root_control` location first and otherwise fall back to the first affected location, while preserving every distinct entrypoint, wrapper, sink, concrete-implementation, and code-evidence occurrence as a matchable location.

## Rule ID Policy

`ruleId` identifies a stable vulnerability family, not a per-scan finding.
Prefer:

`<primary-category>.<stable-control-family>`

Examples:

- `path-traversal.archive-extraction`
- `authorization-bypass.object-update`
- `sql-injection.query-builder`

Use CWE taxonomy separately. Do not include file names, line numbers, scan IDs, or display numbering in `ruleId`.

## Coverage

`coverage.json` prevents downstream consumers from confusing `not observed` with `not scanned`.

Record:

- scan mode and inventory strategy
- included and excluded paths
- reviewed surfaces
- detailed receipt references
- explicit exclusions
- deferred work
- completeness

`mode` records the requested scan workflow:

| Mode | Meaning |
| --- | --- |
| `repository` | Repository-wide scan |
| `scoped_path` | Scan limited to explicitly requested paths |
| `diff` | Git-backed change-set scan when no more specific mode applies |
| `commit` | Commit compared with its resolved baseline |
| `branch_diff` | Branch or pull-request change set compared with its baseline |
| `working_tree` | Staged or unstaged local changes |
| `deep_repository` | Exhaustive repeated repository-wide scan |

`inventoryStrategy` records how the producer enumerated the reviewed content, independently of the requested scan workflow:

For a whole-repository Deep scan, keep `inventoryStrategy` as `repository`; repeated discovery is workflow metadata, not a different inventory strategy.

| Inventory strategy | Meaning |
| --- | --- |
| `repository` | Repository-wide tracked source-like file inventory |
| `scoped_path` | Repository inventory constrained to requested paths |
| `diff` | Files selected from the reviewed Git change set |
| `directory` | Deterministic non-Git directory inventory |
| `custom` | Producer-defined inventory described by detailed receipts |

Use `complete` when the requested scope was fully reviewed, `partial` when in-scope work was deferred, and `unknown` when the producer cannot establish enough coverage to make that distinction.

Map detailed ledger closure into completed surface summaries in this order:

| Completed surface condition | Disposition |
| --- | --- |
| At least one `reportable` row | `reported` |
| Otherwise, at least one `deferred` row | `needs_follow_up` |
| Otherwise, at least one `suppressed` row | `rejected` |
| Otherwise, an applicable surface was checked and no candidate survived | `no_issue_found` |
| Otherwise, the surface is not applicable | `not_applicable` |

Record each explicit exclusion with a `pattern` and `reason`. Record each deferred unit with a stable `id`, a `reason`, and optional `paths` or `surfaceIds`.

Detailed ledgers remain under the numbered scan artifact directories.
Receipt references must point to regular non-symlink files under `artifacts/`.
`coverage.json` is the structured summary for adapters and comparison.

## Canonical Report Semantics

The three canonical JSON files are also the only semantic inputs to final report generation. Producers must not author `report.md`; finalization deterministically projects it after validating the canonical seal. The report remains an unsealed downstream projection and can be regenerated without changing canonical JSON or evidence artifacts.

Record report-specific semantics without duplicating data already represented elsewhere:

- `scan.scope`: optional narrative `summary`, reviewed artifact names, runtime/test status, validation mode, scan context, and limitations. Include/exclude paths remain the authoritative scope boundaries.
- `scan.threatModel`: concise summary plus assets, trust boundaries, attacker capabilities, security objectives, and assumptions.
- finding `validation`: validation method, direct evidence, counterevidence, and the conclusion used by the report.
- finding `codeEvidence`: stable, exact source snippets with labels, locations, language, and explanations; `rootCause`, `validation`, and `attackPath` select the snippets they need through `evidenceRefs`.
- finding `rootCause`: the violated invariant and the code that breaks it. Do not substitute a path/line restatement for the explanation.
- finding `attackPath.dataflow`: source, transformations, sink, outcome, and a concise source-to-sink narrative.
- finding `attackPath.reachability`: attacker, entry point, preconditions, outcome, and a concise reachability narrative.
- finding `severity`: the assigned level plus rationale and the concrete evidence that would raise or lower it.
- finding remediation: the existing minimal fix string plus optional tests and preventive controls.
- coverage surfaces: optional `riskArea` and `notes` used by the Reviewed Surfaces table.
- coverage `openQuestions`: concrete unresolved questions and optional copyable follow-up prompts.

These fields are optional for compatibility with existing v1 canonical artifacts. When omitted, finalization emits explicit, deterministic fallback text derived only from the remaining canonical JSON. It never reads an existing report to recover missing semantics.

## Schemas

- `schemas/scan-manifest.schema.json`
- `schemas/findings.schema.json`
- `schemas/coverage.schema.json`

V1 consumers ignore unknown properties for forward compatibility. Producers must still validate documented fields and should not emit undocumented properties casually.

Representative valid contract examples live under `examples/completed-scan/`.
