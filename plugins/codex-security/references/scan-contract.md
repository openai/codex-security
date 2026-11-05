# Sealed Scan Contract

This contract defines the canonical machine-readable documents for scans that reached a sealed terminal outcome and their readable markdown report projection.

## Canonical Documents

Open the [current example manifest](../examples/completed-scan/scan-manifest.json) alongside its [findings](../examples/completed-scan/findings.json) and [readable report](../examples/completed-scan/report.md).

| File or field | What it contains |
| --- | --- |
| `scan-manifest.json` | Immutable receipt with scan ID, target, scope, terminal status, seal time, and artifact digests. |
| `findings.json` | Semantic finding records retained at the terminal outcome. The manifest's `scan.findingsRef` points to this file. See [finding detail fields](finding-detail-fields.md) for optional evidence and analysis. |
| `scan.review` inside the manifest | Additional excluded paths (`excludedPaths`). |
| `report.md` | Human-readable report generated from the canonical JSON. The [SARIF adapter](sarif-adapter.md) explains which fields survive export. |

See [final report paths](scan-artifacts.md#final-report-paths) for the complete directory layout and optional outputs.

For a [legacy manifest](../examples/legacy-completed-scan/scan-manifest.json) with `scan.coverageRef`, read the [referenced coverage document](../examples/legacy-completed-scan/coverage.json) alongside the findings. Check for this field before opening a separate coverage file. Keep detailed evidence in scan-local artifacts and reference it from the canonical summaries.

Deep-scan SARIF results and CSV rows preserve their existing instance-level presentation and add only the canonical candidate id needed to group child reports. Standard-scan CSV presentation remains unchanged.

This bundle records immutable scan observations. It is not a workflow-state database. Consumers must store mutable annotations, lifecycle decisions, external links, retention policy, and synchronization state separately.

Retention is an explicit consumer decision. Producing a sealed bundle must not silently copy it into an archive.

## Manifest Semantics

The manifest records the terminal timestamp and a SHA-256 digest for each file listed in `scan.artifacts`. Each path appears exactly once. The current example lists `findings.json` alone. A legacy bundle also lists its referenced coverage file, and scans that retain immutable evidence receipts list those files too. The manifest carries these digests and does not hash itself. Adapters read the sealed files and write reports or exports separately from the seal.

Producers should use UTC ISO 8601 timestamps in the native SDK or plugin format. All schema-valid fractional widths remain readable on supported Python versions; parsing uses native microsecond precision. History and finding queries use native date precision and stable ID tie-breakers; ordering beyond millisecond precision is not guaranteed. Stored timestamp text remains unchanged.

`scan.status` records why the bundle was sealed:

| Status        | Meaning                                                                                                         |
| ------------- | --------------------------------------------------------------------------------------------------------------- |
| `completed`   | The requested scan reached normal completion.                                                                   |
| `failed`      | The scan stopped after an unrecoverable failure; retained artifacts may be partial.                             |
| `canceled`    | The scan stopped after an explicit cancellation; retained artifacts may be partial.                             |
| `interrupted` | The scan stopped before normal completion because execution was interrupted; retained artifacts may be partial. |

Only `completed` supports a completed-scan conclusion. For every stopped outcome, consumers must preserve retained findings and review state while treating absence of findings as inconclusive.

Optional `scan.warnings` records run-level diagnostics available when the bundle is first sealed. SARIF exports include these messages alongside deferred-task reasons in `toolExecutionNotifications`; warnings do not change `executionSuccessful`, which follows `scan.status`. Missing or empty warnings add no notifications. Existing sealed bundles remain unchanged, and export or publication warnings discovered afterward remain separate operation diagnostics.

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

| Kind                 | Required snapshot fields                                                   |
| -------------------- | -------------------------------------------------------------------------- |
| `git_revision`       | `revision`                                                                 |
| `git_worktree`       | `revision` when available and `snapshotDigest`                             |
| `git_diff`           | `snapshotDigest`; include `baseRevision` and `headRevision` when available |
| `directory_snapshot` | `snapshotDigest`                                                           |

`targetId` identifies the stable repository or workspace. Prefer a digest of a sanitized canonical absolute remote URL when one exists. Otherwise use a digest of a stable local workspace identity. Never persist remote URL credentials, query parameters, fragments, or tokens.

For dirty worktrees and working-tree diffs, calculate `snapshotDigest` from a deterministic representation of the reviewed content, including staged changes and reviewed untracked files where applicable. For committed or revision-range diffs, derive `snapshotDigest` from the authoritative diff kind and immutable base/head revisions. The workbench supplies it during finalization, so workbench-backed unsealed drafts may omit it. Previously sealed manifests retain their recorded digest. For directory snapshots, hash a sorted relative-path and file-hash inventory of the reviewed scope. Encode the result as `codex-security-snapshot/v1:sha256:<64 lowercase hex characters>`.

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

## Review state

New scans publish `scan-manifest.json` and `findings.json`. The manifest owns scan identity, mode, and configured scope. `scan.review` contains only `excludedPaths`, used when comparing scans. These values do not measure the percentage of files read.

A Deep parent retains the configured paths and notes from accepted reviews. Worker IDs distinguish each review's surfaces and deferred items. Receipt references point to the original evidence. Merging duplicate findings preserves pending review work. If the discovery deadline arrives before a review finishes, the host preserves valid checkpoint findings and pending work with the deadline reason. See [stopped-result recovery](#stopped-result-recovery).

For file-authored drafts, put `reviewState` inside `scan` in the unsealed manifest. Finalization preserves recovery details in checkpoints and replaces the draft state with the small `scan.review` summary. For tool-authored drafts, pass `reviewState` to `record_codex_security_scan_draft`.

Comparison uses the later scan's execution status, configured scope and additional exclusions before classifying an absent finding as resolved.

### Scan modes and inventory

`scan.mode` (or `mode` in a legacy coverage document) records the requested scan workflow:

| Mode              | Meaning                                                       |
| ----------------- | ------------------------------------------------------------- |
| `repository`      | Repository-wide scan                                          |
| `scoped_path`     | Scan limited to explicitly requested paths                    |
| `diff`            | Git-backed change-set scan when no more specific mode applies |
| `commit`          | Commit compared with its resolved baseline                    |
| `branch_diff`     | Branch or pull-request change set compared with its baseline  |
| `working_tree`    | Staged or unstaged local changes                              |
| `deep_repository` | Exhaustive repeated repository-wide scan                      |

In a legacy coverage document, `inventoryStrategy` records how the producer enumerated the reviewed content:

| Inventory strategy | Meaning                                                   |
| ------------------ | --------------------------------------------------------- |
| `repository`       | Repository-wide file inventory                            |
| `scoped_path`      | Repository inventory constrained to requested paths       |
| `diff`             | Files selected from the reviewed Git change set           |
| `directory`        | Deterministic non-Git directory inventory                 |
| `custom`           | Producer-defined inventory described by detailed receipts |

The discovery helper reads one UTF-8 path per line from `in_scope_files.txt`. It accepts LF and CRLF separators and preserves other whitespace. Filenames containing CR or LF are unsupported. For a whole-repository Deep scan, use `repository` for the inventory strategy and `deep_repository` for the mode.

### Detailed review state in drafts, checkpoints, and legacy coverage

These records can list reviewed surfaces, exclusions, and follow-up work. Use the terminal manifest for execution status.

Map detailed ledger closure into completed surface summaries in this order:

| Completed surface condition                                            | Disposition       |
| ---------------------------------------------------------------------- | ----------------- |
| At least one `reportable` row                                          | `reported`        |
| Otherwise, at least one `deferred` row                                 | `needs_follow_up` |
| Otherwise, at least one `suppressed` row                               | `rejected`        |
| Otherwise, an applicable surface was checked and no candidate survived | `no_issue_found`  |
| Otherwise, the surface is not applicable                               | `not_applicable`  |

Record each explicit exclusion with a `pattern` and `reason`. Record each deferred unit with a stable `id`, a `reason`, and optional `paths` or `surfaceIds`.

When retained, detailed ledgers live under the numbered scan artifact directories.
Receipt references must point to regular non-symlink files under `artifacts/`.
`scan.review` retains additional exclusions for adapters and comparison. Legacy sealed scans continue to reference their original `coverage.json`.

## Canonical Report Semantics

In the current format, the manifest and findings are the semantic inputs to final report generation. Producers must not author `report.md`; finalization deterministically projects it after validating the canonical seal. The report remains an unsealed downstream projection and can be regenerated without changing canonical JSON or evidence artifacts.

Record report-specific semantics without duplicating data already represented elsewhere:

- `scan.scope`: optional narrative `summary`, reviewed artifact names, runtime/test status, validation mode, scan context, and limitations. Include/exclude paths remain the authoritative scope boundaries.
- `scan.threatModel`: structured summary plus assets, trust boundaries, attacker capabilities, security objectives, and assumptions, or `{ "format": "markdown", "content": "<exact model text>" }` for a retained document. Optional model `scope` and `origin` identify the modeled paths and source separately from the scan's scope. When completed Deep reviews supply different models, the parent retains the first model here and the other models on their worker records in the retained draft or checkpoint review state. The host derives `<scan_dir>/threatmodel.md` from the primary model; it is an exportable projection, not an independently authored input.
- finding `validation`: validation method, direct evidence, counterevidence, and the conclusion used by the report.
- finding `codeEvidence`: stable, exact source snippets with labels, locations, language, and explanations; `rootCause`, `validation`, and `attackPath` select the snippets they need through `evidenceRefs`.
- finding `rootCause`: the violated invariant and the code that breaks it. Do not substitute a path/line restatement for the explanation.
- finding `attackPath.dataflow`: source, transformations, sink, outcome, and a concise source-to-sink narrative.
- finding `attackPath.reachability`: attacker, entry point, preconditions, outcome, and a concise reachability narrative.
- finding `severity`: the assigned level plus rationale and the concrete evidence that would raise or lower it.
- finding remediation: the existing minimal fix string plus optional tests and preventive controls.

These fields are optional for compatibility with existing v1 canonical artifacts. When omitted, finalization emits explicit, deterministic fallback text derived only from the remaining canonical JSON. It never reads an existing report to recover missing semantics.

## Schemas

New completed findings must match the [scan draft schema](../schemas/tools/scan-draft.schema.json). Finalization rejects legacy field aliases, malformed optional details, and invalid semantic slugs instead of repairing them. Historical sealed reports are validated through an in-memory compatibility adapter; their saved bytes remain unchanged. Stopped-scan recovery still salvages saved evidence.

- [Scan manifest schema](../schemas/scan-manifest.schema.json)
- [Findings schema](../schemas/findings.schema.json)
- [Coverage schema](../schemas/coverage.schema.json) for legacy scans

V1 consumers ignore unknown properties for forward compatibility. Producers must still validate documented fields and should not emit undocumented properties casually.
