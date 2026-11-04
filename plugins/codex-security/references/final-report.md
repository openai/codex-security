# Final Scan Results

The canonical inputs are `scan-manifest.json` and `findings.json`. The host validates and seals those documents and evidence, then projects `report.md`. Do not author or repair that report, parse it back into findings, or use it to fill gaps in canonical evidence. Follow `artifact-storage.md` for retained files.

## Ownership And Submission

| Caller | Submit | Completion owner |
| --- | --- | --- |
| Workbench Standard or diff | `record_codex_security_scan_draft({ scanId, handoffClaimToken?, scope?, threatModel?, findings, reviewState, complete? })` | Parent calls `complete_codex_security_scan` after an accepted final draft |
| Bound Deep Standard worker | Its bound semantic draft tool | Deep coordinator |
| Workbench Deep parent | Coordinator's accepted aggregate | Coordinator finalizes the scan and returns `completion` with the sealed manifest |
| SDK-owned scan | Unsealed canonical files with the SDK-provided identity and metadata, using a bound draft tool when supplied | SDK; do not call completion or a finalizer |

Other scans need authoritative managed context; do not substitute shell-authored canonical files. Checkpoint findings, pending candidates, and the threat model with `complete: false`. An accepted `complete: true` draft (or the backwards-compatible omitted flag) ends submission; a checkpoint does not claim completed review.

Completion validates existing artifacts; it does not perform missing phases or create an absent draft. Do not claim completion or finish an existing scan goal until finalization succeeds and the generated report exists. No new goal is required by this reference.

## Finding Semantics

Use `schemas/tools/scan-draft.schema.json` for new drafts and `finding-detail-fields.md` for rich fields. Supply:

- An evidence-supported lowercase vulnerability-family `ruleId`, `taxonomy.category`, known `taxonomy.cwe` values (or `[]`), and genuine `provenance.source`. Use `local_plugin` only for findings this plugin discovered; preserve worker/source provenance and candidate identity.
- Verified source locations, including the broken control or sink and materially affected entry points or concrete implementations. Preserve independently vulnerable instances. Group observations only when they share the broken control and remediation, not merely a CWE.
- A concise summary, root cause, validation basis, attacker dataflow and reachability, calibrated severity and confidence, counterevidence, and practical remediation. Classify by the primary broken control; describe secondary impacts without inventing additional vulnerabilities.
- Nonempty exact snippets in `codeEvidence` when supplied, with valid evidence references. Retain the analysis and code that establish the claim rather than repeating a location table in prose.
- `severity.changeConditions` as one nonempty string when present; combine multiple attack-path change conditions into that string. Keep `remediation` a string; `remediationTests` and `preventiveControls` are arrays of strings.

Use `scope` for reviewed context, artifacts, runtime/test status, validation mode, and limitations. Preserve the completed canonical `threatModel`, including source citations and uncertainty; do not reconstruct it from the final findings. A supplied or completed Markdown model is retained as `{ "format": "markdown", "content": "<exact model text>" }`. A historical context file can supply missing content but must not replace a newer canonical model.

## Review State And Pending Work

Keep unfinished requested work and essential in-scope proof gaps in `reviewState.deferred`. Retain optional follow-up in `reviewState.openQuestions`. These notes are checkpoint bookkeeping, not measured file coverage, and do not change the scan execution outcome.

Standard and diff drafts use `{ surfaces, explicitExclusions, deferred }`. Give surfaces meaningful labels and schema-defined dispositions, preserving saved surface IDs in updates. Retain reasons and evidence for rejected, not-applicable, and follow-up work. Open questions may be strings or `{ question, followUpPrompt? }` objects. An open question does not prevent the configured review from finishing.

Preserve each saved deferred `id` or `candidateId`, use each deferred ID only once, and reuse IDs from the zero-based input row in `assignedSurfaces` or `assignedDeferred`. Full review state is saved in the draft manifest and retained checkpoints, or in the bound worker’s `result.json`. Close a generic saved task in the final Standard or diff draft with `reviewState.resolvedDeferred: [{ id, reason }]`; keep unfinished tasks deferred and update linked surfaces by ID. Candidate-linked tasks close through findings or terminal dispositions. Deep parents cannot close worker tasks; original checkpoints remain unchanged.

The workbench assigns IDs to new surfaces and derives a finding's `identity` when omitted. Review notes do not measure file coverage; do not add reviewed-surface tables or file-coverage claims to the report. Omit host-owned target/scope metadata, `reviewState.inventoryStrategy`, `reviewState.receiptRefs`, and each active finding's `findingId`, `occurrenceId` and `fingerprints` from semantic drafts. SDK-authored canonical files follow `scan-contract.md` and the SDK's supplied metadata.

For compact diff candidates, map recorded outcomes in this order:

1. Validation `reportable` and attack-path `reportable`: finding, with its distinct instance and all relevant locations.
2. Either phase `deferred`: `needs_follow_up` surface and deferred work with the proof gap.
3. Validation `not_applicable`: `not_applicable` coverage.
4. Validation `suppressed` or attack-path `ignore`: `rejected` coverage.

A missing required phase record remains unresolved with its available evidence. Do not add another reconciliation pass or duplicate phase receipts. When an SDK/legacy caller supplies ledgers, preserve their candidate traceability and outcomes; do not drop an exact seed because a same-family neighbor survived.

## Optional Documents

Detailed vulnerability writeups and hardening proposals are derived, unsealed outputs, not prerequisites for completing a scan. When produced within a running scan, record `finding.writeup.reportPath` as `findings/<slug>/<slug>.md` and `scan.hardening.portfolioPath` as `hardening/hardening.md`. The renderer supplies their links and presentation. Do not add them to the canonical seal or infer that design guidance fixes a finding. Later requests use standalone collections under `artifact-storage.md` rather than editing sealed results.

## Errors And Recovery

An MCP `-32602` or `isError: true` input-validation rejection makes no draft write. Correct the rejected fields in the same draft, preserving valid evidence and pending work, then resubmit. Do not repeat an unchanged failing request or blindly retry an ambiguous transport/write failure.

For a required phase, artifact, or completion failure, preserve and report the actual diagnostic. Resolve a recoverable cause when the tool's state makes retry safe; do not claim a final report, a no-findings conclusion, or a successful structured result while completion remains unresolved. Preserve the durable scan for continuation rather than canceling or failing it merely because assembly is blocked. Do not resubmit an accepted final draft or repeat successful completion.

On explicit cancellation, stop additional model work. Use retained results and exports, distinguishing validated findings from pending candidates and recording incomplete scope. A stopped scan with no findings is not a clean-scan conclusion.

### Historical findings and coverage in workbench Standard and diff drafts

The plugins bundled in `npm-v0.1.32` through `npm-v0.6.0` preserve the saved `identity` of an unambiguously matched finding when a revision omits it. Supplying a different anchor can leave both findings active. These releases have no supported operation to supersede the old identity. In 0.1.32, updating a surface by its generated ID can also leave both dispositions active if the original checkpoint omitted the ID.

On builds containing `e6c7b28` (after `npm-v0.6.0`), first establish the corrected `identity` from independent evidence. Use this procedure only if no checkpoint has already saved the corrected identity alongside the original. If both identities are active, leave the scan unsealed and report the conflict. [Finding recovery change #1310](https://github.com/openai/codex-security/pull/1310)

Submit the revision with its corrected identity through `record_codex_security_scan_draft` with `complete: false`. Put each distinct prior version directly in the revision's `provenance.previousFindings` array. Copy the full saved finding, including its identity, evidence and provenance, omitting only its own `provenance.previousFindings`. The workbench restores nested history for each unambiguous match. Before submitting the final draft, verify in `findings.json` and `coverage.json` that only the corrected identity is active for this finding, its prior versions are in its history, and other findings and independently pending work are intact.

A finding or a `rejected` or `not_applicable` disposition for the same candidate can resolve a `needs_follow_up` surface. Since `npm-v0.2.0`, `coverage.resolvedDeferred` closes generic tasks by saved ID and reason. Omission alone does not retire a surface or explicit exclusion. There is no general operation to remove either entry by request or to migrate a copy of a 0.1.32 scan for these corrections. If the required correction is unsupported or still absent from the saved result, leave the scan unsealed, preserve its checkpoints and outstanding work, and report which entry still needs correction.

## Response

Link the generated `report.md` as the primary readable result. Mention material limitations and specific follow-up work; offer export, patching, or tracking only when relevant to the request. Do not initiate additional external actions or scans without authorization.

After completion, report the latest `usage.totalTokens`, `usage.inputTokens` (including cached input), and `usage.cachedInputTokens`. If `usage.completion.finalized` is `false`, leave the total to the host, which includes this final turn; do not quote preliminary counts as final or as a lower bound. Otherwise label partial coverage as "at least X tokens; some usage unavailable" and explain its warnings. If usage is unavailable, say so instead of reporting zero. Retain any separate cost estimate.

Include `byRole` when present and use `window` and `tokensUpdatedAt` to describe the measured period. For account allowance, quote the latest `accountRateLimits` observation and its `observedAt`; identify weekly limits by window duration. These account-wide readings may include other work, saved readings are historical, and absent readings or null windows mean allowance was not observed. Do not convert between tokens, estimated API cost, and subscription allowance or modify sealed artifacts to add this metadata.

For Codex app rendering, emit one `::code-comment` per surviving finding and none otherwise. Keep its title, explanation, and location consistent with the canonical finding. Map `critical`, `high`, `medium`, and `low` to priorities 0, 1, 2, and 3 respectively:

```text
::code-comment{title="[P1] Example title" body="One-paragraph explanation." file="/absolute/path/to/file" start=10 end=12 priority=1}
```

Use verified, tight 1-based lines and an absolute path. Optional `confidence` is numeric when available. Backticks can delimit identifiers inside attributes; do not put double quotes, including escaped quotes, inside quoted attribute values.
