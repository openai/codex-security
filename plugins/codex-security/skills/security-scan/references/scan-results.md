# Save results to the registered scan

When the SDK supplies only a registered environment, use `CODEX_SECURITY_REPOSITORY` as the target. If `CODEX_SECURITY_TARGET_PATHS_FILE` is set, use the supplied source inventory or [resolve it](scoped-paths.md) before review. Emit the SDK's standalone `CODEX_SECURITY_SCAN_PROGRESS {"phase":"discovery","filesCompleted":3,"filesTotal":8}` at discovery start, meaningful review batches, and later phase transitions using the actual phase, distinct completed paths and scoped total or host estimate.

For a scan with bound progress and context tools, persist user-requested context edits with the current handoff token. Use each real forward phase transition’s returned `scan.userContext` for that phase and its workers. Without a bound context tool, retain the original context.

At the first usable threat model, call `record_codex_security_scan_draft` with the scan ID, handoff token when required, `complete: false`, the model, and empty findings if none are validated yet. The workbench writes the canonical artifacts and derives target metadata and finding identities. If the SDK supplied the scan and no draft tool is bound, follow the [SDK file handoff](sdk-files.md) through completion instead. Other hosts require the draft tool.

Keep the full worker returns in the Standard queue. Save decisions in small draft updates using the queue’s candidate IDs and the [candidate validation instructions](../../../references/standard-search-rules.md). Reuse saved surface IDs. Use [artifact storage](../../../references/artifact-storage.md) for supplemental evidence. A caller-supplied custom validation handoff determines which candidates are provisional.

When assigned work finishes, submit one accepted `complete: true` draft with scope, threat model, findings, and `reviewState`. Close finished generic tasks in `reviewState.resolvedDeferred` with their saved ID and a reason. Keep unresolved work. If a draft is explicitly rejected before writing, correct the identified fields and retry at most twice without dropping valid evidence.

Verify `scan-manifest.json` and `findings.json` exist. For an SDK-owned scan, return now. The SDK seals the results and generates the reports. For another managed scan, follow any [desktop handoff](desktop-scan.md) if on desktop, then call `complete_codex_security_scan` once with the same ID and token. On success, link the generated `report.md` and canonical artifacts. Retrieve full findings only if requested. Report only complete measured usage. Leave pending usage to the host and identify other incomplete counts as unavailable.

If completion fails, surface the error and preserve the durable scan. Cancel only at the user's request. Fail the scan only for a confirmed unrecoverable blocker after recovery is exhausted. Leave unfinished work resumable.
