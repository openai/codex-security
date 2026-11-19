### VERIFY -- adversary to claims.md

Read: `plan.md`, `claims.md`, `qa-report.md` if present. You re-prove; you do not trust.
Write: append to the vault `verification.md`; ticket comments. Do NOT edit application code.

1. Re-run every claim's run-to-prove command from a clean checkout state.
2. Run the FULL test suite, lint, and typecheck -- not just slice tests.
3. Exercise integration points across slices (start the app, probe the API).
4. Append to `verification.md`: per-claim result, full-suite result, integration probes, and a final line `verdict: GREEN` or `verdict: RED`.
   For an `app-release` verifier, first rebase this evidence-only verifier branch onto the exact current target tip and confirm the target SHA is an ancestor; if that synchronization cannot be proved, stay in `Verify` with an environment error. Then re-run the exact contract runner on that SHA and run the `symphony release check` gate via `${SYMPHONY_CLI:-symphony} release check "$SYMPHONY_WORKFLOW_DIR/WORKFLOW.md" --ticket {{ issue.identifier }} --workspace "$PWD"`. The host snapshots this evidence branch but never merges it into the target. Historical ledger or Markdown GREEN is never approval for the current target. Evidence, schema, or environment errors stay in `Verify` and require corrected evidence only. A structurally valid repairable RED must request the normal forward historical transition to `Done`; the file-tracker host, not this worker, groups repairs, creates the fresh verifier, and relinks the finalizer.
5. For non-app work, RED -> reopen each failed slice's BUILD ticket with `${SYMPHONY_CLI:-symphony} board update <BUILD-ID> --state Build` and append `## Verify Failure` (discrepancy + repro command) to it, spawn a fresh `VERIFY-<n+1>` ticket blocked by those builds (`${SYMPHONY_CLI:-symphony} board new VERIFY-<n+1> "..." --state Verify --blocked-by <BUILD-ID>`), then close this ticket. Never hand-edit ticket frontmatter. A RED verdict must also block delivery: append `## Merge Hold` to the request ticket naming the reopened builds, and do NOT let `DOCUMENT-*` start (it has its own GREEN gate). You never merge or revert anything yourself — the orchestrator owns merges, and a reopened Build re-merges when it reaches `Done` again.

Hard gate before closing for non-app work:

```bash
grep -q '^verdict: GREEN' "<vault>/verification.md" || exit 1
```

(RED path: the gate is the recorded `verdict: RED` plus reopened builds + the fresh Verify ticket.) Then set state to `Done`.

For `app-release`, the CLI result replaces the ledger grep and the app-release transition rule above replaces the non-app RED workflow.
