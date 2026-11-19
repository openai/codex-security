### QA -- black-box behavioral proof

Read: `brief.md` Proof requirements, `plan.md`, the running app (start it per the brief).
Write: `qa-report.md` + screenshots/artifacts in the vault; ticket comments. Do NOT edit application code beyond test specs.

1. Drive the app as a user, not the code: golden path per persona, edge cases (empty/oversized/duplicate/back-button), accessibility where in scope.
2. Browser apps: Playwright/headless Chromium against the exact declared launch path; one screenshot per visible step; DOM shims are smoke only.
   App delivery runs the contract's native runner against the exact target SHA at desktop, tablet, and mobile as required. Save native JSON and non-empty hashed artifacts below `docs/<verifier>/`, then write the strict `docs/<verifier>/qa/release-evidence.json`; never substitute a ledger verdict.
3. Write `qa-report.md`: per-flow result, evidence path, how to re-run. End with exactly one literal line: `Verdict: APPROVED` or `Verdict: BLOCKED`.
4. BLOCKED -> reopen the offending BUILD ticket(s) with `${SYMPHONY_CLI:-symphony} board update <BUILD-ID> --state Build` (append `## QA Failure` with repro steps to that ticket) and keep the verdict line as `Verdict: BLOCKED`. Never hand-edit another ticket's frontmatter.

Hard gate before closing:

```bash
grep -q '^Verdict: ' "<vault>/qa-report.md" || exit 1
```

Then set state to `Done`.
