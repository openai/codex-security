# Browser-app QA — Playwright + screenshots + PDF gate

For any product where `.oneshot/vault/.is_browser_app` exists, the QA lane
runs a black-box, end-to-end Playwright sweep, captures a screenshot per
flow step, and emits an *officially signed* QA report PDF as the gate
artifact for the Deliver lane.

For an application release, the runner is selected by `release-contract.yaml`,
not assumed from `package.json`. Its exact command and every non-empty hashed
repo-relative source are part of the immutable contract. It must emit native structured results and
non-empty hashed artifacts at the required viewports, followed by strict
`docs/<verifier>/qa/release-evidence.json`. Specs containing `EDIT-ME` or
placeholder selectors/URLs are rejected before execution. A failed repair
never reuses this report: a fresh verifier proves the new exact target SHA.

> **Why a PDF gate?** Markdown can be hand-edited at the last second to
> claim approval. A PDF rendered fresh from the markdown + screenshots is a
> snapshot — its sha256 is logged in `verification.md`, so any later edit
> to the markdown invalidates the gate. The bytes either exist with the
> right hash or they don't.

## What the QA lane produces

```
.oneshot/vault/
├── qa-report.md                   # markdown source (human-readable, version-controlled)
└── artifacts/
    ├── qa-report.pdf              # GATE artifact — Deliver lane checks for this
    ├── screenshots/
    │   ├── signup-1-empty-form.png
    │   ├── signup-2-validation-errors.png
    │   ├── signup-3-success-redirect.png
    │   ├── login-1-form.png
    │   ├── login-2-dashboard.png
    │   └── ...
    └── test-results/
        ├── results.json           # Playwright JSON reporter
        └── trace.zip              # Playwright trace for failures
```

## The Playwright spec — what to cover

The QA lane reads `brief.md` "Proof requirements" and "Done criteria" and
turns each user-visible item into a Playwright test. Required coverage:

1. **Golden path** — happy flow end-to-end for every primary persona in `brief.md`'s Audience section.
2. **Critical edge cases** — at minimum: empty input, oversized input, duplicate submission, network failure mid-flow (use `route.abort()`), back-button mid-flow.
3. **Authentication boundary** — if auth is in scope: unauthed access to protected routes redirects to login; logout actually invalidates the session.
4. **Accessibility** — `axe-playwright` scan on every page in golden path; fail on `serious` or `critical` violations.
5. **Visual evidence** — every test step that changes the rendered DOM calls `page.screenshot({ fullPage: true })` into `artifacts/screenshots/`.

The stub at `templates/playwright-qa.spec.ts` shows all five categories
wired up — adapt URLs/selectors to the product but don't drop categories.
For an app release, adaptation belongs to the dedicated pre-Verify Build slice
that finalizes the native runner and `release-contract.yaml` hashes. QA executes
those committed bytes without editing them. A required runner change reopens
that Build slice and requires a fresh target-bound release verifier.

## Screenshot naming convention

`<flow>-<step-number>-<short-description>.png`

Examples: `signup-1-empty-form.png`, `checkout-3-stripe-modal.png`,
`a11y-2-dashboard.png`. The QA report's coverage table cites these paths
verbatim, so the convention matters — broken citations break the report.

## How the PDF is rendered (no extra deps)

`templates/qa-pdf.sh` uses Playwright itself (already installed because the
QA spec runs on it) to render the markdown report to PDF. The pipeline:

```
qa-report.md  ─marked─▶  qa-report.html  ─Playwright page.pdf()─▶  qa-report.pdf
                ▲
                screenshots embedded as <img src="…"> with absolute paths
```

This avoids the typical PDF stack (`pandoc + wkhtmltopdf + LaTeX`) which
is heavy and version-fragile. Playwright is already required for the QA
spec, so the cost is zero new dependencies.

The script writes PDF metadata (Title, Subject, Producer, CreationDate),
embeds the screenshots inline, and uses A4 + 18mm margins by default.

## The QA report format

```markdown
# QA Report — <product name from brief.md>

| Field        | Value                                  |
|--------------|----------------------------------------|
| Date         | 2026-05-09T15:42Z                      |
| Build SHA    | abc1234                                |
| Branch       | main                                   |
| QA Agent     | claude-opus-4-7 via OneShot route      |
| Spec file    | tests/e2e/qa.spec.ts                   |
| Total tests  | 14                                     |
| Passed       | 14                                     |
| Failed       | 0                                      |

## 1. Golden paths

### 1.1 Signup → Dashboard (anonymous user)
| Step | Action | Expected | Actual | Screenshot |
|------|--------|----------|--------|------------|
| 1 | Visit /signup | Empty form rendered | ✓ rendered | `signup-1-empty.png` |
| 2 | Fill valid creds, submit | Redirect to /dashboard | ✓ 302 → /dashboard | `signup-2-success.png` |
| 3 | Verify dashboard greeting | "Hi, <user>!" visible | ✓ visible | `signup-3-dashboard.png` |

(repeat per golden path)

## 2. Edge cases

| Case | Expected | Actual | Screenshot |
|------|----------|--------|------------|
| Empty signup form | Validation errors shown | ✓ | `signup-edge-empty.png` |
| Duplicate email | "Already registered" error | ✓ | `signup-edge-dup.png` |
| Network drop mid-submit | Retry button shown | ✓ | `signup-edge-netfail.png` |

## 3. Authentication boundary
...

## 4. Accessibility (axe-core)
| Page         | Violations (serious+) | Notes |
|--------------|-----------------------|-------|
| /            | 0                     | clean |
| /signup      | 0                     | clean |
| /dashboard   | 1                     | one moderate (missing skip-link) — not blocking |

## 5. Performance smoke (optional but recommended)
| Page | LCP | CLS | TBT |
|------|-----|-----|-----|
| /    | 1.2s | 0.04 | 80ms |

## Findings
- (none / list)

## Sign-off
QA agent: claude-opus-4-7
Verified against: <git sha>
PDF rendered: 2026-05-09T15:43Z
sha256: <hash will be computed by qa-pdf.sh and written to verification.md>

Verdict: APPROVED FOR DELIVERY
```

The sign-off block's last line is the literal trigger the Deliver gate
greps for: `^Verdict: APPROVED FOR DELIVERY`.

## How the Deliver lane uses the PDF

```bash
# Inside Deliver lane prompt's gate
if [ -f .oneshot/vault/.is_browser_app ]; then
  test -s .oneshot/vault/artifacts/qa-report.pdf || { echo "QA PDF missing"; exit 1; }
  expected=$(grep -o '[0-9a-f]\{64\}' .oneshot/vault/verification.md | tail -1)
  actual=$(shasum -a 256 .oneshot/vault/artifacts/qa-report.pdf | awk '{print $1}')
  [ "$expected" = "$actual" ] || { echo "QA PDF hash mismatch — possible tampering"; exit 1; }
  grep -q '^Verdict: APPROVED FOR DELIVERY' .oneshot/vault/qa-report.md \
    || { echo "QA verdict not APPROVED"; exit 1; }
fi
```

If any check fails, the Deliver ticket goes to `Blocked` with a precise
`## Blocker` section. Symphony retries on the next poll until either the
gate passes or `agent.max_turns` exhausts.

## When the user's `qa-engineer` skill should run instead

The `qa-engineer` skill exists for *deployed* (dev/stg/prod) environments
on the user's company stack. Use it instead of the localhost Playwright
flow when:

- `brief.md`'s "How to run" points at an `https://*.aidt.*` (or other
  company-deployed) URL, not `localhost:*`.
- The product is being shipped *to* a deployed environment, not just built.

In that case the QA lane prompt should:
1. Invoke the `qa-engineer` skill against the deployed URL.
2. Copy the skill's outputs into `.oneshot/vault/artifacts/`.
3. Render the same `qa-report.md` + `qa-report.pdf` from those outputs so
   the Deliver gate logic remains unchanged.

This keeps the gate uniform regardless of which evidence-collector ran.

## Anti-patterns

| Symptom                                        | Cause                                         | Fix                                              |
|------------------------------------------------|-----------------------------------------------|--------------------------------------------------|
| PDF exists but tests didn't actually run       | QA agent generated the markdown without running spec | qa-pdf.sh requires `artifacts/test-results/results.json`; refuse to render without it |
| Screenshots are empty white                    | App not yet ready when screenshot taken       | Always `await expect(locator).toBeVisible()` BEFORE `page.screenshot()` |
| Different screenshot dimensions per run        | Default viewport drifted                      | `playwright.config.ts`: `use: { viewport: { width: 1440, height: 900 } }` |
| QA approves but feature is broken              | Spec covers happy path only                   | Mandatory edge-case section; reviewer rejects PR if missing |
| Deliver gate keeps failing on hash             | qa-report.md was edited after PDF render      | Re-render PDF; never edit md after sign-off      |
