# Invoice Desk: scan, inspect, patch, and verify

Use the synthetic Invoice Desk app to follow one finding from a source scan to
an explicit patch and a separate verification. This guide supplies commands and
an illustrative finding; it is **not a recorded model run**. Finding counts,
severity, evidence, and coverage must come from your own saved results.

The app is deliberately insecure. Use only its synthetic data on loopback, and
keep the [QA guide](qa/README.md) outside the scan input. Ten seeded scenarios do
not guarantee ten findings. The behavior tests establish the sample's behavior,
not scanner recall.

## 1. Prepare a standalone copy

Install and authenticate the [Codex Security CLI](../../sdk/typescript/docs/cli.md#authentication).
The app itself needs Node.js 22.13 or later and has no dependencies. Follow the
CLI's own [runtime requirements](../../sdk/typescript/README.md#install).
Scanning, patching, and verification use model inference.

Run these Bash commands from the repository root:

```bash
invoice_source="$PWD"
invoice_run="$(mktemp -d "${TMPDIR:-/tmp}/invoice-desk-workflow.XXXXXX")"
cp -R "$invoice_source/examples/invoice-desk/app" "$invoice_run/app"
git -C "$invoice_source" rev-parse HEAD > "$invoice_run/source-revision.txt"
codex-security --version > "$invoice_run/cli-version.txt"
cd "$invoice_run/app"
git init -q
git add .
git -c user.name="Invoice Desk demo" -c user.email="demo@example.test" \
  commit -qm "Baseline synthetic Invoice Desk app"
git rev-parse HEAD > "$invoice_run/app-revision.txt"
```

The new Git repository has no remote. It provides a baseline for reviewing the
patch. Results will be siblings of `app/`, outside its worktree. The copied app
contains no sample guide, threat model, QA harness, answer key, or prior report.
Keep the scanner's working directory here and do not supply the original checkout
as additional context. You do not need to start the HTTP server for a source scan.

## 2. Run and retain the scan

```bash
codex-security scan . --mode standard --effort high --format json \
  --output-dir "$invoice_run/scan" > "$invoice_run/scan-result.json"
```

This uses your configured provider and model. To select a model explicitly, add
`--model MODEL` with a model available through that provider. Retain the effective
settings from the saved scan below, alongside the CLI version and source revision.
Use a new output directory for another run.

With these options, exit `0` means the scan completed, including when it reports
findings. Exit `2` means execution or required output failed; inspect diagnostics
and retained artifacts instead of treating it as a clean result. If you add
`--fail-on-severity`, exit `1` means findings met that threshold.

After completion, read `scan.id` from `$invoice_run/scan/scan-manifest.json`. Replace `SCAN_ID`
in the following commands with that actual value:

```bash
codex-security scans show SCAN_ID --json > "$invoice_run/saved-scan.json"
codex-security scans logs SCAN_ID
```

`scans show` records the saved model, reasoning effort, mode, and replay recipe.
The manifest identifies the target revision and scope; it does not define model
configuration fields. Always use the explicit scan ID when navigating results so
a later failed or active run is not confused with an earlier completed scan.

## 3. Read evidence and coverage together

Start with `$invoice_run/scan/report.md`, then inspect the structured artifacts.
Paths in this table are relative to `$invoice_run`:

| Artifact                  | What to inspect                                                                                            |
| ------------------------- | ---------------------------------------------------------------------------------------------------------- |
| `scan/scan-manifest.json` | `scan.id`, `scan.status`, target identity, revision, and requested scope.                                  |
| `scan/findings.json`      | The actual finding's `occurrenceId`, source evidence, root cause, attack path, confidence, and validation. |
| `scan/coverage.json`      | Assessed `surfaces`, their dispositions, `explicitExclusions`, `deferred` work, and any `openQuestions`.   |
| `saved-scan.json`         | Saved scan settings and recipe, for reproducing or comparing the run.                                      |

When present, follow `rootCause.evidenceRefs` into `codeEvidence`; otherwise,
inspect the finding's recorded source locations and evidence. Separate what the
source proves from what runtime validation actually exercised. Missing runtime validation is a proof gap, not evidence that
the issue is safe. An empty finding list also says nothing about excluded or
deferred surfaces.

### Illustrative example: a workspace boundary

Read this example **after independent discovery**. It describes the seeded
cross-workspace invoice read; it is not a claim that your scan found it.

| Part of the finding       | Source-supported interpretation                                                                                                       |
| ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| Attacker-controlled input | An authenticated member supplies an invoice ID to `GET /api/invoices/:id`.                                                            |
| Broken boundary           | The GET route calls `getInvoice(store, id)`, which looks up the invoice without checking the member's workspace.                      |
| Impact                    | A North Studio member can read a Cedar Workshop invoice by ID.                                                                        |
| Existing control          | `ownedInvoice(store, user, id)` checks workspace ownership for other invoice operations; the list endpoint also filters by workspace. |
| Verification target       | Cross-workspace reads must fail, while the member can still read an invoice in their own workspace.                                   |

Inspect the [HTTP route](app/server.mjs) and [invoice helpers](app/invoices.mjs).
The separate [QA harness](qa/app.test.mjs) reproduces this behavior as ID-002 and
checks legitimate controls. Its scenario tests intentionally assert that seeded
weaknesses remain present; they are not post-fix acceptance tests.

If your scan reports this root cause, use its actual `occurrenceId` from this
run's `findings.json`. Do not substitute the QA label `ID-002`, a title, or an ID
from an unrelated scan. If it does not report the issue, record a miss or
uncertainty when evaluating recall. A later patch from a supplied description
would test remediation, not retroactively count as scanner discovery.

## 4. Explicitly request one patch

Continue only after choosing a source-supported finding from the saved scan.
Set `invoice_occurrence` to its actual ID and preserve that finding before patching:

```bash
invoice_occurrence="occ_REPLACE_WITH_ACTUAL_ID"
node --input-type=module - "$invoice_run/scan/findings.json" \
  "$invoice_occurrence" "$invoice_run/finding.json" <<'JS'
import { readFileSync, writeFileSync } from "node:fs";
const [source, id, output] = process.argv.slice(2);
const finding = JSON.parse(readFileSync(source, "utf8")).findings.find(
  (item) => item.occurrenceId === id,
);
if (!finding) throw new Error("Select an occurrence from this scan.");
writeFileSync(output, JSON.stringify(finding, null, 2) + "\n");
JS
```

Now explicitly authorize changes to the standalone app associated with that finding:

```bash
codex-security patch "$invoice_occurrence" --json > "$invoice_run/patch-result.json"
git status --short
git diff
```

`patch` fixes and verifies the selected finding. Review the returned status and
verification evidence, the tracked diff, and any new files reported by `git status`.
For the example above, look for enforcement at the invoice-read boundary, a
regression check for the other workspace, and a legitimate same-workspace control.
A change in finding count or a modified file alone does not prove remediation.

The saved-finding result distinguishes `verified`, `no_change`, `blocked`, and
`failed`. Preserve a blocked or failed result with its missing prerequisite or
failed check; do not relabel it as fixed. Keep unrelated seeded scenarios out of
this patch. The original app in the source checkout remains the vulnerable sample.

## 5. Explicitly verify the original boundary

After reviewing the patch, request a separate read-only assessment from the
patched app directory. Use the preserved original finding file to assess the
same claim and evidence independently of its current status in scan history.
File input targets the current directory; keep it set to the patched app. The
verification result labels this single input `finding-1`; `finding.json` retains
its original occurrence ID.

```bash
codex-security verify-fix "$invoice_run/finding.json" --json \
  > "$invoice_run/verify-result.json"
```

For the illustrated finding, the evidence should establish all of the following
against the patched standalone app:

- A North Studio member's request for a Cedar Workshop invoice is rejected,
  following the application's existing not-found behavior.
- The same member can still read their own workspace's invoice.
- The route uses the intended ownership check, and a nearby alternative path
  does not preserve the reported bypass.
- Relevant regression checks ran, or the result states why they could not run.

`verify-fix` reports `fixed`, `still_vulnerable`, or `inconclusive`; it does not
apply another patch. Its exit codes are `0`, `1`, and `2`, respectively, with `2`
also covering failed checks. Preserve exact commands and evidence. Another scan
omitting the finding is not sufficient verification, and unavailable relevant
checks must remain visible in an inconclusive result.

Keep the source revision, CLI version, saved scan and settings, patch result,
final diff, and verification result together. Review them before sharing. To
measure discovery separately, compare the original scan with the
[QA scoring guide](qa/README.md#scanner-evaluation), counting distinct root causes,
misses, uncertain cases, additional findings, and duplicates.
