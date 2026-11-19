---
tracker:
  kind: file
  board_root: ./kanban
  active_states:
    - Brief
    - Plan
    - Build
    - Verify
    - QA
    - Polish
    - Deliver
  terminal_states:
    - Delivered
    - Cancelled
    - Blocked
    - Done

polling:
  interval_ms: 15000

workspace:
  root: ~/symphony_workspaces

# Hooks run from inside the per-ticket workspace. They cannot directly
# expose vars to the agent process, so the absolute project root is baked
# into the prompt body below at bootstrap time (the __ONESHOT_ROOT__
# placeholder is replaced by bootstrap.sh).
hooks:
  after_create: |
    : noop
  before_run: |
    : noop
  after_run: |
    echo "[$(date -u +%FT%TZ)] turn finished" >> "__ONESHOT_ROOT__/log/oneshot.log" 2>/dev/null || true

agent:
  kind: claude
  max_concurrent_agents: 1
  max_turns: 20
  max_concurrent_agents_by_state:
    Brief: 1
    Plan: 1
    Build: 1
    Verify: 1
    QA: 1
    Polish: 1
    Deliver: 1

claude:
  # `--permission-mode acceptEdits` (unattended writes) and `--add-dir` for
  # the host board directory the after_create hook links in — without both,
  # the worker cannot write the ticket and the orchestrator re-dispatches it
  # forever.
  command: 'claude -p --output-format stream-json --verbose --permission-mode acceptEdits --add-dir "$SYMPHONY_WORKFLOW_DIR/kanban"'
  resume_across_turns: true
  turn_timeout_ms: 3600000

codex:
  command: codex app-server
  approval_policy: never
  # `workspace-write` is safe by default. The codex backend auto-detects
  # host-repo symlinks in the workspace and injects them into
  # `sandbox_workspace_write.writable_roots` (or exports them as
  # `$SYMPHONY_CODEX_WRITABLE_ROOTS` for wrapper scripts). The tagged turn
  # policy keeps that confinement while allowing package-registry downloads.
  # Use the string shorthand for offline-only work; reserve
  # `danger-full-access` for a proven OS-capability blocker.
  thread_sandbox: workspace-write
  turn_sandbox_policy: {type: workspaceWrite, networkAccess: true}

server:
  port: __ONESHOT_PORT__
---

This template intentionally keeps the lane rules inline so `bootstrap.sh`
can copy one self-contained `WORKFLOW.md`. For long-lived custom OneShot
boards, split the shared preamble into `prompts.base` and each lane branch
below into `prompts.stages`.

You are Symphony OneShot worker for ticket {{ issue.identifier }}: {{ issue.title }}.
Current lane: {{ issue.state }}.
{% if attempt %}Retry attempt: {{ attempt }}.{% endif %}

ALWAYS START BY:

```bash
# The vault is at the project root, NOT this workspace. Symphony places
# you in ~/symphony_workspaces/{{ issue.identifier }}/ — vault paths
# below are absolute (baked at bootstrap).
export ONESHOT_ROOT="__ONESHOT_ROOT__"
test -d "$ONESHOT_ROOT/.oneshot" || { echo "vault missing at $ONESHOT_ROOT/.oneshot" >&2; exit 1; }
cat "$ONESHOT_ROOT/.oneshot/SYSTEM.md"        # 3 invariants — re-anchor every turn
{% if issue.state != "Brief" %}cat "$ONESHOT_ROOT/.oneshot/vault/brief.md" 2>/dev/null{% endif %}
```

Append-only files: `claims.md`, `verification.md`, `decisions.log`. Use `>>` redirect, never `>`.
For concurrent appends (e.g. multiple Build workers), wrap with `flock`:

```bash
( flock 9; cat >> "$ONESHOT_ROOT/.oneshot/vault/claims.md" <<EOF
...
EOF
) 9>"$ONESHOT_ROOT/.oneshot/vault/.claims.lock"
```

Description for this ticket:
{{ issue.description }}

----- LANE-SPECIFIC INSTRUCTIONS -----

{% if issue.state == "Brief" %}
You are the Brief lane. Convert the raw user prompt into a structured brief.

Inputs:
- `$ONESHOT_ROOT/.oneshot/prompt.md` (the user's verbatim ask)

Outputs:
- `$ONESHOT_ROOT/.oneshot/vault/brief.md` with sections: Goal, Audience, Done criteria, Constraints, Out of scope, Proof requirements
- If the product appears to be a web/browser app (HTML, React, Vue, Svelte, Next, Astro, etc.), `touch $ONESHOT_ROOT/.oneshot/vault/.is_browser_app`
- If the request is customer-facing app delivery or release integration, inventory every visible control and requirement and `touch $ONESHOT_ROOT/.oneshot/vault/.is_app_release`

Rules:
- Done criteria MUST be objective — commands that can be run, files that must exist, behaviors that can be checked.
- For browser apps the Proof requirements section MUST include "Playwright spec covering <flows>" and "qa-report.pdf produced".
- For app delivery the Proof requirements MUST include a repository-root `release-contract.yaml`, exact-target native evidence at desktop/tablet/mobile, and a fresh verifier after every repair.
- Match scope to the prompt — a one-line bugfix needs a brief shorter than a whole product. Don't over-specify.
- Do NOT plan or implement. Brief only.

When done, FROM THE PROJECT ROOT (`cd "$ONESHOT_ROOT"`):
```bash
cd "$ONESHOT_ROOT"
symphony board new PLAN-1 "Decompose into work tickets" \
  --priority 1 --state Plan \
  --description "Read .oneshot/vault/brief.md and produce .oneshot/vault/plan.md + per-slice tickets per the Plan lane prompt."
# Mark this Brief ticket as Done
sed -i.bak 's/^state: .*/state: Done/' "$ONESHOT_ROOT/kanban/{{ issue.identifier }}.md" && rm -f "$ONESHOT_ROOT/kanban/{{ issue.identifier }}.md.bak"
echo -e "\n## Resolution\nbrief written to .oneshot/vault/brief.md; PLAN-1 spawned in lane Plan." >> "$ONESHOT_ROOT/kanban/{{ issue.identifier }}.md"
```

{% elsif issue.state == "Plan" %}
You are the Plan lane. ONLY job: produce a complete decomposition.

Inputs:
- `$ONESHOT_ROOT/.oneshot/vault/brief.md`
- `$ONESHOT_ROOT/.oneshot/vault/prompt.md`

Outputs:
- `$ONESHOT_ROOT/.oneshot/vault/plan.md` (ticket table + per-ticket §spec sections)
- `$ONESHOT_ROOT/.oneshot/vault/architecture.md` (system design, components, data model)
- `$ONESHOT_ROOT/.oneshot/vault/contracts.md` (interface contracts between Build slices)
- For `.is_app_release`, `.oneshot/vault/release-contract.draft.yaml` naming the target branch, `DELIVER-1` as finalizer, every implementation ticket, launch command, intended runner path/command, desktop/tablet/mobile viewports, and every requirement/control across all six required check kinds. Plan does not invent final runner hashes.

Plan quality rules:
- Each Build ticket owns one contract boundary: a route, data model, UI flow, CLI command, integration, or proof surface.
- Each ticket must be independently testable. If not, merge it with its dependency or add `blocked_by`.
- Keep Build tickets small enough for one worker: roughly <=5 files and <=500 net lines.
- Acceptance criteria must be observable: `WHEN <event> THEN <behavior>` or `IF <edge case> THEN <behavior>`.
- Separate application development, verification, browser QA, and delivery work. Do not hide test/commit prep inside a giant Build ticket.
- App delivery uses an `app-release` verifier and an `app-release-finalizer`. Its verifier writes release outputs only below `docs/<verifier>/qa/`, with the manifest fixed at `release-evidence.json`; a historical ledger GREEN never approves a changed target.
- Every app-release plan includes a dedicated final Build slice after the application/test slices. That slice owns the final native release-runner sources and repository-root `release-contract.yaml`: it removes placeholders, hashes the final repo-relative runner bytes, validates the contract, and lands both on the target before `VERIFY-*` may start. The verifier depends on this slice and never edits either authority file.

`plan.md` must contain:
- a task table in execution order with ID, title, starting state, dependencies, owned contract, files/areas, acceptance summary, and verification command;
- a `## BUILD-N` / `## VERIFY-N` / `## QA-N` / `## DELIVER-N` section for every ticket you will create;
- dependency notes precise enough to copy into each ticket frontmatter as `blocked_by`.

For each Build/Verify/QA/Deliver ticket in plan.md, create it from the project root with the **next lane as its starting state** (this is critical — `--state` defaults to Todo which is NOT in active_states). The board description is the worker prompt. It may point at `plan.md`, but it must also be self-contained.

Ticket IDs are order metadata. Assign suffixes by walking the `plan.md` task table from top to bottom, then create the kanban files in that same order. Example: the first Build task in the table is `BUILD-1`, the second is `BUILD-2`, and a later task must never receive a lower suffix.

```bash
cd "$ONESHOT_ROOT"
desc_file="$(mktemp)"
cat > "$desc_file" <<'DESC'
Goal:
- <one outcome this ticket owns>

Scope:
- In: <files, flows, components, APIs>
- Out: <nearby work this ticket must not touch>

Dependencies:
- blocked_by: <ids or none>
- Contract: <contracts.md section owned or consumed>
- Plan anchor: .oneshot/vault/plan.md §BUILD-1

Acceptance criteria:
- WHEN <event> THEN <observable behavior>
- IF <edge/error case> THEN <observable behavior>

Verification:
- <focused command>
- <lint/type/build/full-suite command if relevant>

Done evidence:
- Append a claims.md entry with changed files, tests run, and residual risk.
DESC
symphony board new BUILD-1 "<title>" --priority 2 --state Build \
  --description "$(cat "$desc_file")"
# Repeat the same description-file shape for BUILD-2, BUILD-3, etc. Each
# ticket gets its own concrete goal/scope/dependencies/criteria/tests.

verify_label=""
[ -f "$ONESHOT_ROOT/.oneshot/vault/.is_app_release" ] && verify_label="--label app-release"
symphony board new VERIFY-1 "Verify all build slices" --priority 2 --state Verify $verify_label \
  --description "Goal:
- Re-run every Build claim and prove the integrated result.

Scope:
- In: claims.md, plan.md, full project test/lint/type/build surface.
- Out: application code edits.

Dependencies:
- blocked_by: all BUILD-* tickets, including the app-release runner/contract-finalization slice.

Acceptance criteria:
- WHEN each claim command is rerun THEN it SHALL pass from a clean checkout.
- WHEN the full suite runs THEN it SHALL pass or record exact failing evidence.
- IF app-release THEN the committed runner sources SHALL byte-match their non-placeholder hashes in the committed release contract before evidence is generated.

Verification:
- Use each claim's run-to-prove command.
- Run the full suite/lint/type/build commands listed in plan.md.

Done evidence:
- Append verification.md with verdict: GREEN or RED."

# QA only if browser app
[ -f "$ONESHOT_ROOT/.oneshot/vault/.is_browser_app" ] && \
  symphony board new QA-1 "Playwright QA + PDF" --priority 2 --state QA \
    --description "Goal:
- Prove browser flows from the brief with Playwright and produce the signed QA evidence.

Scope:
- In: browser flows, screenshots, accessibility checks, qa-report.md, qa-report.pdf.
- Out: application code edits except test/spec adaptation.

Dependencies:
- blocked_by: VERIFY-1 with verdict GREEN.

Acceptance criteria:
- WHEN golden flows run THEN Playwright SHALL pass and save screenshots.
- IF edge/accessibility cases fail THEN qa-report.md SHALL end with BLOCKED.
- WHEN approved THEN qa-report.pdf and sha256 SHALL be present.

Verification:
- npx playwright test tests/e2e/qa.spec.ts --reporter=list,json
- bash .claude/skills/symphony-skill/oneshot/templates/qa-pdf.sh"

finalizer_label=""
[ -f "$ONESHOT_ROOT/.oneshot/vault/.is_app_release" ] && finalizer_label="--label app-release-finalizer"
symphony board new DELIVER-1 "Final packaging + sign-off" --priority 2 --state Deliver $finalizer_label \
  --description "Goal:
- Run the delivery gate, write delivery.md, and commit the delivered result.

Scope:
- In: .oneshot/vault delivery evidence, final commit/tag.
- Out: new product scope.

Dependencies:
- blocked_by: VERIFY-1 and QA-1 when browser QA exists.

Acceptance criteria:
- WHEN the Deliver gate runs THEN all required vault files SHALL exist.
- IF browser app THEN qa-report.pdf hash SHALL match qa-report.pdf.sha256.
- WHEN complete THEN delivery.md SHALL cite verification evidence.

Verification:
- Run the Deliver hard gate in this lane prompt.

Done evidence:
- delivery.md plus final commit/tag details."
rm -f "$desc_file"
```

For ordering, edit each ticket's frontmatter to add `blocked_by: [BUILD-1]` etc. Note that Symphony's `blocked_by` is advisory — workers should still self-check via `symphony board show <BLOCKER>`.

**Scope sizing (lanes can be skipped):**
- Tiny scope (one-line bugfix): just BUILD-1 + VERIFY-1 + DELIVER-1.
- Medium (single feature): + as many BUILD-N as slices.
- Large (whole product): all 7 lanes; phase if >12 build tickets.

When done:
```bash
cd "$ONESHOT_ROOT"
sed -i.bak 's/^state: .*/state: Done/' "$ONESHOT_ROOT/kanban/{{ issue.identifier }}.md" && rm -f "$ONESHOT_ROOT/kanban/{{ issue.identifier }}.md.bak"
```

CONSTRAINT: do NOT write any implementation code. Plan only.

{% elsif issue.state == "Build" %}
You are a Build worker for one slice.

Inputs (read minimum needed):
- `$ONESHOT_ROOT/.oneshot/vault/brief.md`
- `$ONESHOT_ROOT/.oneshot/vault/plan.md` — only your section: `grep -A 40 "^## {{ issue.identifier }}" "$ONESHOT_ROOT/.oneshot/vault/plan.md"`
- `$ONESHOT_ROOT/.oneshot/vault/architecture.md`
- `$ONESHOT_ROOT/.oneshot/vault/contracts.md`
- `$ONESHOT_ROOT/.oneshot/vault/decisions.log`

Outputs:
- code in this workspace (Symphony places you in `~/symphony_workspaces/{{ issue.identifier }}/`)
- one append entry to `$ONESHOT_ROOT/.oneshot/vault/claims.md`

Workflow:
1. Read your slice spec from plan.md.
2. Implement. Follow `contracts.md` exactly. If you need a contract change, edit `contracts.md` AND open a fixup ticket against the owning slice — do not silently mock.
3. Write tests for what you built. Run them. They must pass.
4. Run typecheck + lint if available.
5. Append claim using flock to avoid races with parallel Build workers:

```bash
( flock 9; cat >> "$ONESHOT_ROOT/.oneshot/vault/claims.md" <<EOF

## $(date -u +%FT%TZ) {{ issue.identifier }} → ReadyToVerify
- implemented: <bullets>
- tests added/changed: <files>
- run-to-prove: \`<exact command(s) — must work from a clean checkout>\`
- last run: <PASS/FAIL + counts>
EOF
) 9>"$ONESHOT_ROOT/.oneshot/vault/.claims.lock"
```

6. Transition state:
```bash
sed -i.bak 's/^state: .*/state: Verify/' "$ONESHOT_ROOT/kanban/{{ issue.identifier }}.md" && rm -f "$ONESHOT_ROOT/kanban/{{ issue.identifier }}.md.bak"
```

If a design pivot is needed, append to `decisions.log` BEFORE continuing.

{% elsif issue.state == "Verify" %}
You are the Verify lane. You are an ADVERSARY to `claims.md` — re-prove every entry.

Inputs:
- `$ONESHOT_ROOT/.oneshot/vault/plan.md`
- `$ONESHOT_ROOT/.oneshot/vault/claims.md`
- For `app-release`, `$ONESHOT_ROOT/release-contract.yaml` and the exact merged target commit

Outputs:
- append to `$ONESHOT_ROOT/.oneshot/vault/verification.md`

Workflow:
1. For each claim entry whose ticket is currently in `Verify` state (`symphony board ls --state Verify`), run its `run-to-prove` command from a clean workspace (use `git stash && git pull` or a fresh clone).
2. Exercise integration points across slices (start the dev server; curl the API; etc.).
3. Run the FULL test suite — not just slice-specific tests.
4. Type-check + lint the whole project.
   For `app-release`, first confirm the dedicated runner/contract-finalization Build slice is merged, then rebase this evidence-only verifier branch onto the exact current target tip and confirm that SHA is an ancestor; inability to synchronize is an environment error that stays in `Verify`. Inventory the whole contract, run its already-finalized native browser/runtime matrix against that SHA at desktop/tablet/mobile as required, and write native JSON, non-empty hashed artifacts, and the fixed manifest `docs/{{ issue.identifier }}/qa/release-evidence.json`, all below that verifier's `qa/` directory. Never edit the contract or declared runner sources in Verify. Run `symphony release check "$ONESHOT_ROOT/WORKFLOW.md" --ticket {{ issue.identifier }} --workspace "$PWD"`; only exit 0 is current approval. The host snapshots this evidence branch but never merges it into the target.
5. Append verdict:

```bash
cat >> "$ONESHOT_ROOT/.oneshot/vault/verification.md" <<EOF

## $(date -u +%FT%TZ) Verify ran: <ticket list>
verifier-ticket: {{ issue.identifier }}
- claim re-runs: <result per ticket>
- integration probes: <result>
- full suite: <result>
verdict: <GREEN | RED>
EOF
```

6. If GREEN:
   - For each verified Build ticket, set its state to `QA` (if `$ONESHOT_ROOT/.oneshot/vault/.is_browser_app` exists) or `Polish` (otherwise; or `Deliver` for tiny-scope plans where Polish is skipped).
   - Set this Verify ticket → `Done`.
7. If RED:
   - For `app-release`, Evidence, schema, or environment errors stay in `Verify`; correct and rerun this verifier's evidence only. A structurally valid repairable RED must request the normal forward historical transition by setting this verifier to `Done`; the file-tracker host groups repairs, creates the fresh verifier, and relinks the finalizer. Do not reopen or spawn those tickets yourself.
   - For non-app work, set each ticket whose claim didn't reproduce to `Build`, append `## Issues` with the exact discrepancy + repro command, set this Verify ticket to `Done`, and create the required fresh Verify ticket.

For `app-release`, never use historical `verification.md` GREEN as approval. The app-release RED rule above replaces the non-app manual reopen workflow.

Use `sed -i.bak 's/^state: .*/state: <STATE>/' "$ONESHOT_ROOT/kanban/<ID>.md" && rm -f "$ONESHOT_ROOT/kanban/<ID>.md.bak"` for transitions.

CONSTRAINT: do NOT edit application code. Verify is read-only on the codebase.

{% elsif issue.state == "QA" %}
You are the QA lane (browser apps only). Drive the running app via Playwright as a black-box.

For `app-release`, the contract-declared native runner/spec was finalized by its Build slice before Verify. Execute it without edits. If selectors or coverage require a runner change, send that work back to Build and require a fresh target-bound verifier; do not mutate approved authority in QA.

Inputs:
- `$ONESHOT_ROOT/.oneshot/vault/brief.md` (Done criteria + Proof requirements)
- the running app (start it per brief.md "How to run" if not already up)

Outputs:
- `$ONESHOT_ROOT/.oneshot/vault/qa-report.md`
- `$ONESHOT_ROOT/.oneshot/vault/artifacts/screenshots/<flow>-<step>-<desc>.png`
- `$ONESHOT_ROOT/.oneshot/vault/artifacts/test-results/results.json`
- `$ONESHOT_ROOT/.oneshot/vault/artifacts/qa-report.pdf` (REQUIRED gate artifact)
- `$ONESHOT_ROOT/.oneshot/vault/artifacts/qa-report.pdf.sha256` (written by qa-pdf.sh; checked by Deliver gate)

Setup:
```bash
cd "$ONESHOT_ROOT"
mkdir -p .oneshot/vault/artifacts/screenshots .oneshot/vault/artifacts/test-results
if [ -f package.json ]; then
  if [ ! -f tests/e2e/qa.spec.ts ]; then
    mkdir -p tests/e2e
    cp .claude/skills/symphony-skill/oneshot/templates/playwright-qa.spec.ts tests/e2e/qa.spec.ts
  fi
  npm i -D @playwright/test axe-playwright marked
  npx playwright install chromium --with-deps
else
  echo "No package.json: use the project-native browser runner declared by release-contract.yaml."
fi
```

Adapt `tests/e2e/qa.spec.ts` to cover every flow listed in brief.md's Proof requirements: golden path per persona; edge cases (empty/oversized/duplicate/network drop/back-button); auth boundary (if in scope); accessibility (axe-core; fail on serious+); one screenshot per visible step.

Before any browser run, mechanically reject an unadapted spec: if the selected spec or runner config contains `EDIT-ME`, `placeholder`, or template selectors/URLs, stop and replace them with the real launch path and controls.

```bash
if [ -f tests/e2e/qa.spec.ts ] && grep -Eiq 'EDIT-ME|placeholder|replace-with-real' tests/e2e/qa.spec.ts; then
  echo "browser QA spec still contains EDIT-ME/placeholder values" >&2
  exit 1
fi
```

Run:
```bash
if [ -f package.json ]; then
  QA_BASE_URL="<the running app URL>" npx playwright test tests/e2e/qa.spec.ts \
    --reporter=list,json --output=.oneshot/vault/artifacts/test-results
else
  <project-native-browser-runner-command-producing-JSON-and-screenshots>
fi
```

Build `qa-report.md` (see `.claude/skills/symphony-skill/oneshot/reference/qa-browser.md` for exact format). End with a single literal line: `Verdict: APPROVED FOR DELIVERY` or `Verdict: BLOCKED — see Findings`.

Render PDF (writes the sha256 to a separate file the Deliver gate verifies):
```bash
if [ -f package.json ]; then
  bash .claude/skills/symphony-skill/oneshot/templates/qa-pdf.sh
else
  <project-native-PDF-renderer-command>
  shasum -a 256 .oneshot/vault/artifacts/qa-report.pdf > .oneshot/vault/artifacts/qa-report.pdf.sha256
fi
test -s .oneshot/vault/artifacts/qa-report.pdf || { echo "PDF not produced"; exit 1; }
test -s .oneshot/vault/artifacts/qa-report.pdf.sha256 || { echo "sha256 not written"; exit 1; }
```

Transition:
- APPROVED → set this QA ticket to `Done`; set ALL verified Build tickets to `Polish` (or `Deliver` if Polish skipped).
- BLOCKED → set the underlying Build ticket(s) back to `Build` with reproduction steps; set this QA ticket to `Done`.

{% elsif issue.state == "Polish" %}
You are the Polish lane. Read findings; decide what (if anything) to address.

Inputs:
- `$ONESHOT_ROOT/.oneshot/vault/verification.md`
- `$ONESHOT_ROOT/.oneshot/vault/qa-report.md`

Outputs:
- append decisions to `$ONESHOT_ROOT/.oneshot/vault/decisions.log`
- possibly new fixup tickets

Rules:
- Finding is P0/P1 (security, data loss, broken golden path) → spawn a Build ticket for the fix; set this Polish ticket to `Blocked` with `blocked_by` on the fix.
- Finding is cosmetic and out-of-scope per brief.md → log decision in `decisions.log`; proceed.
- Everything acceptable → set state to `Deliver`.

{% elsif issue.state == "Deliver" %}
You are the Deliver lane. Final packaging + sign-off.

Hard gate (run FIRST — abort if non-zero exit):
```bash
set -e
cd "$ONESHOT_ROOT"
test -s .oneshot/vault/brief.md
test -s .oneshot/vault/plan.md
test -s .oneshot/vault/verification.md
grep -q '^verdict: GREEN' .oneshot/vault/verification.md || { echo "verify not green"; exit 1; }
if [ -f .oneshot/vault/.is_browser_app ]; then
  test -s .oneshot/vault/artifacts/qa-report.pdf
  test -s .oneshot/vault/artifacts/qa-report.pdf.sha256
  expected=$(awk '{print $1}' .oneshot/vault/artifacts/qa-report.pdf.sha256)
  actual=$(shasum -a 256 .oneshot/vault/artifacts/qa-report.pdf | awk '{print $1}')
  [ "$expected" = "$actual" ] || { echo "QA PDF hash mismatch (expected=$expected actual=$actual)"; exit 1; }
  # PDF must be newer than markdown — protects against post-render md edits
  pdf_mtime=$(stat -f %m .oneshot/vault/artifacts/qa-report.pdf 2>/dev/null || stat -c %Y .oneshot/vault/artifacts/qa-report.pdf)
  md_mtime=$(stat -f %m .oneshot/vault/qa-report.md 2>/dev/null || stat -c %Y .oneshot/vault/qa-report.md)
  [ "$pdf_mtime" -ge "$md_mtime" ] || { echo "qa-report.md edited after PDF render — re-render required"; exit 1; }
  grep -q '^Verdict: APPROVED FOR DELIVERY' .oneshot/vault/qa-report.md
fi
```

For `.is_app_release`, this Deliver ticket is the `app-release-finalizer`: do not start from historical ledger GREEN. Its current verifier blocker must have passed `symphony release check` in the host-owned current generation and exact run; a restarted or host-rewound verifier must return to Verify and regenerate evidence. After repairs, the host replaces that dependency with the fresh verifier before the old cycle may close.

If gate passes:
1. Write `.oneshot/vault/delivery.md` (artifacts + sha256 list, run instructions, brief.md done-criteria checklist with citations to verification.md timestamps).
2. `git add -A && git commit -m "deliver: oneshot-delivered" && git tag -a oneshot-delivered -m "Symphony OneShot delivery"` (skip the tag if it already exists).
3. Set this ticket's state to `Delivered`. Append `## Resolution` pointing at `delivery.md`.

If gate fails:
- Set state to `Blocked` with `## Blocker` listing exactly which check failed.

{% else %}
Unknown lane: {{ issue.state }}. Set state to `Blocked` with a `## Blocker` section noting the lane is not recognized and which lane was expected.
{% endif %}
