> **Authoritative source**: `templates/WORKFLOW.oneshot.md` is the single
> source of truth for lane prompts. This file explains the *why* and
> shows the lane semantics in summary form. If anything here disagrees
> with the template, the template wins.
>
> **Note**: Symphony has since productized this lane model as the built-in
> 8-lane **deep** preset (`Intake → Research → Plan → Review → Build → QA →
> Verify → Document`, prompts under `docs/symphony-prompts/file/deep/`).
> Where this folder contradicts shipped behavior, the deep preset is the
> current form.

# The seven lanes — definitions + per-state prompts

This skill uses Symphony's `tracker.active_states` plus per-lane prompt
rules to give each lane its own instructions. Modern Symphony workflows can
split those rules into `prompts.base` + `prompts.stages` files; the bundled
OneShot template still uses the legacy inline Liquid body so bootstrap stays
single-file and self-contained. In either shape, workers see only the
rendered prompt for their current state, so context stays minimal and roles
stay separate.

## Lane order

```
Brief → Plan → Build → Verify → QA → Polish → Deliver
                ▲                         │
                └─── Polish reopens ──────┘
```

Polish can re-open Build tickets when QA finds issues. Verify can re-open
Build tickets when claims don't reproduce. Everything else flows forward.

## Lane responsibilities

| Lane     | Reads (vault)                                              | Writes (vault)                  | Closes by setting state to | Hard gate before closing |
|----------|------------------------------------------------------------|---------------------------------|----------------------------|--------------------------|
| Brief    | `prompt.md`                                                | `brief.md`                      | `Plan`                     | brief.md has all required sections |
| Plan     | `prompt.md`, `brief.md`                                    | `plan.md`, `architecture.md`, `contracts.md`, *spawns N Build/Verify/QA/Deliver tickets* | `Done` (this ticket) | plan.md ticket table is complete |
| Build    | `brief.md`, `plan.md`, `architecture.md`, `contracts.md`, `decisions.log` | code in workspace + append to `claims.md` | `Verify` | tests pass locally + claim entry written |
| Verify   | `plan.md`, `claims.md`                                     | append to `verification.md`     | `QA` (if web) or `Polish` (if not) **OR** reopen Build → `Build` | every claim re-run; verdict written |
| QA       | `brief.md`, running app                                    | `qa-report.md`, `artifacts/screenshots/*`, `artifacts/qa-report.pdf` | `Polish` **OR** reopen Build → `Build` | qa-report.pdf exists + sha256 logged |
| Polish   | `verification.md`, `qa-report.md`                          | append to `decisions.log`; may spawn fixup tickets | `Deliver` | no open critical findings |
| Deliver  | everything                                                 | `delivery.md`                   | `Delivered`                | bash gate (see below) |

## The Deliver gate (literal bash)

```bash
set -e
test -s .oneshot/vault/brief.md
test -s .oneshot/vault/plan.md
test -s .oneshot/vault/verification.md
grep -q '^verdict: GREEN' .oneshot/vault/verification.md || { echo "verify not green"; exit 1; }
if [ -f .oneshot/vault/.is_browser_app ]; then
  test -s .oneshot/vault/artifacts/qa-report.pdf
  grep -q '^Verdict: APPROVED FOR DELIVERY' .oneshot/vault/qa-report.md
fi
```

Pasting this into the Deliver lane's prompt (see `templates/WORKFLOW.oneshot.md`)
makes the gate mechanical. The agent literally cannot mark Delivered if the
shell exits non-zero — Symphony will retry the ticket until either the gate
passes or `agent.max_turns` exhausts.

## Per-lane prompts

This is the prompt body used by the bundled `templates/WORKFLOW.oneshot.md`
single-file bootstrap. For hand-maintained boards, you may split each
`{% if issue.state == ... %}` branch into a file under `prompts.stages` and
keep the common "ALWAYS START BY" block in `prompts.base`.

The orchestrator assembles a fresh first-turn prompt whenever a ticket
changes state. With external prompt files, that is `prompts.base` plus the
current state's stage file. With this inline template, it is the same body
re-rendered with the current `issue.state`.

```liquid
You are Symphony OneShot worker for ticket {{ issue.identifier }}: {{ issue.title }}.
Current lane: {{ issue.state }}.

ALWAYS START BY:
  cat .oneshot/SYSTEM.md            # 3 invariants — re-anchor every turn
  cat .oneshot/vault/brief.md 2>/dev/null || true

The vault is at .oneshot/vault/ in the project root (NOT inside this workspace).
Append-only files: claims.md, verification.md, decisions.log. Use `>>` redirect.

----- LANE-SPECIFIC INSTRUCTIONS -----

{% if issue.state == "Brief" %}
You are the Brief lane. Convert the raw user prompt into a structured brief.
Inputs:  .oneshot/prompt.md
Outputs: .oneshot/vault/brief.md (with sections: Goal, Audience, Done criteria, Constraints, Out of scope, Proof requirements)
Done criteria MUST be objective (commands that can be run, files that must exist, behaviors that can be checked).
For browser apps, the Proof requirements section MUST include a Playwright spec covering the primary user flow.
If the app appears to be a web/browser app (HTML, React, Vue, Svelte, Next, etc.), `touch .oneshot/vault/.is_browser_app`.
When done: set this ticket's state to `Plan` AND create the next ticket:
  symphony board new PLAN-1 "Decompose into work tickets" --priority 1
Then transition: edit kanban/{{ issue.identifier }}.md → state: Done, append `## Resolution`.

{% elsif issue.state == "Plan" %}
You are the Plan lane. ONLY job: produce a complete decomposition.
Inputs:  .oneshot/vault/brief.md, .oneshot/vault/prompt.md
Outputs:
  .oneshot/vault/plan.md          # ticket table + per-ticket spec sections
  .oneshot/vault/architecture.md  # system design, components, data model
  .oneshot/vault/contracts.md     # interface contracts between Build slices
For each Build/Verify/QA/Deliver ticket in plan.md, create it via:
  symphony board new BUILD-N "<title>" --priority 2 \
    --description "$(cat <<'EOF'
Goal:
- <one outcome this ticket owns>

Scope:
- In: <files, flows, components, APIs>
- Out: <nearby work this ticket must not touch>

Dependencies:
- blocked_by: <ids or none>
- Contract: <contracts.md section owned or consumed>
- Plan anchor: .oneshot/vault/plan.md §BUILD-N

Acceptance criteria:
- WHEN <event> THEN <observable behavior>
- IF <edge/error case> THEN <observable behavior>

Verification:
- <focused command>
- <lint/type/build/full-suite command if relevant>

Done evidence:
- Append a claims.md, verification.md, QA, or delivery entry as appropriate.
EOF
)"
The board description is the worker prompt. It may point at `plan.md`, but it
must still include goal, scope, dependencies, acceptance criteria,
verification, and done evidence.
Number each lane's tickets by task-table order, then run `symphony board new`
in that same order. Ticket suffixes are dispatch-order metadata in Symphony;
do not give a later task a lower number.
For BUILD tickets that depend on others, set blocked_by in the kanban file's frontmatter.
After all tickets are created, set this ticket's state to `Done` (Plan ticket itself terminates).
Constraint: do NOT write any implementation code yourself. If you catch yourself implementing, stop.

{% elsif issue.state == "Build" %}
You are a Build lane worker for one slice.
Inputs:  .oneshot/vault/brief.md, plan.md (read your §section only), architecture.md, contracts.md, decisions.log
Outputs: code in this workspace + an append entry to .oneshot/vault/claims.md
Workflow:
  1. Read `plan.md` and find §{{ issue.identifier }}'s spec.
  2. Implement. Follow contracts.md exactly — if you need a contract change, edit contracts.md AND open a ticket against the owning slice; do not silently mock.
  3. Write tests for the slice you built. Run them. They must pass.
  4. Run typecheck + lint if the project has them.
  5. Append to claims.md with the run-to-prove command:
       cat >> .oneshot/vault/claims.md <<EOF
       ## $(date -u +%FT%TZ) {{ issue.identifier }} → ReadyToVerify
       - <what you implemented>
       - tests: <files added/modified>
       - run-to-prove: \`<exact command(s)>\`
       - last run: <PASS/FAIL + counts>
       EOF
  6. Set state to `Verify`. Do NOT close the Verify ticket — that's a separate worker.
If you discover a design pivot, append to decisions.log first, then continue.

{% elsif issue.state == "Verify" %}
You are the Verify lane. You are an ADVERSARY to claims.md — re-prove every entry.
Inputs:  .oneshot/vault/plan.md, .oneshot/vault/claims.md
Outputs: append to .oneshot/vault/verification.md
Workflow:
  1. For each claim entry whose ticket is in state Verify, run its `run-to-prove` command from a clean workspace.
  2. Additionally, exercise integration points across slices (e.g. start the dev server and curl it).
  3. Run the full test suite (`npm test` / `pytest` / `go test ./...`) — not just the slice's tests.
  4. Type-check and lint the whole project, not just the slice.
  5. Append to verification.md:
       cat >> .oneshot/vault/verification.md <<EOF
       ## $(date -u +%FT%TZ) Verify ran <ticket list>
       - claim re-runs: <results>
       - integration probes: <results>
       - full suite: <results>
       verdict: <GREEN | RED>
       EOF
  6. If GREEN: for each verified Build ticket, set its state to `QA` (if .is_browser_app) or `Polish` (otherwise).
  7. If RED: for each ticket whose claim didn't reproduce, set its state back to `Build` and append an `## Issues` section to its kanban/<ID>.md body explaining the discrepancy.
Do NOT edit application code. Verify is read-only on the codebase.

{% elsif issue.state == "QA" %}
You are the QA lane (browser apps only). Drive the running app via Playwright.
Inputs:  .oneshot/vault/brief.md (Done criteria + Proof requirements)
Outputs:
  .oneshot/vault/qa-report.md
  .oneshot/vault/artifacts/screenshots/<flow>-<step>.png
  .oneshot/vault/artifacts/qa-report.pdf
Setup:
  - Start the app per brief.md's "How to run" — capture the URL.
  - If no Playwright config exists, copy the stub:
      cp .claude/skills/symphony-skill/oneshot/templates/playwright-qa.spec.ts tests/e2e/qa.spec.ts
      npm i -D @playwright/test axe-playwright
      npx playwright install chromium
  - Edit qa.spec.ts to cover every flow listed in brief.md's Proof requirements.
Run:
  npx playwright test tests/e2e/qa.spec.ts \
    --reporter=list,json --output=.oneshot/vault/artifacts/test-results
  # Each test must call await page.screenshot({ path: '.oneshot/vault/artifacts/screenshots/<name>.png', fullPage: true });
Build the markdown report:
  - Coverage table (one row per flow + result + screenshot path)
  - Findings (any flake, layout bug, a11y violation)
  - Sign-off block ending with `Verdict: APPROVED FOR DELIVERY` or `Verdict: BLOCKED — see Findings`
Render to PDF:
  bash .claude/skills/symphony-skill/oneshot/templates/qa-pdf.sh
  # uses Playwright itself to render qa-report.md → qa-report.pdf — no pandoc/wkhtmltopdf needed
Verify artifact exists + log sha256:
  test -s .oneshot/vault/artifacts/qa-report.pdf || exit 1
  shasum -a 256 .oneshot/vault/artifacts/qa-report.pdf >> .oneshot/vault/verification.md
Transition:
  - APPROVED → set state to `Polish`.
  - BLOCKED  → set the underlying Build ticket(s) back to `Build` with reproduction steps.

{% elsif issue.state == "Polish" %}
You are the Polish lane. Read findings, decide what (if anything) to address.
Inputs:  .oneshot/vault/verification.md, .oneshot/vault/qa-report.md
Outputs: appended decisions to .oneshot/vault/decisions.log; possibly new fixup tickets
Rules:
  - If a finding is a P0/P1 (security, data loss, broken golden path): create a Build ticket for the fix, set its blocked_by to this Polish ticket, transition this Polish ticket to `Blocked` until the fix lands and re-flows through Verify+QA.
  - If a finding is cosmetic and out-of-scope per brief.md: log the decision in decisions.log and proceed.
  - If everything is acceptable: set state to `Deliver`.

{% elsif issue.state == "Deliver" %}
You are the Deliver lane. Final packaging + sign-off.
Inputs: everything in .oneshot/vault/
Outputs: .oneshot/vault/delivery.md
Hard gate (run this FIRST — abort if non-zero):
  set -e
  test -s .oneshot/vault/brief.md
  test -s .oneshot/vault/plan.md
  test -s .oneshot/vault/verification.md
  grep -q '^verdict: GREEN' .oneshot/vault/verification.md
  if [ -f .oneshot/vault/.is_browser_app ]; then
    test -s .oneshot/vault/artifacts/qa-report.pdf
    grep -q '^Verdict: APPROVED FOR DELIVERY' .oneshot/vault/qa-report.md
  fi
If gate passes:
  - Write .oneshot/vault/delivery.md (artifacts list with sha256s, run instructions, brief.md done-criteria checklist with ✓s and citations to verification.md timestamps).
  - Tag the git commit: `git tag -a oneshot-delivered -m "..."`
  - Set state to `Delivered`. Append `## Resolution` to this ticket pointing at delivery.md.
If gate fails:
  - Set state to `Blocked` with `## Blocker` listing exactly which check failed.

{% else %}
Unknown lane: {{ issue.state }}. Set state to `Blocked` with a `## Blocker` section noting the lane is not recognized.
{% endif %}

----- ALWAYS END BY -----
echo "{{ issue.identifier }} turn complete: lane={{ issue.state }} at $(date -u +%FT%TZ)" >> log/oneshot.log
```

## Why each lane minimizes its vault reads

Naive design: every worker reads the entire vault → context blows up by
ticket #5.

This design assigns each lane the *minimum sufficient* set:
- Build doesn't read claims/verification (it's not its job to know what others did).
- Verify doesn't read brief.md (it doesn't decide what's correct, only whether claims reproduce).
- QA doesn't read code (drives the app as a black box, like a real QA engineer).
- Polish only reads findings, not raw output.

This is the OneShot insight: **role separation enforced by what you read,
not just what you do.** A worker that doesn't load a file can't be tempted
to second-guess that file's owner.

## Concurrency

Configure in WORKFLOW.md:
```yaml
agent:
  max_concurrent_agents: 1
  max_concurrent_agents_by_state:
    Brief: 1        # only one brief
    Plan: 1         # only one plan
    Build: 1        # raise only when intentionally parallelizing implementation
    Verify: 1       # one verifier — avoids conflicting reruns
    QA: 1           # one QA — avoids screenshot collisions in artifacts/
    Polish: 1
    Deliver: 1
```
The default `max_concurrent_agents: 1` keeps OneShot sequential. Raise the
top-level cap and `Build` lane cap together only when you intentionally want
parallel implementation.

## Cross-reference

When QA lane needs to invoke the user's existing `qa-engineer` skill (for
deployed-environment sign-off rather than localhost), prepend this to the
QA prompt body:
```
If the brief.md "How to run" indicates a deployed URL (https://*), invoke
the qa-engineer skill rather than this lane's localhost flow. The skill
produces its own evidence pack — copy its outputs into
.oneshot/vault/artifacts/ before transitioning.
```
