# The `.oneshot/vault/` — shared knowledge contract

The vault is the *only* persistent state across worker sessions. Every
ticket spawned by Symphony gets a fresh LLM context window, so anything
the next worker needs to know MUST live in the vault. The vault sits in the
project root (NOT inside any per-ticket workspace), so all workers see the
same view via the `workspace.root` mount or via a shared bind-mount.

> **Why outside the workspace**: Symphony creates `~/symphony_workspaces/<ID>/`
> per ticket and the `after_create` hook clones a repo there. If the vault
> lived *inside* the workspace it would be cloned-from-template per ticket
> and divergent. Putting it at `<project_root>/.oneshot/vault/` and giving
> workers the path via the `WORKFLOW.md` prompt body keeps it singular.

## Layout

```
.oneshot/
├── SYSTEM.md                # orchestrator constitution (read-only after bootstrap)
├── prompt.md                # the user's original one-shot prompt (read-only)
└── vault/
    ├── brief.md             # north star: goal, audience, done criteria
    ├── plan.md              # decomposition + ticket map (frozen after Plan lane)
    ├── architecture.md      # system design, data model, deps (living)
    ├── contracts.md         # API/interface contracts between slices (living)
    ├── decisions.log        # ADR-lite, append-only
    ├── claims.md            # per-ticket "I did X" entries, append-only
    ├── verification.md      # per-ticket "I re-ran X and saw Y", append-only
    ├── qa-report.md         # human-readable QA findings (markdown source for PDF)
    ├── delivery.md          # final manifest, written only at Deliver lane
    └── artifacts/
        ├── qa-report.pdf    # PDF gate artifact for browser apps
        ├── screenshots/     # Playwright screenshots (PNG)
        └── test-results/    # raw JUnit/Playwright JSON outputs
```

## File-by-file contract

### `SYSTEM.md` — orchestrator constitution
- Written once by `bootstrap.sh`. Read-only thereafter.
- Encodes the three invariants from SKILL.md + the lane gates.
- Every lane prompt opens with `cat .oneshot/SYSTEM.md` so workers re-anchor.

### `prompt.md` — original user prompt
- Verbatim copy of what the user typed.
- Read-only. The Brief lane derives `brief.md` from it; later lanes refer to `brief.md`, not `prompt.md`.

### `brief.md` — north star (Brief lane writes it once)
Required sections:
```markdown
# Goal
<one-paragraph what-and-why>

# Audience
<who uses this; what they expect>

# Done criteria
- [ ] <objective acceptance check #1>
- [ ] <objective acceptance check #2>
- ...

# Constraints
- <tech, time, license, deploy target>

# Out of scope
- <explicit non-goals>

# Proof requirements
- [ ] tests pass: <commands>
- [ ] for browser apps: Playwright spec covers <flows> + qa-report.pdf produced
- [ ] <other proofs the user named>
```
The Plan lane treats every box in *Done criteria* + *Proof requirements* as
mandatory; nothing reaches Deliver until each is checked off in `verification.md`.

### `plan.md` — decomposition (Plan lane writes; frozen after)
```markdown
# Architecture overview
<2–4 paragraphs>

# Tickets
| ID         | Lane    | Title                         | Depends on  | Owner spec   |
|------------|---------|-------------------------------|-------------|--------------|
| BUILD-1    | Build   | Schema + migrations           | —           | §below       |
| BUILD-2    | Build   | API: /users CRUD              | BUILD-1     | §below       |
| BUILD-3    | Build   | Web UI: signup/login          | BUILD-2     | §below       |
| VERIFY-1   | Verify  | Run full suite + fixtures     | BUILD-*     | §below       |
| QA-1       | QA      | Playwright signup→logout flow | BUILD-3     | §below       |
| DELIVER-1  | Deliver | Package + README + sign-off   | VERIFY-1, QA-1 | §below     |

## BUILD-1 spec
<self-contained spec — file pointers, acceptance, test commands>

## BUILD-2 spec
...
```
**Frozen after the Plan lane closes.** Re-planning happens by writing to
`decisions.log` and creating new tickets, never by editing `plan.md` in place.

### `architecture.md` — living design doc
Updated whenever a Build ticket discovers a design change. Has a header
table-of-contents so workers can `head -50` to find their section without
loading the whole file.

### `contracts.md` — interface contracts
The boundary spec between Build tickets so they can run in parallel without
waiting for each other to compile. E.g.:
```
## /api/users (BUILD-2 owns; BUILD-3 consumes)
POST /api/users  body: {email, password}  → 201 {id, email}  | 400 {error}
GET  /api/users/:id                       → 200 {id, email}  | 404
```
If BUILD-3 needs a contract change, it MUST edit `contracts.md` AND open a
ticket against BUILD-2 — not silently mock locally.

### `decisions.log` — ADR-lite, append-only
```
## 2026-05-09T14:22Z BUILD-2: switched from JWT to session cookies
why: simpler CSRF story given target stack
impact: BUILD-3 must use credentials:'include' in fetch calls
```
Every meaningful design pivot is one entry. Workers grep this before making
their own decisions.

### `claims.md` — what each ticket says it did (append-only)
The Build/Polish lanes append here when transitioning to a verification-eligible
state. **This is untrusted input** — Verify lane treats it as a checklist
to re-prove, not as truth.
```
## 2026-05-09T14:55Z BUILD-2 → ReadyToVerify
- implemented POST /api/users, GET /api/users/:id
- tests added: tests/api/users.test.ts (4 cases)
- type-check: passing
- lint: 0 warnings
- run-to-prove: `npm test -- users.test.ts` → 4 passed
```

### `verification.md` — what was actually re-run (append-only)
The Verify lane re-executes every claim's `run-to-prove` and writes:
```
## 2026-05-09T15:02Z VERIFY-1 re-ran BUILD-2 claims
- `npm test -- users.test.ts` → 4 passed ✓ (matches claim)
- `npm run typecheck` → clean ✓
- `npm run lint` → 0 warnings ✓
- additional probe: `curl -X POST localhost:3000/api/users -d ...` → 201 ✓
verdict: GREEN
```
On RED, the Verify lane reopens the offending Build ticket (sets it back to
Build) and appends an `## Issues` section with the discrepancy.

### `qa-report.md` — human-readable QA narrative
Markdown source for the PDF. The QA lane writes:
```
# QA report — <product name>
date: <iso>
build sha: <git rev>

## Coverage
| Flow                     | Result | Screenshot                        |
|--------------------------|--------|-----------------------------------|
| signup happy path        | PASS   | artifacts/screenshots/signup-1.png |
| signup duplicate email   | PASS   | artifacts/screenshots/signup-2.png |
| login + logout           | PASS   | ...                                |
| accessibility (axe-core) | PASS   | (no violations)                    |

## Findings
- ...

## Sign-off
QA agent: <model id>
Verdict: APPROVED FOR DELIVERY
```
The PDF is rendered from this file by `templates/qa-pdf.sh`.

### `delivery.md` — final manifest (Deliver lane only)
```
# Delivery — <product name>
date: <iso>

## Artifacts
- source tree: <git sha + tag>
- qa-report.pdf: <sha256>
- test-results.json: <path>
- screenshots: 12 images

## Acceptance checklist
<copy of brief.md "Done criteria" with each box ticked + verification.md ref>

## How to run
<commands the user types>
```

## Append-only enforcement

Workers can rationalize "I'll just clean up this old claim entry."
**No.** The Verify lane uses the full claims log as its work queue;
deletions break the audit trail. Lane prompts say verbatim:

> Append to `claims.md` with `>>` redirect, never `>`. If you find yourself
> opening the file in an editor, stop — you don't need to.

## Reading the vault efficiently (context discipline)

Each lane's prompt names the *minimum* vault files that lane needs:
- Brief lane:    `prompt.md`
- Plan lane:     `prompt.md` + `brief.md`
- Build lane:    `brief.md` + `plan.md` + `architecture.md` + `contracts.md` + `decisions.log` (NOT claims, NOT verification)
- Verify lane:   `plan.md` + `claims.md` (the only lane that reads claims)
- QA lane:       `brief.md` + (running app URL from `delivery.md` if present, else from build hooks)
- Polish lane:   `verification.md` + `qa-report.md`
- Deliver lane:  everything

This minimization is what makes the pattern scalable to large products —
Build workers don't drown in QA findings they can't act on, and the QA
lane doesn't get dragged into refactoring debates.
