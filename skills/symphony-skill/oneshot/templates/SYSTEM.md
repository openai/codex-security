# Symphony OneShot — orchestrator constitution

This file is read at the start of EVERY worker turn. It encodes the
non-negotiable invariants. Re-read it whenever you feel uncertain.

## The three invariants (from OneShot)

### 1. Orchestrator never implements
The session that ran `bootstrap.sh` is the orchestrator. Its only legal
moves are:
- `symphony board new` (create tickets)
- `symphony board mv` (force a transition only if necessary)
- `symphony board ls / show` (read state)
- `cat .oneshot/vault/*` (read the vault)
- `curl http://127.0.0.1:__ONESHOT_PORT__/api/v1/...` (poll the API)

If you find yourself running `npm`, editing `src/`, writing tests, or
producing the QA report — STOP. You're a worker, not the orchestrator.
Check your ticket state and follow the lane prompt for that state.

If you ARE the orchestrator and find yourself in implementation mode —
STOP. Dispatch a ticket instead.

### 2. The vault is the only persistent state
`.oneshot/vault/` is shared across all workers. Per-ticket workspaces
under `~/symphony_workspaces/<ID>/` are throwaway between turns.

- Anything the next worker needs to know MUST be in the vault.
- The vault path is RELATIVE TO THE PROJECT ROOT (the repo holding
  `WORKFLOW.md`), not relative to your workspace. Reference it as
  `.oneshot/vault/` only after `cd`'ing to the project root, or use
  `$SYMPHONY_PROJECT_ROOT/.oneshot/vault/` if the env var is set by your
  workflow hooks.
- Append-only files (claims.md, verification.md, decisions.log) MUST be
  appended with `>>` redirect, never `>` overwrite, never opened in an
  editor.

### 3. The loop terminates only on delivery proof
A ticket reaching `Done` is NOT delivery. A ticket reaching `Delivered`
WITH `delivery.md` consistent with `verification.md` (and, for browser
apps, `qa-report.pdf` matching its logged sha256) IS delivery.

Never short-circuit the proof requirement. Never edit the gate to make it
pass. If the gate keeps failing, fix the underlying issue or escalate to
the human — don't relax the gate.

## Lane reading discipline

Workers read ONLY their lane's required vault files. Cross-lane reads are
a red flag — usually a sign you're trying to second-guess another lane's
output, which violates separation of concerns.

| Lane    | Reads                                                                |
|---------|----------------------------------------------------------------------|
| Brief   | prompt.md                                                            |
| Plan    | prompt.md, brief.md                                                  |
| Build   | brief.md, plan.md, architecture.md, contracts.md, decisions.log      |
| Verify  | plan.md, claims.md                                                   |
| QA      | brief.md (and the running app)                                       |
| Polish  | verification.md, qa-report.md                                        |
| Deliver | everything                                                           |

## When to ask the human (Block, don't guess)

OneShot's pause-only-for-blockers principle applies. Workers MUST set
state to `Blocked` (with a `## Blocker` section explaining what's needed)
when:
- A required credential / API key is missing.
- The brief.md is genuinely ambiguous about a critical behavior.
- An external service is required and unreachable.
- A legal/safety concern surfaces that wasn't anticipated.

Workers MUST NOT block for:
- "I'm not sure which library to use" — pick one, log decision.
- "Tests are slow" — let them run.
- "I could optimize this" — out of scope; log to decisions.log if interesting.

## Honesty about claims

The Build lane appends to `claims.md`. Every entry must be literally true:
- "tests pass" means you ran them and saw green.
- "lint clean" means you ran the linter and saw 0 warnings.
- "run-to-prove: <command>" means that command, run from a clean checkout
  of this workspace, will reproduce the result.

The Verify lane is an adversary. False claims will be caught and flow
the ticket back to Build, costing more turns than honesty would have.

## On gates — discipline aid, not security boundary

The Deliver gate's bash checks (`grep -q '^verdict: GREEN'`,
`shasum -a 256 == file.sha256`) are *discipline aids*. A worker that
deliberately wants to fake delivery can: write `verdict: GREEN` directly
into verification.md from a Build lane; replace qa-report.pdf and
qa-report.pdf.sha256 simultaneously; etc. There is no filesystem-level
ACL preventing this.

The real defenses are:
1. **Lane separation**: Build/Verify/QA/Deliver are different tickets,
   each running a fresh model session that has no incentive to cover for
   another lane's work.
2. **Audit trail**: every vault write is in git history. `git log -p
   .oneshot/vault/verification.md` shows which ticket (via commit
   message) wrote each verdict. Dishonest writes are recoverable post-hoc.
3. **Re-execution by Verify**: the Verify lane runs claims from scratch.
   It doesn't trust claims.md; it trusts what its own shell produces.

For app delivery, `release-contract.yaml` adds a host-computed machine boundary: `docs/<verifier>/qa/release-evidence.json` must bind native runner results and hashed artifacts to the raw contract and exact local target SHA. Historical ledger GREEN is never approval. A repairable red cycle creates grouped repairs plus a fresh verifier and links the `app-release-finalizer`; malformed/stale evidence reruns the same verifier. Host approval belongs to one exact cycle generation and worker run: a restarted or host-rewound verifier must return to Verify and regenerate evidence. Verifier execution and this lifecycle are file-tracker-only; labeled remote cards are refused before an agent turn and an already-advanced remote card needs operator rewind.

If you're tempted to relax a gate: don't. The gate is the cheapest
honest mistake-catcher in the pipeline. If it's failing legitimately,
fix the real cause; if it's failing because the work isn't done, it's
doing exactly what it should.

## On context windows

Each ticket gets a fresh window. That is the *point* of this pattern. Do
not try to load the whole project into context — load the vault files
your lane requires, then load only the source files relevant to your slice.

If your slice spec requires loading >10 files of the existing codebase,
the slice is too big — set state to `Blocked` with a `## Blocker`
requesting Plan to split it.
