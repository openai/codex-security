# Decomposition heuristics — turning one prompt into N tickets

The Plan lane is the only lane that decides what tickets exist. Quality of
decomposition is the upper bound on quality of delivery — if the Plan lane
ships a bad ticket map, no amount of clever Build/Verify/QA work fixes it.

## Route before slicing

Plan must classify the request before creating tickets:

- **Bugfix**: reproduction -> minimal fix -> regression verification.
- **Feature/enhancement**: behavior contract -> implementation -> changed-flow
  integration proof.
- **Customer-facing app delivery**: product brief -> workflow slices ->
  merged-target release verification.
- **Release/integration only**: current merged state -> build/start/customer
  flow proof -> delivery notes.
- **Docs/config/tooling**: exact surface -> static or command proof ->
  no-runtime-change rationale.
- **Research/spike**: evidence gathering -> decision note -> follow-up ticket
  list.

Do not use the app-delivery pattern for every prompt. A bugfix ticket that
requires a reproduction log should not be turned into market research; an app
delivery ticket that needs customer workflows should not be sliced as isolated
tables and screens.

## The decomposition checklist (Plan lane runs this)

For each candidate ticket:

0. **If this is app delivery, is the product defined?** — Before Build
   tickets exist, create a product-readiness brief ticket. It must name the
   target customer, core workflows, must-have features, non-goals, research
   sources or assumptions, data/auth/deploy constraints, and the final
   release-verification matrix. A pretty shell without the necessary customer
   workflows is not complete.
1. **Is it independently testable?** — A ticket whose tests need another
   un-built ticket should be merged with that ticket OR sequenced via
   `blocked_by`.
2. **Is its spec self-contained?** — Worker reads only the ticket's
   description + vault. If a third file is needed, add it to the spec.
3. **Does it fit one context window?** — Rough rule: a Build ticket should
   touch ≤5 files and ≤500 net lines. Bigger → split.
4. **Does it own one contract?** — Each Build ticket owns one section of
   `contracts.md`. Two tickets owning the same contract is a merge conflict
   waiting to happen.

## Ticket descriptions are worker prompts

The Plan lane must not create tickets whose description only says "read
plan.md". A ticket can point at its plan section, but its board description
must carry the minimum context needed for a fresh worker:

```text
Goal:
- <one outcome>

Scope:
- In: <files, flows, components, APIs>
- Out: <nearby work to avoid>

Dependencies:
- blocked_by: <ids or none>
- Contract: <the contract section this ticket owns or consumes>

Acceptance criteria:
- WHEN <event> THEN <observable behavior>
- IF <edge/error> THEN <observable behavior>

Verification:
- <focused command>
- <integration/full-suite command if this ticket owns it>

Done evidence:
- claim entry, verification entry, QA artifacts, or delivery.md section
```

This follows the spec-first discipline: requirements are observable, design is
separate from acceptance criteria, and tasks are small enough to verify
independently. If a Build slice needs more than this, put the full detail under
`## BUILD-N` in `plan.md` and summarize the exact anchor in the ticket.

## Ticket numbering is task order

The Plan lane must treat ticket IDs as ordering metadata, not decoration.
After writing the task table in `plan.md`, assign suffixes by walking that
table from top to bottom. The first Build task is `BUILD-1`, the second is
`BUILD-2`, and so on; the same applies to `VERIFY-N`, `QA-N`, `POLISH-N`, and
`DELIVER-N` if there are multiple tickets in those lanes. Then create the
kanban files in that same order. Do not sort by lane name, priority, or ease
of implementation when assigning numbers.

## Common slice patterns by product type

### CRUD web app
```
DISCOVERY-1 Product brief + release matrix      (no deps)
BUILD-1    Schema + migrations                  (deps: DISCOVERY-1)
BUILD-2    Auth: signup/login/session           (deps: DISCOVERY-1, BUILD-1)
BUILD-3    API: <resource> CRUD                 (deps: DISCOVERY-1, BUILD-1, BUILD-2)
BUILD-4    Web UI: primary customer workflow    (deps: BUILD-3)
BUILD-5    Web UI: secondary/edge workflows     (deps: BUILD-2, BUILD-3)
BUILD-6    Final release runner + contract hashes (deps: BUILD-1..5)
VERIFY-1   Merged-target release verification   (deps: BUILD-1..6)
QA-1       Playwright golden + accessibility    (deps: VERIFY-1)
DELIVER-1  Package + README + tag               (deps: VERIFY-1, QA-1)
```

`VERIFY-1` must run the declared app from the merged target branch, not just
the current feature branch. It records install/build/start output, readiness
checks, browser/API customer-flow proof, console/network/server errors, and a
market-ready gap list. A startup failure such as no listening port or
`curl 000` blocks delivery.
If defects appear, `VERIFY-1` runs a defect-registration loop: create new
Kanban bug tickets with repro evidence, expected behavior, fix boundary, and
verification commands; add them as blockers; rerun merged-target verification
after those blockers complete.

For an application release, Plan writes
`.oneshot/vault/release-contract.draft.yaml`, labels the release verifier
`app-release`, labels the named delivery ticket `app-release-finalizer`, and
creates a final Build slice that depends on the application/test slices. That
Build slice creates the native runner, removes placeholders, writes the final
repository-root `release-contract.yaml`, fills non-empty hashes from the final
repo-relative runner bytes, and lands both before Verify. The verifier writes
native results, artifacts, and the fixed
`docs/<verifier>/qa/release-evidence.json` manifest only below that verifier's
`qa/` directory, bound to the exact target SHA; it never edits the contract or
runner. The host verifies declared runner sources at both the exact target
commit and workspace. A repairable result is historical after Symphony creates grouped
repairs and a fresh verifier; the finalizer waits for that new cycle rather
than trusting an earlier ledger verdict.

### CLI tool
```
BUILD-1  Core domain logic + unit tests   (no deps)
BUILD-2  CLI surface (argparse/clap/etc)  (deps: BUILD-1)
BUILD-3  Output formatting                (deps: BUILD-1)
BUILD-4  Config loading (env/file)        (deps: BUILD-2)
VERIFY-1 Integration tests + golden CLI   (deps: BUILD-*)
DELIVER-1 README + man page + binary      (deps: VERIFY-1)
```
(no QA lane — `.is_browser_app` not set)

### Static landing page
```
DISCOVERY-1 Audience + offer + conversion brief       (no deps)
BUILD-1    Hero + nav + footer (semantic HTML)        (deps: DISCOVERY-1)
BUILD-2    Section components                         (deps: BUILD-1)
BUILD-3    Styling + responsive                       (deps: BUILD-2)
BUILD-4    Build pipeline (vite/astro/etc)            (deps: BUILD-3)
VERIFY-1   Merged-target browser + launch proof       (deps: BUILD-*)
QA-1       Playwright cross-viewport + a11y           (deps: VERIFY-1)
DELIVER-1  Deploy script + DNS notes                  (deps: VERIFY-1, QA-1)
```

## Anti-patterns

| Anti-pattern | Why it breaks | Fix |
|--------------|---------------|-----|
| One giant BUILD-1 "implement everything" | No parallelism; verify lane has nothing to compare against | Split per layer or per route |
| Build tickets call each other's internals | Re-introduces sequential dependency | Talk only via `contracts.md` |
| QA ticket created before any Build ticket | Nothing to test; QA worker idles or hallucinates | QA `blocked_by` all relevant Build tickets |
| Verify ticket per Build ticket | Ledger fragmentation; can't see integration failures | One Verify ticket per release; runs full suite |
| "Polish" used as catchall for missed work | Polish balloons; brief.md gets re-litigated | Polish only addresses verified findings; new scope → new ticket |

## Sizing the Plan

If decomposition produces >12 Build tickets, the Plan lane should *itself*
split: produce a `plan-phase-1.md`, `plan-phase-2.md` and only spawn
phase 1 tickets now. The Deliver gate of phase 1 then triggers a fresh
Plan ticket for phase 2 (set `blocked_by` accordingly).

This caps the in-flight surface area at ~10 active tickets, which is
roughly the most a single Verify lane can hold in its head.
