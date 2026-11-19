# Delegating sub-tasks to Symphony

When the user gives a large task that decomposes into N independent
sub-tasks, you (the main conversational agent) can offload each sub-task
to Symphony rather than doing them inline. Each spawned worker runs in a
**fresh LLM session** with its own context window — so the calling agent's
context only carries the orchestration overhead, not all sub-implementations.

## Recipe

1. **Frame the objective** before creating files: one goal, expected user or
   operator outcome, constraints, out of scope, and proof commands. If the
   request is really one small change, create one ticket instead of a board.

   Classify the work type before decomposition. The ticket map should match the
   job:

   | Work type | First ticket owns | Final proof owns |
   | --- | --- | --- |
   | Bugfix | Reproduction, suspected area, failing test/log | Regression closes repro + focused suite |
   | Feature/enhancement | Behavior contract and acceptance criteria | Integration for changed workflow |
   | Customer-facing app delivery | Product brief and workflow matrix | Merged-target release verification |
   | Release/integration only | Current merged state and release risks | Full launch/build/customer-flow proof |
   | Docs/config/tooling | Exact affected surface and rollback risk | Static checks + no-runtime-change rationale |
   | Research/spike | Unknowns, evidence plan, decision criteria | Decision note + follow-up ticket list |

   Do not register product-discovery tickets for a narrow bugfix unless the bug
   exposes a missing product contract. Do not register a single broad
   `implement app` ticket when the work is customer-facing app delivery.

   For customer-facing app work, frame the product before the implementation
   queue. Do not decompose straight into screens or tables. Capture:

   - target customer and the job they need done;
   - comparable product or domain research used, with sources or explicit
     assumptions when live research is unavailable;
   - core customer workflows that must work end to end;
   - must-have functionality, non-goals, and market-ready gaps;
   - data, auth, permissions, security, deploy, and seed/demo-data assumptions;
   - the declared launch path and final release verification command set.

2. **Decompose** the request into independent tickets, each with a
   self-contained spec. Independence is critical: Symphony runs eligible
   tickets concurrently up to `agent.max_concurrent_agents`. Use `blocked_by`
   for real dependencies, and use ticket IDs to express FIFO order among
   otherwise eligible tickets.

   A good ticket slice has all of these:

   - independently testable without relying on unfinished work;
   - one contract owner: a route, data model, CLI behavior, UI flow, or
     integration boundary;
   - small implementation surface: roughly <=5 files and <=500 net lines for a
     Build ticket;
   - explicit acceptance criteria, including edge/error cases;
   - exact verification commands the worker can run.

   Bad slices: `misc cleanup`, `implement app`, `frontend polish`, or two
   tickets that must edit the same behavior without an ordered dependency.

   For a new app or major product surface, the first ticket is a
   product-readiness brief, not code. It owns the user research summary,
   customer workflow map, feature inventory, and release acceptance matrix.
   Build tickets consume that brief. A final release-verification ticket is
   blocked by every Build ticket and proves the merged target branch runs as a
   coherent product.
   That release ticket is a loop: after prerequisite work is committed, pushed,
   and merged, it runs full functionality QA on the merged target. If QA finds
   defects, register new Kanban bug tickets with repro evidence, add them as
   blockers, and loop until the merged target passes.

3. **Register** each as a Symphony ticket with a rich description (this
   description is the only context the worker gets, plus the WORKFLOW.md
   prompt template):

   ```bash
   symphony board new TASK-001 "<title>" \
     --priority 2 \
     --description "<full spec + acceptance criteria + file pointers>"
   ```

   Number tickets in the same order you created the task list. Do not let a
   later task receive a lower suffix, because the dispatcher treats
   `TASK-001` as earlier work than `TASK-002` regardless of priority.

4. **Launch headless** (TUI requires a TTY you don't have):

   ```bash
   symphony ./WORKFLOW.md --port 9999 2>> log/symphony.log &
   ```

5. **Poll for completion** at sensible intervals (don't tight-loop):

   ```bash
   curl -s http://127.0.0.1:9999/api/v1/state \
     | jq '.counts, .running[].issue_identifier'
   symphony board ls --state Done
   ```

6. **Collect results** by reading the `## Resolution` section of each
   completed ticket file:

   ```bash
   symphony board show TASK-A
   ```

## Ticket prompt template

Use this shape for `--description`. Keep it compact but complete; the worker
should not need the original chat.

```text
Goal:
- <one outcome in user/operator terms>

Scope:
- In: <files, flows, APIs, or components this ticket owns>
- Out: <nearby work this ticket must not touch>

Dependencies:
- blocked_by: <ticket ids or "none">
- Contracts to preserve: <public API, schema, prompt, CLI, UI behavior>

Acceptance criteria:
- WHEN <event> THEN <observable behavior>
- IF <edge/error case> THEN <observable behavior>

Implementation notes:
- Prefer existing helpers/patterns: <paths>
- Avoid: <risky shortcut or unrelated refactor>

Verification:
- <exact unit/integration command>
- <lint/type/build command if relevant>
- For app delivery: <merged-target start command + customer workflow smoke>

Done evidence:
- Append a Resolution with changed files, tests run, and residual risk.
```

If a dependency is real, add it to the ticket frontmatter after creation:

```yaml
blocked_by:
  - TASK-001
```

Symphony workers should still self-check blockers with
`symphony board show <ID>` because frontmatter is advisory metadata, not a
distributed lock.

## Application-development slice patterns

For a typical app change, separate by behavior and proof surface:

```text
TASK-001  Product readiness brief + release matrix (no deps)
TASK-002  Data model / migration / fixtures        (deps: TASK-001)
TASK-003  Core service or API behavior + tests     (deps: TASK-001,TASK-002)
TASK-004  Primary customer workflow UI + tests     (deps: TASK-001,TASK-003)
TASK-005  Secondary workflow / edge states         (deps: TASK-001,TASK-003)
TASK-006  Release verification on merged target    (deps: TASK-002..005)
TASK-007  Delivery docs / changelog / commit prep  (deps: TASK-006)
```

The release-verification ticket is not a paperwork ticket. It checks out or
uses the merged target branch after prior tickets land, runs install/build/start
from a clean-ish operator path, waits for readiness, drives the core customer
flows in a browser or API client, records console/network/server failures, and
states whether the app is market-ready or which customer-critical gaps remain.
If the app cannot start (`curl 000`, no listening port, failed build, missing
env, broken seed data), the ticket blocks delivery instead of moving to Document.
When this proof finds defects, register new Kanban bug tickets with
reproduction steps, logs, expected behavior, fix boundary, and verification
commands; add them to the release ticket's `blocked_by` and loop until the
merged target passes.

For a bug:

```text
TASK-001  Reproduce failure with failing test/log (no deps)
TASK-002  Minimal fix + focused tests             (deps: TASK-001)
TASK-003  Regression verification + full suite    (deps: TASK-002)
```

Bugfix ticket descriptions must include the observed failure, expected
behavior, suspected area or "unknown", reproduction command/log, fix boundary,
regression command, and what would still be `Not proven`. They should not ask
the worker to redesign unrelated product flows.

For a bounded feature/enhancement:

```text
TASK-001  Behavior contract + acceptance matrix   (no deps)
TASK-002  Implementation + focused tests          (deps: TASK-001)
TASK-003  Changed-workflow integration proof      (deps: TASK-002)
```

Feature tickets own one behavior change. If the change becomes a new product
surface, route it through the app-delivery pattern instead of silently expanding
scope.

For browser UI:

```text
TASK-001  Product/customer workflow contract
TASK-002  Data/API contract
TASK-003  UI implementation
TASK-004  Responsive/accessibility/browser QA
TASK-005  Merged-app release proof
```

One Verify ticket per release is usually better than one Verify ticket per
Build ticket; it catches integration failures and keeps the evidence ledger in
one place.

## When this pattern wins

- Large, parallelizable work (N independent features / fixes / migrations).
- Each sub-task fits in a worker's context — the orchestrator can't help
  if a sub-task itself is too big.
- The user is happy to wait for a polling cycle rather than streaming
  output.

## When this pattern *doesn't* win

- Sub-tasks have ordering dependencies you cannot encode with `blocked_by`.
- The user expects real-time visibility into each sub-agent's reasoning
  (Symphony exposes only event-level logs, not the agent's stream).
- There is no callback / push notification — the calling agent must poll.

## Distinction from in-session TodoWrite

| Aspect       | Claude Code TodoWrite                  | Symphony delegation                       |
|--------------|----------------------------------------|-------------------------------------------|
| Execution    | same agent, same session               | N separate subprocesses, fresh sessions   |
| Context      | within calling agent's context         | each worker has its own context           |
| Sync         | synchronous, inline                    | asynchronous, polling required            |
| Best for     | steps within one conversation          | independent work units, large fan-out     |

The two compose: one Symphony worker can use TodoWrite internally to
track the sub-steps of *its* sub-task.

## Quality of decomposition matters more than mechanism

Symphony will faithfully run whatever you put in front of it. The hard
part is human-side decomposition:

- Each ticket's `description` should read like a self-contained spec:
  acceptance criteria, file pointers, test commands, dependencies, and proof.
  The worker has no conversation history.
- Avoid sub-tasks that require shared in-memory state. If two tickets
  must agree on a schema, write the schema down in a third ticket (or in
  a file the workspace will pick up via `after_create`) before launching
  them.
- Time-box experiments: start with `agent.max_turns: 5` and `agent.max_concurrent_agents: 1`
  while validating the decomposition. Crank up only after seeing a clean
  run.
