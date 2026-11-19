# Operations

Day-to-day commands for managing projects, tickets, and orchestrators.

## Projects and hub

Never run a project workflow from the `oh-my-symphony` source checkout. Doctor
and runtime protect that canonical Git repository, including linked worktrees.
Create a bootstrapped sibling repository or register an existing project:

```bash
symphony project create "My App" --path ../my-app
symphony project add /path/to/existing-repo --name "Existing App"
symphony project list
symphony project start my-app
symphony hub
```

The hub is a control plane: each card opens that project's independent service.
The Hub exposes an add/adopt form and project cards; every project board
exposes **Manage projects** and a project selector. Both surfaces show the
canonical repository, workflow, and board paths. A missing path is created and
initialized as Git; an existing non-Git directory is initialized in place; an
existing Git repository is reused. Only missing Symphony files are added, and
unrelated changes are never staged.

Switching starts the destination service when needed and navigates to it. It
never retargets or stops existing workers. Each service continues to own its
`WORKFLOW.md`, board, Git repository, project-scoped workspaces, and Product
Preview; the Hub does not multiplex projects through the source checkout.

For an existing non-Git directory, Symphony commits only its own newly added
operator files. Review and commit the directory's pre-existing product files
before dispatch; untracked files are not present in Git worktrees.

## Tickets (file-based tracker)

### Init the board

```bash
symphony board init ./kanban
```

Creates `kanban/` and a sample `DEMO-001.md`. Idempotent — re-running is
safe.

### Add a ticket

```bash
symphony board new TASK-1 "Fix flaky pagination test" \
  --priority 2 \
  --labels backend,test \
  --agent-kind claude \
  --description "tests/test_pagination.py::test_cursor_advance is flaky on CI."

# Structured creation: dependencies, request grouping, body from file/stdin.
symphony board new TASK-2 "Add regression test" \
  --blocked-by TASK-1 \
  --request REQ-1 \
  --label test --label ci \
  --description-file ./spec.md      # or `-` to read stdin
```

Identifiers must match `^[A-Za-z][A-Za-z0-9_-]{0,63}$` (`TASK-1`, `BUG-007`,
`PROD-2026-05-09`); anything with a slash, backslash, space or `..` is
rejected before it can escape the board root. Convention is
`<PREFIX>-<NUMBER>` but the shape is not enforced. The file lands at
`kanban/<ID>.md`. Omit `--agent-kind` to use the global `agent.kind` from
`WORKFLOW.md`; set it only for tickets that need a different backend.

`new` validates before writing: legal id, unique id, a state from
`tracker.active_states`/`terminal_states`, every `--blocked-by` target must
exist on the board, and the added edges must keep the dependency graph
acyclic (violations print the cycle path and exit non-zero). The web API's
issue create/update endpoints apply the same rules.

### Update a ticket

Never hand-edit ticket frontmatter — it bypasses cycle validation:

```bash
symphony board update TASK-2 --add-blocked-by BUG-7   # keep existing blockers
symphony board update TASK-2 --blocked-by TASK-1      # replace the list
symphony board update BUILD-1 --state Build           # reopen a slice
symphony board update TASK-2 --request REQ-2
```

Dispatched workers get the resolved CLI path in `$SYMPHONY_CLI`; prompts call
`${SYMPHONY_CLI:-symphony} board ...` so a venv install that is not on the
worker's PATH still works. `symphony doctor` reports this as `board.cli`.

When creating more than one ticket, assign IDs in the same order as the task
list: `TASK-001`, then `TASK-002`, then `TASK-003`. Symphony uses the stable
numeric suffix as its first dispatch order signal before mutable fields like
priority or update time. If you are adding to an existing prefix, list or scan
the board first, continue from the highest existing suffix, and create the
files in that same order. Use zero padding consistently so humans and shell
sorts see the same order as Symphony.

### List tickets

```bash
symphony board ls                       # everything
symphony board ls --state Todo          # one column
symphony board ls --state "In Progress" # quote multi-word states
```

### Inspect a ticket

```bash
symphony board show TASK-1
```

### Inspect the dependency DAG

```bash
symphony board graph                 # topological, indented
symphony board graph --request REQ-1 # only one request group
```

### Move a ticket (manual override)

```bash
symphony board mv TASK-1 Blocked
```

Use this only to unstick — the agent normally transitions tickets itself.

### Approve an intent from chat

Software requests typed into the web **Chat** page become an intent card,
not tickets. The operator approves once (button, or a bare `approve` /
`approve <slug>` reply from the same browser); the server files the request
ticket with `request: <slug>` and writes `.sdlc/work/<slug>/intent.md`.

```bash
# Same call the Approve button makes; the confirmation header is the
# browser-held capability created when the session started.
curl -X POST "http://127.0.0.1:9999/api/v1/chat/sessions/<session>/intent/<action_id>/approve" \
  -H "X-Symphony-Chat-Confirmation: <token>" -H "Content-Type: application/json" -d '{}'
```

Deep-preset boards receive the ticket in `Intake`; default boards in the first
active state. A proposal expires after 30 minutes and is superseded by any
ordinary reply. New applications: ask in edit mode and the agent proposes a
separate project with `preset: deep`.

## Running the orchestrator

### Managed service (normal headless mode)

```bash
symphony service start ./WORKFLOW.md --port 9999
symphony service status ./WORKFLOW.md
symphony service restart ./WORKFLOW.md
symphony service stop ./WORKFLOW.md
```

**"Open the orchestrator" → open the `--port` web app (default 9999).** The
orchestrator serves the full built-in admin web app at
`http://127.0.0.1:<--port>/` (default `9999`), not just the JSON API under
`/api/v1/`. This is the only board — there is no separate board-viewer
process or `--viewer-port` flag. When the operator says "open the
orchestrator", open the service `--port`:

```bash
open http://127.0.0.1:9999/        # macOS
xdg-open http://127.0.0.1:9999/    # Linux
start http://127.0.0.1:9999/       # Windows
```

Use `symphony service ...` for normal headless operation. It records a
per-workflow run-state file under `.symphony/run/` and refuses to start the
same `WORKFLOW.md` a second time on another port, which prevents duplicate
orchestrators from dispatching the same board.

The admin UI is not read-only: running cards expose Pause / Resume buttons,
the header refresh button triggers an orchestrator `poll + reconcile`, local
git branch dropdowns control `agent.feature_base_branch` and
`agent.auto_merge_target_branch`, the settings page switches lane presets
(default 4-lane ↔ deep 8-lane), and the Chat page turns software requests
into intent cards that one approval files as validated request tickets.

### TUI mode (interactive)

```bash
symphony tui ./WORKFLOW.md
```

**TTY required.** Background processes / scripts cannot render the TUI; the
process will exit silently. If you (the agent) want to start Symphony for
the user from a non-interactive shell, use headless mode below.

### Headless (no TUI)

```bash
symphony ./WORKFLOW.md                  # progress mirror auto-on
symphony ./WORKFLOW.md --no-progress-md # disable the WORKFLOW-PROGRESS.md file
```

A live `WORKFLOW-PROGRESS.md` is rewritten next to your workflow file on
every tick and on every state change. Open the file in any editor to follow
along without a TTY — it includes the current Kanban breakdown and the
last `progress.max_transitions` (default 20) state changes.

Override location and limits in `WORKFLOW.md` frontmatter:

```yaml
progress:
  enabled: true                # default true; CLI --no-progress-md wins
  path: docs/STATUS.md         # default: WORKFLOW-PROGRESS.md beside WORKFLOW.md
  max_transitions: 20
```

CLI flag for one-off path overrides: `--progress-md-path docs/STATUS.md`.

### Headless + JSON API

```bash
symphony ./WORKFLOW.md --port 9999
curl -s http://127.0.0.1:9999/api/v1/state | jq
curl -s http://127.0.0.1:9999/api/v1/TASK-1 | jq
curl -s -X POST -H 'Content-Type: application/json' -d '{}' http://127.0.0.1:9999/api/v1/refresh   # force a poll tick (mutations need JSON, even empty)
```

Endpoints:

| Method | Path                       | Purpose                                      |
|--------|----------------------------|----------------------------------------------|
| GET    | `/api/v1/state`            | Snapshot — running, retrying, totals, limits |
| GET    | `/api/v1/<identifier>`     | Issue detail (404 with structured error)     |
| POST   | `/api/v1/refresh`          | Coalesced trigger of poll + reconcile        |

### Stop a stuck server

```bash
lsof -ti :9999 | xargs -r kill        # SIGTERM (graceful)
lsof -ti :9999 | xargs -r kill -9     # only if SIGTERM doesn't take
```

### Logs

Symphony writes structured logs to **stderr only** by default
(`src/symphony/logging.py:48`). To preserve them:

```bash
mkdir -p log
symphony tui ./WORKFLOW.md 2>> log/symphony.log
# or, headless with tee for live tail:
symphony ./WORKFLOW.md --port 9999 2>&1 | tee -a log/symphony.log
```

## Demo without an agent CLI installed

`src/symphony/mock_codex.py` ships a JSON-RPC mock that the codex backend
can drive. Use it to demo or smoke-test without `codex` / `claude` /
`gemini` on `$PATH`:

```yaml
agent:
  kind: codex
codex:
  command: python -m symphony.mock_codex
```

Tunables (env vars):

| Var                                 | Default | Effect                          |
|-------------------------------------|---------|---------------------------------|
| `SYMPHONY_MOCK_TURN_SECONDS`        | 12      | total turn duration             |
| `SYMPHONY_MOCK_TICK_SECONDS`        | 2       | token-usage tick interval       |
| `SYMPHONY_MOCK_TOKENS_PER_TICK`     | 250     | tokens added per tick           |
| `SYMPHONY_MOCK_FAIL_EVERY_N_TURNS`  | 0       | force the Nth turn to fail      |
| `SYMPHONY_MOCK_MAX_TURNS`           | 0       | stop accepting turns after N    |

The mock does **not** rewrite ticket files — cards stay in their original
column with a runtime ● indicator overlaid. To see real column transitions,
use a real agent backend.
