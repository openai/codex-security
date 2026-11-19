# Authoring `WORKFLOW.md`

`WORKFLOW.md` is a **hybrid file**:
- **YAML frontmatter** = orchestrator config (tracker, hooks, agent, etc.)
- **Prompt source** = either external files declared under `prompts:` or,
  if no matching prompt file is configured, the strict-Liquid body after
  the frontmatter.

When editing, distinguish runtime config from agent instructions. New
workflows should prefer `prompts.base` + `prompts.stages`; the body is the
legacy fallback.

## Minimal template

```markdown
---
tracker:
  kind: file
  board_root: ./kanban
  active_states: [Todo, "In Progress", Verify, Document]
  terminal_states: ["Human Review", Done, Blocked, Archive]

workspace:
  root: ~/symphony_workspaces

hooks:
  after_create: |
    : noop
  before_run: |
    : noop
  after_run: |
    echo "run finished at $(date)"

agent:
  kind: claude          # codex | claude | gemini | opencode | pi | prime-agent
  max_concurrent_agents: 1
  max_turns: 20
  crash_continuation: true

claude:
  command: claude -p --output-format stream-json --verbose
  resume_across_turns: true
  turn_timeout_ms: 3600000

prime_agent:
  command: prime-agent -p --mode json
  resume_across_turns: true
  turn_timeout_ms: 3600000

server:
  port: 9999

prompts:
  base: ./docs/symphony-prompts/file/base.md
  stages:
    Todo: ./docs/symphony-prompts/file/stages/todo.md
    "In Progress": ./docs/symphony-prompts/file/stages/in-progress.md
    Done: ./docs/symphony-prompts/file/stages/done.md
---

This body is only used when `prompts:` is removed or no matching stage
prompt exists.

You are picking up ticket {{ issue.identifier }}: {{ issue.title }}.
…
```

## Picking the agent

Set `agent.kind`:
- **`codex`** — Codex `app-server`. Best for multi-turn JSON-RPC sessions; most mature backend. Long-running stdio JSON-RPC connection; one process for the whole run.
- **`claude`** — Claude Code. Fresh subprocess per turn with `--resume <session-id>` from turn 2 onward. NDJSON event stream.
- **`gemini`** — Gemini CLI. Fresh subprocess per turn. Current releases expose no exact session-resume flag, so Symphony treats each invocation as a one-shot turn and uses a local session UUID only for telemetry.
- **`opencode`** — OpenCode CLI (`opencode run --format json --auto`). Fresh subprocess per turn; Symphony passes the prompt as the documented `message` argument and adds `--session <id>` on continuation turns after OpenCode reports a session id. Usage parsing is best-effort from JSON events.
- **`pi`** — Pi coding-agent (`pi --mode json -p ""`). Per-turn subprocess with `--session <id>` resume from turn 2 onward; JSONL events. Multiplexes Anthropic / OpenAI / Gemini / Bedrock backends behind one CLI — useful when you want to swap LLM providers without changing Symphony config. Auth: sign in once with `pi` → `/login` (OAuth); credentials cached at `~/.pi/agent/auth.json` and inherited by every subprocess Symphony spawns. `symphony doctor` warns if the auth file is missing.
- **`prime-agent`** — Prime Agent (`prime-agent -p --mode json`). Per-turn subprocess with `--resume <id>` continuity; same JSONL event protocol as Pi. Authenticate with `prime-agent` → `/login` or a provider API key; credentials are cached at `~/.prime/agent/auth.json`. `symphony doctor` warns if the auth file is missing.

Each backend reads its own block (`codex`, `claude`, `gemini`, `opencode`, `pi`, `prime_agent`); the
others are ignored. The `codex.linear_graphql` client tool is only
advertised when `agent.kind: codex`.

`agent.kind` is the workflow-wide default. For file-backed boards, one ticket
can opt into a different backend with frontmatter:

```yaml
---
id: TASK-001
title: Run this one with Codex
state: Todo
agent:
  kind: codex
---
```

Symphony also accepts the flat alias `agent_kind: codex` for hand-edited
cards. The override chooses only the backend kind; command, timeout, resume,
and sandbox settings still come from the matching global backend block in
`WORKFLOW.md`. When creating a ticket from the file-board CLI, use
`symphony board new TASK-001 "title" --agent-kind codex`.

Between the ticket pin and the global default sits optional per-state
routing: `agent.stage_kinds` maps board states to agent kinds, so cheap/fast
agents can own light lanes while a strong default handles the heavy ones:

```yaml
agent:
  kind: claude
  stage_kinds:
    Todo: gemini
    Document: gemini
```

Resolution per dispatch: ticket `agent_kind` pin > `agent.stage_kinds[state]`
> `agent.kind`. The backend is re-resolved at every stage change, including the
in-run lane transitions one dispatch walks.

### Crash continuation

`agent.crash_continuation` defaults to `true`. After a hard crash or managed
service restart, Symphony first fences and terminates the prior backend process,
then creates a new Run attempt from the latest completed-turn checkpoint. Codex,
Claude Code, OpenCode, Pi, and Prime Agent resume an exact session identifier.
Gemini, AGY, Kiro, agent/state mismatches, and application-release verifier or
finalizer runs start a fresh session against the preserved workspace instead.
Codex can reject a missing session before work and fall back immediately. A
per-turn CLI binds its first invocation to the exact ID; rejection fails that
recovery attempt closed, and the later retry starts fresh. The interrupted turn
may run again; arbitrary external tool actions are not exactly-once. Set
`crash_continuation: false` to keep fresh-session restart behavior.

### Codex workspace sandbox and package registries

Keep the thread sandbox confined to the worker workspace. When a Codex worker
must install dependencies from package registries, enable network only on the
v2 turn policy:

```yaml
codex:
  thread_sandbox: workspace-write
  turn_sandbox_policy: {type: workspaceWrite, networkAccess: true}
```

The string shorthand `turn_sandbox_policy: workspace-write` remains valid, but
its v2 payload defaults to no network access. A registry download failure does
not require `danger-full-access`; the tagged policy preserves filesystem
confinement while enabling network for the turn. Use `danger-full-access` only
after proving that an OS capability outside workspace and network permissions
is required, such as a browser runtime blocked by the platform sandbox.

Symphony passes tagged policy dictionaries through to Codex and still merges
auto-detected symlink and git-worktree paths into `writableRoots`. Do not put
the tagged object under `thread_sandbox`; Codex thread start expects the
kebab-case string there.

## Prompt files

Preferred current shape:

```yaml
prompts:
  base: ./docs/symphony-prompts/file/base.md
  stages:
    Todo: ./docs/symphony-prompts/file/stages/todo.md
    "In Progress": ./docs/symphony-prompts/file/stages/in-progress.md
    Verify: ./docs/symphony-prompts/file/stages/verify.md
    Document: ./docs/symphony-prompts/file/stages/document.md
    Done: ./docs/symphony-prompts/file/stages/done.md
```

At dispatch, Symphony sends `base` plus only the file matching the ticket's
current `state`. Paths are resolved relative to `WORKFLOW.md`; `$VAR`
values are expanded through the usual config indirection. Stage keys are
matched case-insensitively after trimming whitespace.

Missing prompt files fail config validation with `prompt file not found`.
If `prompts:` is absent, or a state has no configured stage file, Symphony
falls back to the inline body below the frontmatter. Keep that body as a
short legacy fallback, not as the primary place for all stage rules.

## Hooks

Each hook is a shell script that runs in the workspace directory:

| Hook            | When                                | Common use                          |
|-----------------|-------------------------------------|-------------------------------------|
| `after_create`  | when workspace is first created (`reuse_policy: preserve`); on every reuse with `reuse_policy: refresh` | attach a `git worktree` of the host repo on a `symphony/<ID>` branch + record fork-point (`git config symphony.basesha <HEAD>`) for the end-of-run squash |
| `before_run`    | before every turn                   | `git fetch` to pull latest remote refs — **never `git reset --hard`**; that would discard the agent's mid-run work |
| `after_run`     | after every turn                    | per-turn **commit-or-amend**: first turn creates `wip: turn …`, every subsequent turn `--amend --no-edit`s into it. Branch stays at one commit but each turn is durably written to `.git/objects` |
| `before_remove` | before workspace cleanup            | `git worktree remove --force` to drop the registration before Symphony rmtree's the dir |

### Default workspace mechanism: `git worktree`

`WORKFLOW.example.md` and `WORKFLOW.file.example.md` ship with
`after_create` hooks that attach the per-ticket workspace as a **git
worktree** of `$SYMPHONY_WORKFLOW_DIR` on a fresh `symphony/<ID>`
branch. The host's working tree is never modified, and the operator
sees each feature branch immediately. `agent.feature_base_branch` selects
the start point for new `symphony/<ID>` branches; empty means the current
host branch. The default Document prompt merges `symphony/<ID>` into
`agent.auto_merge_target_branch` before the ticket moves to `Done`; empty
means the feature base/current host branch. The admin web app exposes both
values as real local git branch dropdowns, and post-Done auto-merge is only
a compatibility fallback for older prompt packs. Worktrees share the host's
object DB so setup is near-instant compared to a full clone, and the branch
is immediately visible to host-side `git` commands. Under the default
`reuse_policy: preserve`, Symphony never reruns an arbitrary `after_create`
body. For an existing workspace it only fast-forwards an exact linked
worktree that shares this workflow repo, is clean (including non-ignored
untracked files), and whose `symphony/<ID>` tip is strictly behind and
contained by the configured local target branch. Symphony captures that
branch's immutable SHA and uses it for the in-place `git merge --ff-only`; a
later target commit is normal drift and is handled by the delivery gate. The
worktree-local
`symphony.basesha` then advances to the captured target SHA. Dirty, divergent,
same-tip, missing-target, and unexpected/racing workspaces are left alone.
When a workspace was reaped and the shell setup hook must recreate it, that
hook uses a bounded compare-and-swap refresh of the branch ref before
attaching the worktree. Set `reuse_policy: refresh` only when rerunning the
configured lifecycle hook on reuse is intentional.

The matching `before_remove` hook runs `git worktree remove --force`
so cleanup also drops the `.git/worktrees/<ID>` registration; without
it the registration lingers until `git worktree prune`.

If your code lives in a *different* remote than the WORKFLOW.md repo
(common for Linear setups where the config repo is config-only), swap
the worktree commands for `git clone <remote> .`. While experimenting
without any repo, use `: noop`.

### One commit per ticket (`agent.auto_commit_on_done`)

`agent.auto_commit_on_done: true` (the default) gives you a
**one-commit-per-ticket guarantee** on the `symphony/<ID>` branch:

1. `after_create` records the fork-point (`git config symphony.basesha
   $(git rev-parse HEAD)`).
2. `after_run` commits-or-amends every turn into a single `wip: turn …`
   commit on the branch — durable across hard crashes (SIGKILL, host
   reboot) because each turn's tree lands in `.git/objects`.
3. On any clean worker exit (Done, Cancelled, Blocked) and on every
   cleanup path (`reconcile_terminate_terminal`,
   `_startup_terminal_cleanup`), the orchestrator's
   `commit_workspace_on_done`:
   - reads `symphony.basesha`
   - `git reset --soft <basesha>` to collapse the wip commit + any
     agent-authored commits into the index
   - `git commit -m "<ID>: <title>[ <suffix>]"` — single ticket commit

Net result: `git log symphony/<ID>` shows exactly **base + 1 commit**.
During Document, that branch is merged into the target branch with a real
merge/PR before the ticket is allowed to move to `Done`.

`agent.auto_merge_push_target` defaults to `true`: after the local
`--no-ff` target merge, Symphony publishes and verifies the target's
configured upstream. Set it to `false` for a local-only workflow; the same
local merge safety gate still runs, but neither the feature branch's final
history gate nor the target merge performs `git push` or `git ls-remote`.
Release-evidence tickets remain local audit snapshots regardless of this
setting.

Commit-message convention:

| Exit shape                         | Subject                                            |
|------------------------------------|----------------------------------------------------|
| Reached `Done`, normal worker exit | `<ID>: <title>`                                    |
| Other terminal state (Cancelled)   | `<ID>: <title> [state: Cancelled]`                 |
| Force-pruned by reconcile/startup  | `<ID>: <title> [state: <state>]` (or `[exit: …]`) |

**Mid-run hard-crash recovery**: even if Symphony itself is SIGKILLed
before any cleanup runs, the per-turn amend leaves the branch at the
last completed turn's wip commit (durably in `.git/refs/heads/symphony/
<ID>` and `.git/objects`). Operator can rename it manually with
`git -C <host> commit --amend -m "<ID>: <title>"` then merge.

**Pre-commit hook compatibility**: the per-turn commit and the final
squash commit both honour the host repo's pre-commit hooks. If a hook
fails, the auto-commit fails and the operator sees the rejection in
`log/symphony.log` — work is still on disk in the worktree, no silent
loss.

**Opting out**: set `auto_commit_on_done: false` only when the
workspace is an existing repo with strict commit-style rules you don't
want auto-touched. Then you own snapshotting and squashing yourself in
`before_remove`. Recovery from a discarded worktree without it is
`git fsck --lost-found` plus luck.

### File-board host links

When `after_create` links host-owned roots such as `kanban/` or `prompt/`
into the workspace, set `workspace.reuse_policy: refresh`, hide those
roots from the worktree's Git status (`skip-worktree` + `info/exclude`),
guard them in `before_run`, and exclude them from `after_run`'s
`git add -A`.

Keep `docs/` branch-local by default. Per-ticket reports, QA evidence,
and `docs/llm-wiki/` updates are reviewable deliverables and should land
on `symphony/<ID>` before the target branch receives a `--no-ff` merge.
Only link `docs/` from the host if you intentionally want out-of-branch
documentation and accept that it needs a separate capture/commit policy.

Use `git rev-parse --git-path <scratch-name>` for hook temp files; linked
worktrees often have `.git` as a file, not a directory. If these roots
show up as mode `120000` symlink blobs in Review, the branch captured
workflow plumbing instead of code changes. See `WORKFLOW.file.example.md`
for the reference hook.

**Failure mode**: if `after_create` exits non-zero, the worker dies
immediately with `worker_exit reason=error`. The shipped sample's
worktree hook fails when `$SYMPHONY_WORKFLOW_DIR` is not a git repo
or when `symphony/<ID>` is already checked out in another worktree;
a clone-mode override using a placeholder
`git@github.com:my-org/my-repo.git` URL fails the same way.
`symphony doctor` catches the placeholder case.

### Hook authoring rules

Hooks run via `bash -lc` in the workspace directory and inherit only
`os.environ.copy()` — no ticket-specific env vars are injected
(`workspace.py:155-167`). The ticket ID is recoverable as
`basename "$PWD"`; everything else must be parsed out of
`<board_root>/<ID>.md` by hand. Six rules to avoid the most common
self-inflicted hook failures:

1. **Never parse YAML frontmatter with `awk -F':'`.** It splits on every
   colon, so a value like `repo: https://github.com/owner/repo.git`
   becomes `$2 = "https"` — `git clone https .` then fails with rc=128
   and the worker bounces through retries with the same error. Capture
   everything after the first `: ` instead:
   ```bash
   # Wrong:
   REPO=$(awk -F': *' '/^repo:/ {print $2; exit}' "$TICKET")

   # Right:
   REPO=$(sed -n 's/^repo: *\(.*\)$/\1/p' "$TICKET" | head -1 | tr -d '\r"')
   ```
2. **Verify the hook body in isolation before launching the TUI.** Drop
   the `after_create` body into `/tmp/sym-verify-<ID>` and run it
   manually. Symphony cleans up failed workspaces aggressively, which
   makes post-mortem hard.
3. **`set -e` at the top of every non-trivial hook.** Without it, a
   failed `git clone` happily continues into `git checkout` and the
   error trail becomes ambiguous.
4. **Use absolute paths inside hook bodies.** `./kanban/$ID.md` is
   resolved against the workspace cwd, not the WORKFLOW.md directory —
   so it points at a file that doesn't exist. Hardcode the absolute
   board path:
   ```bash
   BOARD="/abs/path/to/kanban"
   TICKET="$BOARD/$(basename "$PWD").md"
   ```
5. **Strip CR and quotes after parsing.** `tr -d '\r"'` on every
   sed-extracted value. Frontmatter authored on Windows is CRLF, and
   string values often pick up surrounding quotes that break shell
   substitution.
6. **`after_create` is not assumed idempotent.** With the default
   `reuse_policy: preserve`, Symphony does not rerun it on an existing
   workspace; with `reuse_policy: refresh`, it intentionally does. Symphony
   removes a workspace on hook failure before retrying, so from-scratch is
   safe — but a partial-success scenario (e.g. clone OK, checkout fail)
   leaves you debugging in the workspace before Symphony wipes it.
   Defensive checks (`[ -d .git ] && exit 0` early, `git rev-parse
   HEAD` to validate clone, etc.) are worth the lines.

## Tracker

Two kinds:

```yaml
# File-backed (no external deps):
tracker:
  kind: file
  board_root: ./kanban

# Linear-backed:
tracker:
  kind: linear
  project_slug: my-team-project
  api_key: $LINEAR_API_KEY      # $VAR expands from environment
```

`active_states` are columns the orchestrator polls and dispatches from.
`terminal_states` are end columns (the orchestrator stops watching once a
ticket lands here).

### Column legends (`tracker.state_descriptions`)

Optional. Maps a state name to a one-line description that the TUI
renders under each column header. Useful when lanes encode workflow
semantics (Triage / Fix / Self-review / Deploy) that aren't obvious
from the lane name alone.

```yaml
tracker:
  active_states: [Todo, "In Progress", Verify, Document]
  terminal_states: ["Human Review", Done, Blocked, Archive]
  state_descriptions:
    Todo: "Triage: decide if actionable"
    "In Progress": "Plan, implement, and self-critique"
    Verify: "Review, QA, and merge proof"
    Document: "Write back docs; Done unless intervention"
    "Human Review": "Manual intervention or explicit review before Done"
```

Keys are matched case-insensitively. Empty strings and non-string
values are dropped. Omit the field entirely to keep the original
column-name-only header.

## Workspace + concurrency

```yaml
workspace:
  root: ~/symphony_workspaces       # one subdirectory per ticket created here
  reuse_policy: preserve            # default; use refresh for host symlink roots

agent:
  max_concurrent_agents: 1
  max_concurrent_agents_by_state:    # optional per-lane throttle
    Todo: 1
    "In Progress": 1
    "Deploy Ready": 1                # never deploy two things at once
```

## Optional HTTP API

```yaml
server:
  port: 9999    # omit to disable; --port on CLI overrides
```

When unset, the orchestrator runs without an HTTP server and you can
observe via stderr logs, the TUI, or the `WORKFLOW-PROGRESS.md` mirror
(below).

## Progress mirror (`WORKFLOW-PROGRESS.md`)

Headless invocations (`symphony ./WORKFLOW.md` without `tui`) auto-write
a Markdown snapshot of the Kanban board next to your workflow file every
tick and on every state change. It is the lowest-friction way to follow
along without a TTY or HTTP server.

```yaml
progress:
  enabled: true                     # default true; CLI --no-progress-md wins
  path: docs/STATUS.md              # default: WORKFLOW-PROGRESS.md beside WORKFLOW.md
  max_transitions: 20               # how many recent state changes to keep
```

CLI overrides:

```bash
symphony ./WORKFLOW.md --no-progress-md           # disable
symphony ./WORKFLOW.md --progress-md-path docs/STATUS.md
```

Symphony rewrites the file atomically — treat it as read-only output.

## TUI display tweaks

```yaml
tui:
  language: en               # `en` (default) or `ko`. Aliases like `Korean` /
                             # `ko-KR` also resolve. Unknown → English.
```

### `language`

Only TUI chrome (column placeholder, header/footer field labels, card
meta verbs `turn` / `retry #` / `blocked by`) is localized. Tracker
state names, ticket titles, and `tracker.state_descriptions` come from
user data and stay as authored.

Per-key fallback to English is silent — adding a new locale never
crashes the TUI on missing keys, but a missing translation surfaces as
the literal key string (e.g. `card.turn`) so the gap is obvious in the
running board.

The `SYMPHONY_LANG` environment variable overrides `tui.language` for the
session, so a single operator can flip locale without committing a
config change others would inherit:

```bash
SYMPHONY_LANG=ko symphony tui ./WORKFLOW.md
```

Per-lane scrolling, mouse wheel, focus traversal, and ticket-detail
modals are handled by the Textual framework — there is nothing to
configure for them.

## Notifications (Slack)

Opt-in. When the orchestrator successfully writes a state transition to
the tracker, it can post a one-line message to a Slack channel via an
incoming-webhook URL. Omit the block entirely and nothing is sent — the
feature stays dormant.

```yaml
notifications:
  slack:
    webhook_url: $SLACK_WEBHOOK_URL    # required; $VAR resolution at load time
    enabled: true                       # default true when webhook_url is set
    notify_on_states: []                # empty = every transition
    templates:                          # optional per-target-state override
      Done: "✅ ${identifier} ${title}"
      Blocked: "🚧 ${identifier} blocked — ${title}"
    username: Symphony
    icon_emoji: ":robot_face:"
    channel: ""                         # optional override; webhook default usually wins
    timeout_ms: 5000
```

Placeholders inside templates use `string.Template`:
`${identifier}` `${title}` `${prev_state}` `${next_state}` `${workflow}`
`${reason}`. Unknown keys render literally (safe_substitute) — they never
raise.

Default behaviour when `notify_on_states` is empty is to ping on every
tracker state transition. Populate it (case-insensitive) to subscribe a
PM-friendly subset, e.g. `["Done", "Blocked"]`.

Failure modes:
- Missing webhook → silent disable (treated as opt-out, not error).
- Non-2xx response → logged `slack_notify_non_2xx`, the transition still
  succeeds; the next event tries again.
- Network error → logged `slack_notify_network_error`, no retry.

This boundary is deliberate: Slack is a side channel; correctness of the
tracker write must not depend on it.

### Requested notification setup

When the operator requests Slack notifications, obtain the webhook environment reference and the states to publish. Keep posting within that authorization. For Done-only events set `notify_on_states: [Done]`; omit the block when notifications are not requested.

## Product Preview

`preview:` adds a one-click local product launcher to the admin UI. It always
checks out the exact `agent.auto_merge_target_branch` commit into a
preview-owned detached worktree; it never runs from the host checkout or a
ticket workspace.

In the hub, Product Preview needs no cross-project routing: every registered
project runs an independent service from its own `WORKFLOW.md`, so preview
naturally resolves that workflow's Git repository and target branch.

```yaml
preview:
  enabled: true
  cwd: todo-app
  command: python3 -m http.server ${PORT} --bind ${HOST}
  health_path: /
  url_path: /
  startup_timeout_ms: 10000
  release_ticket: SMA-32
  acceptance:
    - All acceptance scenarios pass
    - Browser console is clean
    - README and screenshot evidence exist
```

The command is trusted operator configuration, parsed with `shlex`, and
started without a shell. `${PORT}` and `${HOST}` are the only managed launch
placeholders; `PORT`, `HOST`, and `SYMPHONY_PREVIEW_SHA` are also exported.
When `command` is configured, Preview is enabled by default; set
`enabled: false` to keep the launch recipe checked in without allowing it to
run. Omitting the whole `preview:` block remains valid and leaves Preview
unconfigured.
Symphony asks the operating system for a currently free loopback port for each
launch. Stop and restart terminate only the process group owned by that Project
service; Symphony never kills an unrelated listener to reclaim a port. A rare
race in which another process takes the selected port fails safely, and the
next launch selects a new port.
`cwd` must be relative and remain inside the clean checkout. Health and product
paths must begin with `/`. Health checks accept only successful or redirect
responses and are refreshed while the preview is running. Start and restart
are rejected until the configured release ticket is exactly `Done`. Preview
process-control endpoints are available only when Symphony itself is bound to
loopback. Restart stops the current process, removes its checkout, resolves the
newest target-branch SHA, and relaunches. Stop and Symphony shutdown terminate
the process group and remove the managed checkout.
