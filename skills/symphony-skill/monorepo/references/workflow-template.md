# WORKFLOW.md template

Replace placeholders `<...>` with your values. One file per service you want orchestrated.

```yaml
---
tracker:
  kind: file
  board_root: ./.symphony/kanban
  active_states: [Todo, "In Progress", Verify, Document]
  terminal_states: [Closed, Cancelled, Canceled, Duplicate, Done, Archive, Blocked]
  archive_state: Archive
  archive_after_days: 30
  state_descriptions:
    Todo: "Triage; route to In Progress"
    "In Progress": "Plan, build, and self-critique"
    Verify: "Review, QA, and merge proof"
    Document: "Document changes, distill learnings, append to docs/"
    Done: "As-Is -> To-Be report"
    Archive: "Auto-archived after 30 days idle"

polling:
  interval_ms: 30000

workspace:
  root: ./.symphony/workspaces

# Optional: HTTP API alongside TUI
server:
  port: 8765

hooks:
  after_create: |
    set -e
    ISSUE_ID="$(basename "$PWD")"
    SERVICE_DIR="$SYMPHONY_WORKFLOW_DIR/<service-subdir>"
    BRANCH="<branch-prefix>/$ISSUE_ID"
    BASE_REF="origin/<base-branch>"

    case "$ISSUE_ID" in
      <protected-branch-1>|<protected-branch-2>)
        echo "[symphony] ISSUE_ID '$ISSUE_ID' collides with a protected branch — refusing." >&2
        exit 1
        ;;
    esac

    git -C "$SERVICE_DIR" fetch origin
    [ -e "$PWD/.git" ] && exit 0

    if git -C "$SERVICE_DIR" worktree list --porcelain | grep -qE "^branch refs/heads/${BRANCH}$"; then
      echo "[symphony] ${BRANCH} occupied — skip workspace creation" >&2
      exit 0
    fi

    if git -C "$SERVICE_DIR" show-ref --verify --quiet "refs/heads/${BRANCH}"; then
      git -C "$SERVICE_DIR" worktree add "$PWD" "${BRANCH}"
    else
      git -C "$SERVICE_DIR" worktree add "$PWD" -b "${BRANCH}" "$BASE_REF"
    fi

  before_run: |
    git worktree list | awk '/\[(<protected-branch-1>|<protected-branch-2>)\]/ {print "[symphony WARN] protected branch occupied - " $0 > "/dev/stderr"}' || true
    git status --porcelain || true

  after_run: |
    git worktree list | awk '/\[(<protected-branch-1>|<protected-branch-2>)\]/ {print "[symphony WARN] protected branch occupied - " $0 > "/dev/stderr"}' || true
    echo "run finished at $(date)"

prompts:
  base: ./.symphony/prompts/base.md
  stages:
    Todo: ./.symphony/prompts/stages/todo.md
    "In Progress": ./.symphony/prompts/stages/in-progress.md
    Verify: ./.symphony/prompts/stages/verify.md
    Document: ./.symphony/prompts/stages/document.md
    Done: ./.symphony/prompts/stages/done.md

agent:
  kind: claude         # or codex / gemini / pi
  max_concurrent_agents: 2
  max_turns: 40
  max_retry_backoff_ms: 300000
  auto_commit_on_done: false

claude:
  command: >
    claude -p --output-format stream-json --verbose
    --dangerously-skip-permissions
    --disable-slash-commands
    --setting-sources project
    --add-dir "$SYMPHONY_WORKFLOW_DIR"
  resume_across_turns: true
  turn_timeout_ms: 3600000
  read_timeout_ms: 30000
  stall_timeout_ms: 300000

tui:
  language: en
---

Service: **<svc-name>** (`<service-subdir>`). Base branch: `<base-branch>`. Branch prefix: `<branch-prefix>/`.
Build gate (Verify stage): `<build-command>` (e.g. `./gradlew :build -x test` or `npm run build`).
```

## Placeholders to fill

| Placeholder | Example |
|-------------|---------|
| `<service-subdir>` | `services/api-gateway` |
| `<branch-prefix>` | `fix` or `feat` or `team-feat` |
| `<base-branch>` | `main`, `develop`, `release/x.y` |
| `<protected-branch-1..N>` | `main`, `develop`, `release` — never let a ticket id match these |
| `<build-command>` | service-specific build/test command |

## After authoring

```bash
symphony doctor WORKFLOW.<svc>.md   # validates schema + hook env
symphony --tui WORKFLOW.<svc>.md    # TUI + HTTP API (if server.port set)
```
