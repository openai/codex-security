---
tracker:
  kind: file
  board_root: ./kanban
  active_states: [Todo, "In Progress", Verify, Document]
  terminal_states: ["Human Review", Done, Blocked, Archive]
  # Auto-archive sweep — terminal-state issues whose `updated_at` is older
  # than `archive_after_days` move to `archive_state` on each poll tick.
  # Set `archive_after_days: 0` to disable the sweep (TUI `a` hotkey still
  # works). 30 days is a safe default.
  archive_state: Archive
  archive_after_days: 30
  # Optional one-line legend rendered under each TUI column header.
  state_descriptions:
    Todo: "Triage; route to In Progress"
    "In Progress": "Plan + TDD implementation + self-critique"
    Verify: "Review + QA + Merge Gate"
    Document: "Docs + wiki write-back; Done unless intervention"
    "Human Review": "Manual intervention or explicit review before Done"
    Done: "Verified complete"
    Archive: "Auto-archived after 30 days idle"

polling:
  interval_ms: 30000

# Wiki integrity sweep — see `symphony wiki-sweep --help`. The orchestrator
# runs the sweep automatically after every Nth `Done` transition. Set
# `sweep_every_n: 0` to disable; the manual CLI still works either way.
wiki:
  sweep_every_n: 10
  root: ./docs/llm-wiki

workspace:
  root: ~/symphony_workspaces/codex-security
  # Re-run after_create when reusing an existing ticket workspace. Use this
  # for workflows whose after_create installs host-board symlinks that
  # must stay fresh for state transitions to be visible to Symphony.
  reuse_policy: refresh

hooks:
  # Default: each ticket gets its own git worktree of the host repo on a
  # symphony/<ID> branch. Product changes and docs/ artefacts stay on that
  # branch; Symphony merges it back with an explicit --no-ff merge commit
  # in Verify before Document closes as Done or parks for Human Review.
  #
  # If your code lives in a *different* remote than the WORKFLOW.md repo,
  # replace the worktree commands with `git clone <remote> .` instead.
  # Body extracted to scripts/symphony-setup-worktree.sh — see C4 in
  # docs/improvements/workflow-v0.5.2.md. The script provisions the
  # `symphony/<ID>` worktree, records basesha/basebranch/mergetargetbranch,
  # symlinks (or Windows-junctions) `kanban/` back to the host so
  # FileBoardTracker sees state transitions, and primes a `.venv` when
  # `.[dev]` is installable from the host repo.
  after_create: |
    bash "$SYMPHONY_WORKFLOW_DIR/scripts/symphony-setup-worktree.sh"
  before_run: |
    # NEVER `git reset --hard` inside a worktree — it discards in-progress
    # work between turns. Just refresh remotes; let the agent decide if/when
    # to rebase.
    set -uo pipefail
    HOST_REPO="${SYMPHONY_WORKFLOW_DIR:?SYMPHONY_WORKFLOW_DIR not set}"
    for dir in ${SYMPHONY_BOARD_ROOT_NAME:-kanban}; do
      source="$HOST_REPO/$dir"
      target="$PWD/$dir"
      [ -e "$source" ] || continue
      if [ ! -L "$target" ] && [ "${OS:-}" != "Windows_NT" ]; then
        echo "FAIL: workspace $dir must be a symlink to $source; got non-symlink $target" >&2
        exit 42
      fi
      if [ -L "$target" ] && [ "$(readlink "$target")" != "$source" ]; then
        echo "FAIL: workspace $dir points to $(readlink "$target"), expected $source" >&2
        exit 42
      fi
    done
    git fetch origin --quiet || true
  after_run: |
    # Per-turn commit-or-amend. The branch stays at the same number of
    # commits across turns (amends in place when HEAD is already a `wip:`
    # commit), but every completed turn is durably written to .git/objects
    # so even a hard crash (SIGKILL, host reboot) won't lose work. The
    # orchestrator squashes everything into a single `<ID>: <title>` commit
    # on exit — see auto_commit_on_done.
    set -uo pipefail
    git add -A -- . ':(exclude)kanban' ':(exclude).symphony' 2>/dev/null || true
    if git diff --cached --quiet 2>/dev/null; then
      echo "run finished at $(date) (no changes)"
      exit 0
    fi
    # Classify the staged diff so the wip subject carries machine-readable
    # markers. `[no-test]` = production code changed with no paired test
    # file in the same diff (workflow-v0.5.2 § B1 — review.md promotes it
    # to a HIGH finding). `[scope-expand]` = a rewind dispatch (set by the
    # orchestrator when SYMPHONY_REWIND_SCOPE is exported) but the diff
    # touched a file outside the parsed scope list (workflow-v0.5.2 § A2).
    # Both markers can stack.
    STAGED_FILES="$(git diff --cached --name-only 2>/dev/null || true)"
    PROD_CHANGED=0
    TESTS_CHANGED=0
    SCOPE_EXPAND=0
    SCOPE_FILES=""
    if [ -n "${SYMPHONY_REWIND_SCOPE:-}" ]; then
      SCOPE_FILES="$(printf '%s' "$SYMPHONY_REWIND_SCOPE" \
        | tr ',' '\n' \
        | sed -n 's/.*"file"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"
    fi
    NL=$(printf '\nx'); NL=${NL%x}
    OLDIFS="$IFS"
    IFS="$NL"
    for f in $STAGED_FILES; do
      [ -n "$f" ] || continue
      case "$f" in
        tests/*|*_test.py|*.test.ts|*.test.tsx|*_test.go)
          TESTS_CHANGED=1
          ;;
      esac
      case "$f" in
        tests/*|docs/*|kanban/*|.symphony/*|*.md|LICENSE|LICENSE.*|NOTICE|CHANGELOG*|README*|AGENTS.md|GEMINI.md)
          : # carve-out: docs/license/wiki edits never count as production change
          ;;
        *)
          PROD_CHANGED=1
          ;;
      esac
      if [ -n "$SCOPE_FILES" ] && [ "$SCOPE_EXPAND" = 0 ]; then
        in_scope=0
        for s in $SCOPE_FILES; do
          if [ "$f" = "$s" ]; then
            in_scope=1
            break
          fi
        done
        if [ "$in_scope" = 0 ]; then
          SCOPE_EXPAND=1
        fi
      fi
    done
    IFS="$OLDIFS"
    PREFIX=""
    if [ "$PROD_CHANGED" = 1 ] && [ "$TESTS_CHANGED" = 0 ]; then
      PREFIX="${PREFIX}[no-test]"
    fi
    if [ -n "${SYMPHONY_REWIND_SCOPE:-}" ] && [ "$SCOPE_EXPAND" = 1 ]; then
      PREFIX="${PREFIX}[scope-expand]"
    fi
    # Honors any pre-commit hooks in the host repo — if they fail, this
    # turn's snapshot fails and the next turn picks up where files are.
    MSG="$(sed -n '1{s/^[[:space:]]*//;s/[[:space:]]*$//;p;q;}' .symphony/commit-message.txt 2>/dev/null || true)"
    [ -n "$MSG" ] || MSG="turn $(date -u +%FT%TZ)"
    case "$MSG" in wip:*) COMMIT_MSG="$MSG" ;; *) COMMIT_MSG="wip: $MSG" ;; esac
    LAST="$(git log -1 --format=%s 2>/dev/null || echo "")"
    # On amend, preserve any markers the previous turn already set so a
    # later test-passing turn doesn't drop the historical `[no-test]`.
    # Markers are sticky within a wip subject.
    PRIOR_PREFIX=""
    case "$LAST" in
      *"[no-test]"*) PRIOR_PREFIX="${PRIOR_PREFIX}[no-test]" ;;
    esac
    case "$LAST" in
      *"[scope-expand]"*) PRIOR_PREFIX="${PRIOR_PREFIX}[scope-expand]" ;;
    esac
    MERGED_PREFIX=""
    case "$PRIOR_PREFIX$PREFIX" in
      *"[no-test]"*) MERGED_PREFIX="${MERGED_PREFIX}[no-test]" ;;
    esac
    case "$PRIOR_PREFIX$PREFIX" in
      *"[scope-expand]"*) MERGED_PREFIX="${MERGED_PREFIX}[scope-expand]" ;;
    esac
    if [ -n "$MERGED_PREFIX" ]; then
      COMMIT_MSG="${MERGED_PREFIX} ${COMMIT_MSG}"
    fi
    if [ "${LAST#wip:}" != "$LAST" ]; then
      git -c user.email=symphony@local -c user.name=symphony \
          commit --amend -m "$COMMIT_MSG" >/dev/null 2>&1 || true
    else
      git -c user.email=symphony@local -c user.name=symphony \
          commit -m "$COMMIT_MSG" >/dev/null 2>&1 || true
    fi
    echo "run finished at $(date)"
  before_remove: |
    # Detach the worktree before Symphony rmtree's the dir, otherwise
    # `.git/worktrees/<ID>` lingers until `git worktree prune`. By this
    # point the orchestrator has already auto-committed any leftover
    # changes (see agent.auto_commit_on_done).
    set -uo pipefail
    HOST_REPO="${SYMPHONY_WORKFLOW_DIR:?}"
    WORKTREE_PATH="$PWD"
    ISSUE_ID="${SYMPHONY_ISSUE_ID:-$(basename "$WORKTREE_PATH")}"
    for dir in ${SYMPHONY_BOARD_ROOT_NAME:-kanban}; do
      git -C "$HOST_REPO" update-index --no-skip-worktree -- "$dir/$ISSUE_ID.md" 2>/dev/null || true
    done
    git -C "$HOST_REPO" worktree remove --force "$WORKTREE_PATH" 2>/dev/null || true

agent:
  kind: claude         # codex | claude | gemini | agy | kiro | opencode | pi | prime-agent
  # Backends to switch to, in order, when a worker exits on a quota /
  # usage-limit error ("usage limit", "insufficient_quota", "billing"…).
  # Transient rate limits (429) still retry on the same backend. Symphony
  # pins the next untried kind onto the ticket (`agent.kind` frontmatter),
  # appends `## Backend Fallback`, and retries instead of pausing for an
  # operator. Empty list keeps the pause. File boards only.
  fallback_kinds: []
  # Optional per-state backend routing: cheap/fast agents on light lanes,
  # the default `kind` everywhere else. Precedence per dispatch:
  # per-ticket `agent_kind` frontmatter pin > stage_kinds > kind.
  # stage_kinds:
  #   Todo: gemini
  #   Document: gemini
  max_concurrent_agents: 1
  # This is the per-attempt execution cap. In prompt templates,
  # {{ turn_number }}/{{ max_turns }} reports the ticket lifetime position/cap.
  max_turns: 100
  # Hard per-ticket budget across continuation attempts. Prevents an
  # active-state ticket from restarting forever and wasting tokens.
  max_total_turns: 200
  # Continue interrupted work from the latest completed turn after confirmed
  # process cleanup. Set false to force a fresh agent session after restart.
  crash_continuation: true
  max_total_tokens: 100000000
  max_total_tokens_by_state:
    "In Progress": 500000000
    Verify: 500000000
  # Per-lane stall budget (ms), falling back to the resolved backend's
  # `stall_timeout_ms`. Heavy lanes (a Verify that runs a full suite) go quiet
  # far longer than light ones; widen just that lane instead of every backend.
  # stall_timeout_ms_by_state:
  #   Verify: 900000
  budget_exhausted_state: Blocked
  # Soft cap for Verify/Document rewinds back into In Progress. Set 0 to disable.
  max_attempts: 3
  # Cap on re-dispatching a ticket that already reached Done (deep preset:
  # Verify RED / QA BLOCKED reopen a merged Build slice; each reopen is a
  # fresh run, so max_attempts never sees it). Past the cap Symphony
  # appends `## Reopen Budget` and parks the ticket in Blocked; a
  # `## Reopen Approved` section on the ticket buys one more cycle.
  # Set 0 to disable.
  max_reopens: 3
  # Mechanical evidence floor (orchestrator/contracts.py):
  #   auto (default) — enforce when the board is a shipped preset: every
  #                    active lane is a default-preset lane (Todo / In
  #                    Progress / Verify / Document), or the lanes are exactly
  #                    the deep preset (vault-file + verdict-line contracts).
  #                    Renaming a lane therefore turns it OFF — logged as
  #                    `stage_contracts_disabled` and reported by
  #                    `symphony doctor`, never silent.
  #   on             — enforce the default contract set whatever the lanes
  #                    are called.
  #   off            — never enforce; the stage prompts are the only gate.
  stage_contracts: auto
  # Route obvious Todo tickets with Acceptance Criteria to In Progress without
  # spending a model turn. Bug/blocked/ambiguous tickets still run Todo.
  auto_triage_actionable_todo: true
  max_concurrent_agents_by_state:
    Todo: 1
    "In Progress": 1
    Verify: 1
    Document: 1
  # Snapshot the workspace into one git commit when a ticket reaches Done.
  # Reuses any enclosing git repo; otherwise runs `git init` first. Set to
  # false to opt out (e.g. workspace is a real repo you don't want touched).
  auto_commit_on_done: true
  # Merge policy for the Verify -> Document gate. Verify must merge the
  # `symphony/<ID>` feature branch into the target branch before setting
  # Document. A human later confirms Done from the TUI (`c`) or board viewer
  # button. kanban/ is a host-owned board link, so if it appears in the
  # feature-branch diff the merge is blocked as leaked workspace plumbing.
  # docs/ is intentionally branch-local and merges normally. The post-Done
  # auto-merge remains a best-effort fallback for older prompts.
  auto_merge_on_done: true
  # Publish and verify the target upstream after the local --no-ff merge.
  # Set false for a local-only run; no git push or git ls-remote is attempted.
  auto_merge_push_target: true
  # Branch/ref used as the start point for new `symphony/<ID>` feature
  # branches. Empty string = current host branch. The board viewer can
  # update this from its real git branch dropdown.
  feature_base_branch: ""
  # Branch to merge into after Document. Empty string = same as feature base
  # branch/current host branch. The board viewer can update this too.
  auto_merge_target_branch: ""
  auto_merge_exclude_paths:
    - kanban

codex:
  command: codex app-server
  model: gpt-5.5
  reasoning_effort: high
  approval_policy: never
  # `workspace-write` is the safe default. When `after_create` symlinks
  # host repo dirs (kanban, prompt, ...) into the workspace, symphony's codex
  # backend auto-injects `-c sandbox_workspace_write.writable_roots=[...]`
  # for direct `codex ...` commands and exports the resolved targets via
  # `$SYMPHONY_CODEX_WRITABLE_ROOTS` (os.pathsep-joined) for wrapper
  # scripts to forward themselves. The tagged turn policy retains workspace
  # confinement while allowing package-registry downloads; use the string
  # shorthand `workspace-write` for offline-only workers. Reserve
  # `danger-full-access` for a proven OS-capability blocker.
  thread_sandbox: workspace-write
  turn_sandbox_policy: {type: workspaceWrite, networkAccess: true}

claude:
  # `--add-dir "$SYMPHONY_WORKFLOW_DIR/kanban"` extends Claude
  # Code's write scope to the host directories that after_create
  # junctioned into the worktree. Without these, the agent silently
  # fails to flip ticket state to Done because the resolved path lands
  # outside its cwd, and Symphony's tracker keeps re-dispatching it.
  # `--permission-mode acceptEdits` is also required for the CLI-driven lanes
  # (`symphony board new/update`): a mode that gates every Bash call leaves
  # the agent unable to run the tool its prompt mandates.
  command: 'claude -p --output-format stream-json --verbose --permission-mode acceptEdits --add-dir "$SYMPHONY_WORKFLOW_DIR/kanban"'

gemini:
  # `gemini -p` (no argument) prints help in Gemini CLI 0.39+; pass `""`
  # so the prompt comes from stdin. Symphony appends `--yolo` for unattended
  # worker runs and keeps its own local session id.
  command: 'gemini -p ""'
  resume_across_turns: true

agy:
  # Antigravity CLI (`agy`) receives the stdin prompt through `--print "$(cat)"`.
  # Symphony appends `--dangerously-skip-permissions` and, on continuation turns,
  # `--continue` when resume_across_turns is true.
  command: agy --print "$(cat)"
  resume_across_turns: true

kiro:
  # Kiro headless mode accepts KIRO_API_KEY or a confirmed `kiro-cli login`.
  # Kiro does not read piped stdin as the first message, so this shell bridge
  # passes Symphony's rendered prompt as the required positional chat input.
  command: 'kiro-cli chat --no-interactive --trust-all-tools "$(cat)"'
  resume_across_turns: true

opencode:
  # `opencode run [message..]` is OpenCode's documented scripting path.
  # Symphony appends the prompt as a shell-quoted message argument and adds
  # `--session <id>` on continuation turns after OpenCode reports a session id.
  command: opencode run --format json --auto
  resume_across_turns: true

pi:
  # `pi --mode json` emits JSONL events; stdin carries the prompt.
  # Auth: sign in once with `pi` → `/login` (OAuth). Credentials cached at
  # `~/.pi/agent/auth.json` are inherited automatically.
  command: 'pi --mode json -p ""'

prime_agent:
  # Prime Agent emits the same JSONL protocol and uses `--resume <id>` on
  # continuation turns. Authenticate with `prime-agent` → `/login` or a
  # provider API key; credentials are cached at `~/.prime/agent/auth.json`.
  command: 'prime-agent -p --mode json'
  resume_across_turns: true

server:
  port: 9999            # optional JSON API; the primary UI is `symphony tui`

# Optional one-click Product Preview in the admin web UI. Tailor and uncomment
# this recipe for the product; a configured command defaults to enabled, and
# `enabled: false` opts out. Commands are trusted WORKFLOW config, executed
# argv-only in a clean checkout of the merge target. The API cannot override
# command, cwd, branch, or port; preview stays loopback.
# preview:
#   cwd: web
#   command: npm run preview -- --host ${HOST} --port ${PORT}
#   health_path: /
#   url_path: /
#   startup_timeout_ms: 30000
#   release_ticket: RELEASE-001
#   acceptance:
#     - Final acceptance suite passes
#     - Release evidence is attached

tui:
  language: en               # `en` (default) or `ko`. SYMPHONY_LANG env overrides.
                             # Also drives artefact language: every prompt is
                             # prefixed with a one-line directive so kanban
                             # comments and docs/<id>/<stage>/*.md come back in
                             # the chosen language. `{{ language }}` is also
                             # exposed to this template for `{% if %}` branches.

prompts:
  base: ./docs/symphony-prompts/file/base.md
  stages:
    Todo: ./docs/symphony-prompts/file/stages/todo.md
    "In Progress": ./docs/symphony-prompts/file/stages/in-progress.md
    Verify: ./docs/symphony-prompts/file/stages/verify.md
    Document: ./docs/symphony-prompts/file/stages/document.md
    Done: ./docs/symphony-prompts/file/stages/done.md

---

This workflow uses stage-specific prompt files configured under `prompts`.
Customize `docs/symphony-prompts/file/` to change the agent instructions.
If the `prompts` block is removed, Symphony falls back to this short legacy body.

You are working on {{ issue.identifier }}: {{ issue.title }}.
Current state: {{ issue.state }}.
Follow the board state instructions configured for this workflow.
