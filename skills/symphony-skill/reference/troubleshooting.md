# Troubleshooting

## Step 1 — run preflight

```bash
symphony doctor ./WORKFLOW.md
```

Catches the most common first-run failures: port collision, missing agent
CLI on `$PATH`, the shipped placeholder clone URL, unwritable workspace,
missing board directory. Exit 0 if green.

## Step 2 — read structured logs

Symphony writes to **stderr only** by default
(`src/symphony/logging.py:48`). Capture it:

```bash
mkdir -p log
symphony tui ./WORKFLOW.md 2>> log/symphony.log
tail -F log/symphony.log
```

## Common failure signatures

| Log line                                 | Meaning                                                  | Fix                                                                                 |
|------------------------------------------|----------------------------------------------------------|-------------------------------------------------------------------------------------|
| `hook_failed hook=after_create rc=128`   | Worktree/clone failed (e.g. `git worktree add` against a non-repo, placeholder URL, or branch already checked out elsewhere) | Confirm `SYMPHONY_WORKFLOW_DIR` is a real git repo; `cd $HOST_REPO && git worktree list` to spot dangling registrations (`git worktree prune` to clean). For clone-mode hooks, replace placeholder repo URL or set `after_create: \|\n  : noop`. If the hook parses ticket frontmatter, see "awk vs sed for YAML values" below |
| `hook_failed hook=after_create rc=1 stderr="rmdir: ... Device or resource busy"` (Windows) | Pre-`worktree add` `rmdir` raced the Windows file indexer | Update to a Symphony build ≥ 2026-05-15 (the shipped hook no longer rmdirs); see `reference/platform-compat.md` |
| `hook_failed hook=after_create rc=128 stderr="missing but already registered worktree"` | Crashed prior attempt left `.git/worktrees/<ID>` registered | The 2026-05-15 hook does `worktree remove --force` + `prune` before `add`; if you're on the old hook, run `git worktree remove --force $WORKTREE_PATH` once and update WORKFLOW.md |
| `hook_failed hook=after_create ... Not a directory` under `.git/symphony-*` | The hook wrote temp files under `.git/...`, but linked worktrees often have `.git` as a file pointing at the real metadata dir | Use `git rev-parse --git-path <name>` for hook scratch files instead of hardcoding `.git/<name>` |
| `hook_failed hook=after_create rc=127 stderr="python3.11: command not found"`            | Hook hardcoded a Python version not installed       | The 2026-05-15 hook walks `python3.11/3.12/3.13/python3/python`; update WORKFLOW.md from the example or accept that the venv step will be skipped |
| `worker_exit reason=error error="module 'os' has no attribute 'WIFEXITED'"` (Windows)   | `_shell.safe_proc_wait` hit POSIX-only `os.WIF*`     | Update to a Symphony build ≥ 2026-05-15 (`safe_proc_wait` now delegates to `proc.wait()` on Windows) |
| `worker_exit reason=error`               | Worker terminated abnormally                             | Read the preceding `hook_failed` event or backend stderr for the actual cause       |
| `outcome=turn_error`                     | Turn ended in error (timeout, agent crash, tool failure) | Inspect backend stderr; for timeouts, raise `<kind>.turn_timeout_ms`                |
| `hook_timeout`                           | Hook exceeded its time budget                            | Shorten the hook or remove blocking commands                                        |
| `hook_after_run_skipped_missing_cwd`     | Workspace was deleted before `after_run` could run       | INFO-level only; usually means the agent or a hook removed its own workspace. Not a bug — ignore unless you depend on `after_run`                                                                 |
| `reconcile_skip_active_worker`           | Reconcile saw a terminal state but the worker is still emitting events; gives the worker `last_event_age_s` < 10 s grace to exit naturally | Informational — prevents races that previously dropped `agent_turn_completed` and wiped workspaces mid-cleanup |
| `agent_compaction phase=start/end`       | Pi backend triggered context compaction (`/compact` or auto when nearing the model's context window) | Informational — a sudden token-count drop on the next turn is now attributable     |
| `agent_internal_retry phase=start/end`   | Pi backend retried an upstream LLM call internally (transient error)                              | Informational — recoverable; if `final_error` is set the turn ultimately failed   |
| `empty_response_loop consecutive_empty_turns=N` with `input_tokens=0` AND `output_tokens=0` every turn | Backend CLI output schema drifted (often after an opencode/gemini upgrade) — Symphony parsed neither text nor tokens, so every turn looks empty | See "Backend CLI update broke response parsing" below; fix the backend extractor, do NOT raise the threshold |
| `worker_exit reason=issue_state_refresh_failed` after a nonblank turn | Worker finished, but Symphony could not re-read the ticket state; malformed file-tracker frontmatter can make the ticket disappear from the board | Run `symphony board ls --workflow ./WORKFLOW.md`, inspect the ticket's YAML frontmatter, and fix indentation/key syntax. The v0.9.3 release auto-heals the common `  updated_at:` top-level-key misindent on read |
| `hook before_run exited 42` with `workspace kanban points to <other-project>/kanban` | A reused workspace path belongs to another Symphony board with the same ticket ID, so host-board symlinks point at the wrong project | Use a project-scoped `workspace.root` such as `~/symphony_workspaces/<project>`, then resume. If the foreign worktree is no longer needed, remove it from its owning repo with `git -C <foreign-repo> worktree remove --force <path>` after checking `git status --short` |
| `OSError [Errno 48]` on startup          | Port already in use                                      | `lsof -ti :9999 \| xargs -r kill`                                                   |
| `workflow_path_missing`                  | `WORKFLOW.md` not at the path you passed                 | Pass an explicit path; default is `./WORKFLOW.md`                                   |
| `dispatch_validation_failed`             | Config invalid for the chosen `agent.kind`               | Check the matching `<kind>:` block in `WORKFLOW.md` (command, timeouts)             |
| TUI exits immediately, no error          | No TTY (running under a non-interactive shell)           | Run from a real terminal, or use `--port 9999` headless mode                        |
| Review reports mass deletes or `120000` symlink entries for host-backed roots such as `kanban/` or `prompt/` | The ticket branch captured host-owned workspace plumbing instead of real code changes | Stop the service, reset the polluted `symphony/<ID>` branch to the last good tree commit, update the file-workflow hooks to hide host symlink roots from Git, then restart |

## Step 3 — inspect runtime state

When triaging, the JSON snapshot is the source of truth:

```bash
curl -s http://127.0.0.1:9999/api/v1/state | jq '.workers'
curl -s http://127.0.0.1:9999/api/v1/<ID>  | jq
```

Useful fields:
- `.running[]` — currently active workers with last_event, tokens, turn_count
- `.retrying[]` — tickets in the retry queue with their last error
- `.counts` — quick header counts
- per-issue: `.recent_events[]` with timestamped event stream

## Common standalone issues

### "TUI started but the screen is blank"

Check whether you launched it under a multiplexer (tmux/screen) — `rich`
sometimes mis-detects color support. Try `TERM=xterm-256color`
`COLORTERM=truecolor symphony tui ./WORKFLOW.md`.

### "Worker keeps retrying"

After hitting `max_turns`, the orchestrator marks the worker for retry.
The retry queue uses exponential backoff capped at `agent.max_retry_backoff_ms`.
If the underlying issue is unfixable (e.g. agent CLI is broken), `mv` the
ticket to `Blocked` to stop the cycle.

### "Review keeps rewinding on workspace symlinks"

The reviewer should inspect the current workspace code. `git diff` is only
a map. If it shows whole-tree deletes or mode `120000` symlink entries for
host-backed roots such as `kanban/` or `prompt/`, that is not a product
code defect; it means the workspace branch accidentally recorded Symphony
plumbing. `docs/` should normally be a real branch-local tree; if it shows
up as a symlink root, the workflow is using a legacy host-linked docs
setup and should be reconsidered before continuing review.

Root causes:
- A file-board `after_create` linked host board/prompt roots into the
  workspace, but did not mark the tracked files `skip-worktree` or add the
  link roots to this worktree's `info/exclude`.
- `after_run` used plain `git add -A`, so it staged the plumbing roots.
- A reused workspace kept stale real directories or stale symlinks because
  `after_create` did not run again.

Recovery:
1. Stop the orchestrator for that board.
2. Find the last good commit where those roots are real trees:
   `git -C <workspace> ls-tree <sha> kanban prompt` should show
   `040000 tree`, not `120000 blob`.
3. In the ticket workspace, clear skip-worktree on those paths if needed,
   remove the bad link entries, then hard-reset to the good commit.
4. Update `WORKFLOW.md`:
   - `workspace.reuse_policy: refresh` for file-board workflows that
     depend on host symlinks/junctions.
   - In `after_create`, use `git rev-parse --git-path` for scratch files,
     mark tracked files under host-backed roots `skip-worktree`, add the
     roots to `info/exclude`, then recreate the links.
   - In `before_run`, assert the roots still point at `$SYMPHONY_WORKFLOW_DIR`.
   - In `after_run`, exclude those roots from `git add -A`.
5. Run `symphony doctor ./WORKFLOW.md`, then restart the service.

After this, a reused workspace refreshes its host links before dispatch,
the agent's card edits still reach the host board, docs remain reviewable
branch deliverables, and Review no longer mistakes workflow plumbing for
code changes.

### "Card is in `Done` but workspace still exists"

By design — workspaces persist for inspection. With the worktree-default
hooks, clean up with `git -C <HOST_REPO> worktree remove --force
~/symphony_workspaces/<ID>` (this removes both the directory and the
`.git/worktrees/<ID>` registration). For clone-mode hooks, plain
`rm -rf ~/symphony_workspaces/<ID>` is enough. The `symphony/<ID>`
branch is left alone either way — delete with `git branch -D` once
you've merged or discarded it.

### "Branch exists but has zero commits — agent's work is gone"

Symptom: `git log symphony/<ID>` shows only the base point, the
worktree is gone, and there's nothing to merge. Almost always one of:

1. **`before_run: git reset --hard origin/<base>`** — wipes whatever the
   agent did on the previous turn. Drop `reset --hard` from `before_run`;
   only `git fetch`. The shipped examples follow this rule.
2. **Per-turn amend hook missing or removed from `after_run`** — without
   it, mid-run progress is uncommitted and a hard-crash before the
   orchestrator's exit cleanup loses everything. Restore the
   commit-or-amend snippet from `WORKFLOW.example.md`.
3. **`auto_commit_on_done: false`** combined with an agent that
   transitioned to a non-Done terminal state (Cancelled, Blocked) — the
   agent had no chance to commit and the orchestrator was told not to.
   Either flip `auto_commit_on_done: true` (the default), or commit
   yourself in `before_remove`.
4. **Pre-commit hook in the host repo rejected the auto-commit** — check
   `log/symphony.log` for `auto_commit_failed` with the hook's stderr.
   Fix the underlying hook violation, or commit manually from a copy of
   the workspace before it's reaped.
5. **Pre-`auto_commit_on_done`-broadening Symphony version** — older
   builds only auto-committed when `state == "Done"`, so non-Done exits
   lost their work. Upgrade.

Recovery for already-lost work: `git fsck --no-reflog --lost-found` lists
dangling commits; if any have a subject mentioning your ticket ID,
`git branch recover-<ID> <sha>`. If `symphony/<ID>` itself still points
at a `wip: turn …` commit (the per-turn amend survived), just rename:
`git -C <host> commit --amend -m "<ID>: <title>"` while checked out
on that branch. If the agent never committed at all, the changes are
unrecoverable — there are no objects in the ODB.

### "Two TUI sessions show different state"

Both read from the JSON snapshot via the same orchestrator instance, but
*you can only have one orchestrator process per board at a time*. Stop one
before starting another, otherwise both will fight for hook locks.

### "after_create exits 128 every retry, same error each time"

If your hook parses ticket frontmatter to compute a clone URL, the
single most common cause is an `awk -F':'` field separator that splits
on every colon. A value like `repo: https://github.com/owner/repo.git`
becomes `$2 = "https"`, which `git clone` rejects with rc=128. The
retries fail identically because the parse is deterministic.

```bash
# Wrong — splits on every colon:
REPO=$(awk -F': *' '/^repo:/ {print $2; exit}' "$TICKET")

# Right — captures everything after the first `: `:
REPO=$(sed -n 's/^repo: *\(.*\)$/\1/p' "$TICKET" | head -1 | tr -d '\r"')
```

See `reference/workflow-config.md` ("Hook authoring rules") for the
full list of related gotchas (CRLF, absolute paths, `set -e`, etc.).

### Linear-tracker specific: "tickets aren't appearing"

- `LINEAR_API_KEY` set?
- `tracker.project_slug` matches the Linear project's URL slug?
- Linear API rate-limited you? Check `rate_limits` in
  `/api/v1/state` — it's mirrored from upstream headers.

### Pi/Claude backend: "turn failed but the reason is opaque"

As of the observability patch, `agent_turn_failed` and `worker_exit reason=turn_error`
carry a `stderr_tail` field with the last 20 lines of the backend CLI's stderr.
That's where the actual reason (auth, network, ratelimit, model error)
lives. Greb the structured log:

```bash
grep agent_turn_failed log/symphony.log | jq -R 'fromjson?'  # if you log JSON
grep -A1 agent_turn_failed log/symphony.log                   # plain k=v
```

The `reason` field also concatenates the stderr blob into the human-readable
failure string, so even a raw `tail -F log/symphony.log` shows it inline.

### Pi backend: "first turn fails immediately, no useful error"

Most common cause: `~/.pi/agent/auth.json` is missing or stale. Without it,
`pi --mode json` exits before emitting any events; Symphony surfaces this
as a generic `turn_error` and retries with the same identical failure.

```bash
symphony doctor ./WORKFLOW.md             # WARNs when the auth file is absent
ls -la ~/.pi/agent/auth.json              # confirm presence + recency
pi                                        # then `/login` to refresh OAuth credentials
```

The cached credentials are inherited automatically by every subprocess
Symphony spawns — you do *not* need to put `PI_API_KEY` (or any provider
env var) into `WORKFLOW.md` or the `pi:` block.

### Pi backend: "agent silent for N seconds, no events in log"

The TUI now grows a yellow `silent Ns` badge on running cards once their
last event is older than 30 s, so visual stalls are immediate. In headless
runs, grep for:

```bash
grep agent_session_started log/symphony.log     # session id minted
grep agent_turn_completed log/symphony.log      # turn finished
```

If `agent_session_started` fired but no `agent_turn_completed` follows for
5+ minutes, pi may be stuck on a long tool call (e.g. a slow fetch, or an
agent-spawned subprocess waiting on stdin). The per-turn budget is
`pi.turn_timeout_ms` (default ~1h). Lower it if you want stuck turns to
fail fast and bounce through retry instead of hanging:

```yaml
pi:
  command: 'pi --mode json -p ""'
  resume_across_turns: true
  turn_timeout_ms: 600000        # 10 min instead of the default 1h
```

### Pi backend: "token totals look 2–4× higher than Claude on the same task"

Not a bug. Pi makes one LLM API call per assistant message within a turn,
and each call's prompt is re-billed (cache reads count at a discount but
still count). A 4-call turn with a 30k-token system prompt reports ~120k
`input_tokens`; the same work on Claude reports ~30k because Claude
aggregates per-turn at the `result` event. Both totals are honest — they
just count at different granularities. Verify with the JSON probe:

```bash
echo "<prompt>" | pi --mode json -p "" 2>/dev/null \
  | jq -c 'select(.type=="message_end") | .message.usage'
# one usage block per LLM call
```

### Backend CLI update broke response parsing: "ticket did real work but got Blocked with `empty_response_loop`"

Recurring class: an agent CLI (opencode, gemini, ...) ships an update that
changes its `--format json` output shape, and Symphony's backend parser — pinned
to the old shape — silently extracts nothing. The ticket keeps doing real work
(commits, file edits), but Symphony sees every turn as empty and the G2
empty-response-loop guard blocks it after 3 turns.

The tell is in the `agent_turn_completed` lines: **`input_tokens=0` AND
`output_tokens=0` on every turn**, with an empty `last_message=`. Input tokens
can't really be zero — the prompt alone is thousands — so a zero means the parser
found no usage at all, and it almost certainly found no response text either
(that is what trips G2: empty `current_turn_message`).

2-minute diagnosis:

```bash
grep -a agent_turn_completed log/symphony.log | tail -5
# input_tokens=0 AND output_tokens=0 every turn = parser mismatch (smoking gun)

# Capture the CLI's REAL output schema. Use the exact command from WORKFLOW.md's
# <kind>: block. opencode buffers all stdout until the turn ends, so give it time:
cd "$(mktemp -d)"
timeout 600 opencode run --format json "reply with the word DONE" | head -c 2000
# See where the assistant text and token usage actually live in the JSON.
```

Then compare against the backend's extractors in
`src/symphony/backends/<kind>.py`: `_response_from_events` / `_extract_text` for
text, `_update_usage_from_events` / `_usage_dicts` for tokens. Recent opencode
(>= 1.x) streams JSONL frames `{"type":"text","sessionID":...,"part":{"type":"text","text":...}}`
and reports tokens on `step_finish.part.tokens`, including nested `cache.read` /
`cache.write`. Older flat-key scans miss both nested paths. Fixed in the
v0.9.3 release: `_text_from_event` reads `part.text` from `type=="text"` frames,
and `_usage_dicts` descends through `part` / `info` usage containers for token
accounting.

Fix pattern: extend the backend's text/usage extractor to the new schema. Do
NOT raise `EMPTY_TURN_LOOP_THRESHOLD` — that only delays the false block and
weakens genuine empty-loop detection for every backend.

Contract for backends: the `EVENT_TURN_COMPLETED` payload must carry the
response under a preview key (`message`) so both the G2 guard and the TUI
preview see it. A backend that returns text only under private keys
(`result` / `response`) reads as a blank turn — see
`docs/dispatch-stability/G2-empty-response-loop.md`.
