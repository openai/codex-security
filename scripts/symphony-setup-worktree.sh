#!/usr/bin/env bash
# Symphony after_create hook — extracted from WORKFLOW.md.
#
# Attach the empty ticket workspace as a git worktree of the host repo on a
# per-ticket `symphony/<ID>` branch, symlink (or junction on Windows) any
# host-owned board roots back into the worktree, and prime a Python venv for
# the agent. Behaviour is identical to the inline hook that previously lived
# inside WORKFLOW.md — see workflow-v0.5.2.md (C4) for the rationale.
#
# Env vars consumed (Symphony injects these before invoking the hook):
#   SYMPHONY_WORKFLOW_DIR        Path to the host repo containing WORKFLOW.md.
#   SYMPHONY_FEATURE_BASE_BRANCH Optional override for the new branch's start point.
#   SYMPHONY_MERGE_TARGET_BRANCH Optional override for the Document-gate merge target.
#   SYMPHONY_BOARD_ROOT_NAME     Board root relative to SYMPHONY_WORKFLOW_DIR
#                                (e.g. `kanban`, `board`). Defaults to `kanban`
#                                for hand-written configs that predate it. A
#                                board that is not linked here leaves the worker
#                                writing a private board copy the orchestrator
#                                never sees.
set -euo pipefail
ISSUE_ID="$(basename "$PWD")"
HOST_REPO="${SYMPHONY_WORKFLOW_DIR:?SYMPHONY_WORKFLOW_DIR not set}"
WORKTREE_PATH="$PWD"
# Prefix mirrors SYMPHONY_BRANCH_PREFIX in src/symphony/workflow/constants.py.
BRANCH="symphony/${ISSUE_ID}"
# Symphony pre-creates the workspace dir; git worktree add refuses to
# populate an existing path, so drop the empty dir first.
cd "$HOST_REPO"
# Linked worktrees expose `.git` as a file; lock their shared admin directory.
COMMON_GIT_DIR="$(cd "$(git rev-parse --git-common-dir)" && pwd -P)"
BASE_BRANCH="$(git symbolic-ref --short HEAD 2>/dev/null || git branch --show-current 2>/dev/null || true)"
FEATURE_BASE_BRANCH="${SYMPHONY_FEATURE_BASE_BRANCH:-${BASE_BRANCH:-}}"
MERGE_TARGET_BRANCH="${SYMPHONY_MERGE_TARGET_BRANCH:-${FEATURE_BASE_BRANCH:-${BASE_BRANCH:-}}}"

_SYMPHONY_WORKTREE_LOCK_DIR=""
_SYMPHONY_WORKTREE_LOCK_FD=""

_symphony_lock_mtime_epoch() {
  if stat -c %Y "$1" >/dev/null 2>&1; then
    stat -c %Y "$1"
  else
    stat -f %m "$1"
  fi
}

_symphony_release_worktree_lock() {
  if [ -n "${_SYMPHONY_WORKTREE_LOCK_DIR:-}" ] && [ -d "$_SYMPHONY_WORKTREE_LOCK_DIR" ]; then
    rm -rf "$_SYMPHONY_WORKTREE_LOCK_DIR"
    _SYMPHONY_WORKTREE_LOCK_DIR=""
  fi
  if [ -n "${_SYMPHONY_WORKTREE_LOCK_FD:-}" ]; then
    flock -u 9 2>/dev/null || true
    exec 9>&-
    _SYMPHONY_WORKTREE_LOCK_FD=""
  fi
}

_symphony_acquire_worktree_lock() {
  local lock_file="$COMMON_GIT_DIR/symphony-worktree.lock"
  local lock_dir="${lock_file}.d"
  local start now mtime
  if command -v flock >/dev/null 2>&1; then
    exec 9>"$lock_file"
    flock 9
    _SYMPHONY_WORKTREE_LOCK_FD="9"
    return
  fi

  start="$(date +%s)"
  while ! mkdir "$lock_dir" 2>/dev/null; do
    now="$(date +%s)"
    if [ -d "$lock_dir" ]; then
      mtime="$(_symphony_lock_mtime_epoch "$lock_dir" 2>/dev/null || printf '%s\n' "$now")"
      case "$mtime" in
        ""|*[!0-9]*) mtime="$now" ;;
      esac
      if [ $((now - mtime)) -gt 300 ]; then
        rm -rf "$lock_dir"
        continue
      fi
    fi
    if [ $((now - start)) -ge 120 ]; then
      echo "after_create: timed out waiting for git worktree lock at $lock_dir" >&2
      exit 1
    fi
    sleep 0.2
  done
  _SYMPHONY_WORKTREE_LOCK_DIR="$lock_dir"
  printf '%s\n' "$$" > "$lock_dir/pid"
}

trap _symphony_release_worktree_lock EXIT

# `git worktree add` (git >= 2.30) tolerates an existing *empty* target
# directory, which is exactly what Symphony pre-creates here. Trying to
# rmdir it first runs straight into Windows file-indexer / AV scans that
# hold a transient handle on the fresh dir and used to trip the
# dispatcher into a retry loop with `Device or resource busy`. Skipping
# the rmdir avoids the race entirely.
#
# A prior crashed attempt may have left `.git/worktrees/<ID>` registered;
# detach it first so the next `add` doesn't fail with
# "missing but already registered" or "already checked out". `remove`
# tolerates a non-existent path (returns non-zero, ignored); `prune`
# mops up any leftover admin files.
_symphony_acquire_worktree_lock
git worktree remove --force "$WORKTREE_PATH" 2>/dev/null || true
git worktree prune 2>/dev/null || true

# A prior worktree may have been reaped after its branch was merged into the
# configured target. Reusing that old tip is unsafe: the next after_run hook
# can amend it into a new parallel history, and the eventual merge sees an
# evidence-only conflict. Refresh only the feature ref when it is already
# contained by the target. `git update-ref`'s expected-old argument makes this
# a compare-and-swap, so a concurrent writer cannot silently overwrite work.
_symphony_refresh_merged_branch() {
  local branch_sha target_sha target_ref attempt branch_after
  # A configured merge target is a local branch name, never a tag, SHA, or
  # revision expression. Resolve only refs/heads/<name> so a tag with the
  # same spelling cannot silently drive a branch refresh.
  case "$MERGE_TARGET_BRANCH" in
    ""|refs/*) return 0 ;;
  esac
  git check-ref-format --branch "$MERGE_TARGET_BRANCH" >/dev/null 2>&1 || return 0
  target_ref="refs/heads/$MERGE_TARGET_BRANCH"
  # Keep the host-side ref update bounded. The lock serializes Symphony's own
  # setup hooks and the expected-old CAS protects against an external branch
  # writer. A target branch may advance after its SHA is captured; the
  # reopened ticket remains at that immutable captured ancestor and the later
  # delivery gate evaluates the new target tip.
  for attempt in 1 2 3; do
    branch_sha="$(git rev-parse --verify --quiet "refs/heads/$BRANCH^{commit}" 2>/dev/null || true)"
    target_sha="$(git rev-parse --verify --quiet "${target_ref}^{commit}" 2>/dev/null || true)"
    [ -n "$branch_sha" ] || return 0
    [ -n "$target_sha" ] || return 0
    [ "$branch_sha" = "$target_sha" ] && return 0
    if ! git merge-base --is-ancestor "$branch_sha" "$target_sha" 2>/dev/null; then
      return 0
    fi
    if ! git update-ref --no-deref "refs/heads/$BRANCH" "$target_sha" "$branch_sha"; then
      if [ "$attempt" -lt 3 ]; then
        continue
      fi
      echo "after_create: failed to refresh already-merged branch $BRANCH; ref changed concurrently" >&2
      exit 1
    fi
    branch_after="$(git rev-parse --verify --quiet "refs/heads/$BRANCH^{commit}" 2>/dev/null || true)"
    if [ "$branch_after" != "$target_sha" ]; then
      echo "after_create: feature branch changed during refresh; refusing to attach $BRANCH" >&2
      exit 1
    fi
    echo "after_create: refreshing already-merged branch $BRANCH $branch_sha -> $target_sha (target $MERGE_TARGET_BRANCH)"
    return 0
  done
}

_symphony_refresh_merged_branch
# Reuse the branch if a prior worktree was reaped without prune.
if git show-ref --verify --quiet "refs/heads/$BRANCH"; then
  git worktree add "$WORKTREE_PATH" "$BRANCH"
elif [ -n "$FEATURE_BASE_BRANCH" ]; then
  git worktree add "$WORKTREE_PATH" -b "$BRANCH" "$FEATURE_BASE_BRANCH"
else
  git worktree add "$WORKTREE_PATH" -b "$BRANCH"
fi
cd "$WORKTREE_PATH"
# Record the fork point so commit_workspace_on_done can `git reset --soft`
# back to it and squash all per-turn work into a single ticket commit.
# Use --worktree so the value is scoped to .git/worktrees/<ID>/config.gitwt;
# writing without the flag leaks into the host repo's shared .git/config
# and corrupts auto_commit for unrelated workspaces nested in the host.
git config extensions.worktreeConfig true
git config --worktree symphony.basesha "$(git rev-parse HEAD)"
git config --worktree symphony.basebranch "${FEATURE_BASE_BRANCH:-${BASE_BRANCH:-}}"
git config --worktree symphony.mergetargetbranch "${MERGE_TARGET_BRANCH:-}"
# Keep the Git-admin lock through host-index updates below. Concurrent ticket
# creation otherwise races on the host index and can leave tracked board files
# visible as dirty even though they are live orchestration state.
# Link shared board directories back to host so agent state changes are
# visible to Symphony's file tracker (which reads host board_root).
#
# Cross-platform: on POSIX use `ln -s`; on Windows Git Bash without
# admin / Developer Mode, `ln -s` silently *copies* the source, leaving
# the worktree's kanban/ as a divergent real directory — the tracker
# never sees the agent's Done transition and dispatches forever. The
# portable fix is a Windows directory junction (`mklink /J`), which
# behaves like a real directory to every tool, works cross-volume, and
# needs no elevation.
_symphony_link_dir() {
  local target="$1" source="$2"
  rm -rf "$target"
  if [ "${OS:-}" = "Windows_NT" ] && command -v cmd.exe >/dev/null 2>&1; then
    # MSYS bash mangles backslashes inside `cmd.exe //c "..."` argument
    # strings (e.g. `\U` in `\Users` becomes garbled), so route through
    # a tiny .bat that takes %1/%2 — bat files receive properly quoted
    # args untouched. Also handles paths containing spaces.
    local target_win source_win bat bat_win
    target_win="$(cygpath -w "$(realpath -m "$target")")"
    source_win="$(cygpath -w "$source")"
    bat="${TEMP:-/tmp}/symphony-link-$$-$RANDOM.bat"
    printf '@echo off\r\nmklink /J %%1 %%2\r\n' > "$bat"
    bat_win="$(cygpath -w "$bat")"
    cmd.exe //c "$bat_win" "$target_win" "$source_win" >/dev/null
    rm -f "$bat"
  else
    ln -s "$source" "$target"
  fi
}
for dir in ${SYMPHONY_BOARD_ROOT_NAME:-kanban}; do
  [ -e "$HOST_REPO/$dir" ] || continue
  tracked_file="$(git rev-parse --git-path "symphony-${dir}-tracked")"
  git ls-files -z -- "$dir" > "$tracked_file" || true
  if [ -s "$tracked_file" ]; then
    xargs -0 git update-index --skip-worktree -- < "$tracked_file" || true
  fi
  # The symlink writes this ticket card into the host checkout, whose main
  # worktree has a separate index. Hide only the active card while its workspace
  # exists; before_remove clears the bit so normal host review is restored.
  # The shared info/exclude entry below already hides new operational cards.
  git -C "$HOST_REPO" ls-files -z -- "$dir/$ISSUE_ID.md" > "$tracked_file" || true
  if [ -s "$tracked_file" ]; then
    xargs -0 git -C "$HOST_REPO" update-index --skip-worktree -- < "$tracked_file" || true
  fi
  rm -f "$tracked_file"
  exclude_file="$(git rev-parse --git-path info/exclude)"
  mkdir -p "$(dirname "$exclude_file")"
  grep -qxF "$dir" "$exclude_file" 2>/dev/null || echo "$dir" >> "$exclude_file"
  _symphony_link_dir "$dir" "$HOST_REPO/$dir"
done
_symphony_release_worktree_lock
# Pick the first available Python interpreter that satisfies pyproject first.
# The package currently requires >=3.12; keep 3.11 only as a last fallback so
# older clones fail in pip with a clear reason instead of skipping venv setup.
PYTHON=""
for candidate in python3.12 python3.13 python3.11 python3 python; do
  if command -v "$candidate" >/dev/null 2>&1; then
    PYTHON="$candidate"; break
  fi
done
if [ -z "$PYTHON" ]; then
  echo "after_create: no python3 on PATH; skipping venv install." >&2
else
  # Hide the worker venv from the worktree's git status so per-turn
  # commit hooks (and `git status` invariants in tests) don't see it.
  exclude_file="$(git rev-parse --git-path info/exclude)"
  mkdir -p "$(dirname "$exclude_file")"
  grep -qxF ".venv" "$exclude_file" 2>/dev/null || echo ".venv" >> "$exclude_file"
  "$PYTHON" -m venv .venv
  # `python -m pip` survives the venv-script path differences between
  # POSIX (`.venv/bin/pip`) and Windows (`.venv/Scripts/pip.exe`).
  .venv/*/python -m pip install --quiet -e '.[dev,browser]' 2>/dev/null \
    || .venv/bin/python -m pip install --quiet -e '.[dev,browser]' 2>/dev/null \
    || .venv/Scripts/python -m pip install --quiet -e '.[dev,browser]' 2>/dev/null \
    || echo "after_create: pip install failed; agent will fall back to host python." >&2
fi
