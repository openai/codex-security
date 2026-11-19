#!/usr/bin/env bash
# Symphony monorepo bootstrap (idempotent).
#
# Required env:
#   SYMPHONY_HOME   absolute path to this oh-my-symphony clone
#   WORKSPACE_ROOT  absolute path to the target monorepo
#
# What it does:
#   1) Creates $WORKSPACE_ROOT/.symphony/{kanban,workspaces,prompts,logs}/
#   2) Copies upstream 4-stage prompts from $SYMPHONY_HOME/docs/symphony-prompts/file/
#   3) Appends .symphony/ to $WORKSPACE_ROOT/.gitignore if missing
#   4) Registers bidirectional permissions.additionalDirectories
#      in both .claude/settings.local.json files (needs jq)
#   5) Symlinks the symphony-skill router into $WORKSPACE_ROOT/.claude/skills/

set -euo pipefail

: "${SYMPHONY_HOME:?must export SYMPHONY_HOME=/path/to/oh-my-symphony}"
: "${WORKSPACE_ROOT:?must export WORKSPACE_ROOT=/path/to/your/monorepo}"

if [[ ! -d "$SYMPHONY_HOME" ]]; then
  echo "[error] SYMPHONY_HOME not a directory: $SYMPHONY_HOME" >&2
  exit 1
fi
if [[ ! -d "$WORKSPACE_ROOT/.git" ]]; then
  echo "[error] WORKSPACE_ROOT is not a git repo: $WORKSPACE_ROOT" >&2
  exit 1
fi

ABS_SYMPHONY_HOME="$(cd "$SYMPHONY_HOME" && pwd)"
ABS_WORKSPACE_ROOT="$(cd "$WORKSPACE_ROOT" && pwd)"

# 1) skeleton
mkdir -p "$ABS_WORKSPACE_ROOT/.symphony/kanban"
mkdir -p "$ABS_WORKSPACE_ROOT/.symphony/workspaces"
mkdir -p "$ABS_WORKSPACE_ROOT/.symphony/logs"
mkdir -p "$ABS_WORKSPACE_ROOT/.symphony/prompts/stages"
echo "[ok] created .symphony/ skeleton in $ABS_WORKSPACE_ROOT"

# 2) upstream prompts
SRC_PROMPTS="$ABS_SYMPHONY_HOME/docs/symphony-prompts/file"
if [[ -d "$SRC_PROMPTS" ]]; then
  cp -Rf "$SRC_PROMPTS/." "$ABS_WORKSPACE_ROOT/.symphony/prompts/"
  echo "[ok] copied upstream 4-stage prompts into .symphony/prompts/"
else
  echo "[warn] upstream prompts not found at $SRC_PROMPTS — skipping prompt copy" >&2
fi

# 3) .gitignore
GITIGNORE="$ABS_WORKSPACE_ROOT/.gitignore"
if [[ -f "$GITIGNORE" ]] && ! grep -qE "^\.symphony/?$" "$GITIGNORE"; then
  printf '\n# Symphony multi-agent\n.symphony/\n' >> "$GITIGNORE"
  echo "[ok] appended .symphony/ to .gitignore"
fi

# 4) bidirectional Claude Code permissions
register_additional_dir() {
  local settings="$1" target="$2"
  if ! command -v jq >/dev/null 2>&1; then
    echo "[warn] jq not found — $settings auto-register skipped. Add manually: \"additionalDirectories\": [\"$target\"]"
    return
  fi
  mkdir -p "$(dirname "$settings")"
  [[ -f "$settings" ]] || echo '{}' > "$settings"
  if jq -e --arg p "$target" '.permissions.additionalDirectories // [] | index($p)' "$settings" >/dev/null; then
    echo "[skip] $target already in $settings"
    return
  fi
  local tmp
  tmp="$(mktemp)"
  jq --arg p "$target" '
    .permissions //= {} |
    .permissions.additionalDirectories //= [] |
    .permissions.additionalDirectories += [$p] |
    .permissions.additionalDirectories |= unique
  ' "$settings" > "$tmp" && mv "$tmp" "$settings"
  echo "[ok] appended $target to $settings"
}

register_additional_dir "$ABS_WORKSPACE_ROOT/.claude/settings.local.json" "$ABS_SYMPHONY_HOME"
register_additional_dir "$ABS_SYMPHONY_HOME/.claude/settings.local.json" "$ABS_WORKSPACE_ROOT"

# 5) symlink the router skill into the workspace
link_skill() {
  local src="$1"
  local name
  name="$(basename "$src")"
  local link="$ABS_WORKSPACE_ROOT/.claude/skills/$name"
  [[ -d "$src" ]] || return 0
  mkdir -p "$(dirname "$link")"
  if [[ -L "$link" ]]; then
    local current
    current="$(readlink "$link")"
    if [[ "$current" == "$src" ]]; then
      echo "[skip] $link already linked to $src"
      return
    fi
    ln -sfn "$src" "$link"
    echo "[ok] re-pointed $link -> $src (was: $current)"
  elif [[ -e "$link" ]]; then
    echo "[warn] $link exists as a regular file/dir — leaving as-is. Remove manually if you want the symlink."
  else
    ln -s "$src" "$link"
    echo "[ok] symlinked $link -> $src"
  fi
}

link_skill "$ABS_SYMPHONY_HOME/skills/symphony-skill"

cat <<EOF

[done] Symphony monorepo bootstrap complete.

Next steps:
  1. Author one WORKFLOW.<service>.md per service (see skills/symphony-skill/monorepo/references/workflow-template.md)
  2. Activate venv:   source $ABS_SYMPHONY_HOME/.venv/bin/activate
  3. Preflight:       symphony doctor $ABS_WORKSPACE_ROOT/WORKFLOW.<svc>.md
  4. First ticket:    symphony board new TICKET-1 "title" --root $ABS_WORKSPACE_ROOT/.symphony/kanban
  5. Run TUI:         symphony tui $ABS_WORKSPACE_ROOT/WORKFLOW.<svc>.md
EOF
