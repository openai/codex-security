#!/usr/bin/env bash
# bootstrap.sh — Symphony OneShot vault + workflow + intake ticket
#
# Usage:   bash bootstrap.sh "<the user's one-shot prompt>"
# Re-init: FORCE=1 bash bootstrap.sh "<new prompt>"  (clobbers .oneshot/, backs up WORKFLOW.md)
#
# Single-shot init by design. Re-running on an existing .oneshot/ aborts
# unless FORCE=1, because partially-merged state across runs is worse
# than a hard reset.

set -euo pipefail

PROMPT="${1:-}"
FORCE="${FORCE:-0}"
REQUESTED_PORT="${SYMPHONY_ONESHOT_PORT:-9999}"

if [ -z "$PROMPT" ]; then
  echo "usage: bash bootstrap.sh \"<one-shot prompt>\"" >&2
  exit 2
fi

SKILL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(pwd)"

# Stricter repo detection — match the actual symphony package, not any pyproject
if ! { [ -f "$PROJECT_ROOT/src/symphony/cli.py" ] || \
       grep -qE '^name = "(oh-my-)?symphony' "$PROJECT_ROOT/pyproject.toml" 2>/dev/null; }; then
  echo "warn: $PROJECT_ROOT does not look like the oh-my-symphony repo." >&2
  echo "       (no src/symphony/cli.py and pyproject.toml doesn't name 'symphony')" >&2
  echo "       Vault will be created at $PROJECT_ROOT/.oneshot/ anyway." >&2
fi

if ! command -v symphony >/dev/null 2>&1; then
  echo "error: 'symphony' CLI not on PATH." >&2
  echo "       Install: pip install -e \".[dev]\" from the oh-my-symphony repo." >&2
  exit 1
fi

PYTHON_BIN=""
for python_candidate in python3 python; do
  candidate_path="$(command -v "$python_candidate" 2>/dev/null || true)"
  if [ -n "$candidate_path" ] && "$candidate_path" -c 'pass' >/dev/null 2>&1; then
    PYTHON_BIN="$candidate_path"
    break
  fi
done

port_free() {
  [ -n "$PYTHON_BIN" ] || return 1
  "$PYTHON_BIN" - "$1" <<'PY'
import socket
import sys

port = int(sys.argv[1])
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    try:
        sock.bind(("127.0.0.1", port))
    except OSError:
        raise SystemExit(1)
PY
}

pick_free_port() {
  [ -n "$PYTHON_BIN" ] || return 1
  "$PYTHON_BIN" - <<'PY'
import socket

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
}

if [ "$REQUESTED_PORT" = "auto" ]; then
  SYMPHONY_PORT="$(pick_free_port)"
elif port_free "$REQUESTED_PORT"; then
  SYMPHONY_PORT="$REQUESTED_PORT"
elif [ -z "${SYMPHONY_ONESHOT_PORT:-}" ] && [ -n "$PYTHON_BIN" ]; then
  SYMPHONY_PORT="$(pick_free_port)"
  echo "info: port 9999 is occupied; using available port $SYMPHONY_PORT" >&2
else
  echo "error: requested SYMPHONY_ONESHOT_PORT=$REQUESTED_PORT is not available" >&2
  exit 1
fi

if [ -d "$PROJECT_ROOT/.oneshot" ] && [ "$FORCE" != "1" ]; then
  echo "abort: $PROJECT_ROOT/.oneshot already exists." >&2
  echo "       Re-run with FORCE=1 to clobber, or move/remove the dir manually." >&2
  exit 1
fi

# Hard reset under FORCE
if [ "$FORCE" = "1" ] && [ -d "$PROJECT_ROOT/.oneshot" ]; then
  mv "$PROJECT_ROOT/.oneshot" "$PROJECT_ROOT/.oneshot.aborted-$(date +%s)"
fi

# 1. Vault skeleton
mkdir -p "$PROJECT_ROOT/.oneshot/vault/artifacts/screenshots"
mkdir -p "$PROJECT_ROOT/.oneshot/vault/artifacts/test-results"
mkdir -p "$PROJECT_ROOT/log"
mkdir -p "$PROJECT_ROOT/kanban"

# 2. Constitution + raw prompt + project root marker
sed "s|__ONESHOT_PORT__|$SYMPHONY_PORT|g" "$SKILL_DIR/SYSTEM.md" > "$PROJECT_ROOT/.oneshot/SYSTEM.md"
printf "%s\n" "$PROMPT" > "$PROJECT_ROOT/.oneshot/prompt.md"
echo "$PROJECT_ROOT" > "$PROJECT_ROOT/.oneshot/.project_root"

# 3. Empty append-only ledgers + lock files
: > "$PROJECT_ROOT/.oneshot/vault/claims.md"
: > "$PROJECT_ROOT/.oneshot/vault/verification.md"
: > "$PROJECT_ROOT/.oneshot/vault/decisions.log"
: > "$PROJECT_ROOT/.oneshot/vault/.claims.lock"
: > "$PROJECT_ROOT/.oneshot/vault/.verification.lock"

# 4. Placeholder living docs
cat > "$PROJECT_ROOT/.oneshot/vault/brief.md" <<EOF
<!-- Will be filled in by the Brief lane. Do not hand-edit. -->
EOF
cat > "$PROJECT_ROOT/.oneshot/vault/plan.md" <<EOF
<!-- Will be filled in by the Plan lane. Do not hand-edit. -->
EOF
cat > "$PROJECT_ROOT/.oneshot/vault/architecture.md" <<EOF
<!-- Will be filled in by the Plan lane. -->
EOF
cat > "$PROJECT_ROOT/.oneshot/vault/contracts.md" <<EOF
<!-- Will be filled in by the Plan lane. -->
EOF

# 5. WORKFLOW.md — substitute placeholders with the generated local settings
if [ -f "$PROJECT_ROOT/WORKFLOW.md" ]; then
  cp "$PROJECT_ROOT/WORKFLOW.md" "$PROJECT_ROOT/WORKFLOW.md.bak.$(date +%s)"
  echo "info: prior WORKFLOW.md backed up" >&2
fi
# sed -i needs an empty backup ext on macOS; use a temp + mv to be portable
sed \
  -e "s|__ONESHOT_ROOT__|$PROJECT_ROOT|g" \
  -e "s|__ONESHOT_PORT__|$SYMPHONY_PORT|g" \
  "$SKILL_DIR/WORKFLOW.oneshot.md" > "$PROJECT_ROOT/WORKFLOW.md"

# Sanity: make sure substitution actually happened
if grep -qE '__ONESHOT_ROOT__|__ONESHOT_PORT__' "$PROJECT_ROOT/WORKFLOW.md" "$PROJECT_ROOT/.oneshot/SYSTEM.md"; then
  echo "error: OneShot placeholder still present after substitution" >&2
  exit 1
fi

# 6. Initialize kanban board if empty
if [ ! -d "$PROJECT_ROOT/kanban" ] || [ -z "$(ls -A "$PROJECT_ROOT/kanban" 2>/dev/null)" ]; then
  symphony board init "$PROJECT_ROOT/kanban" >/dev/null
fi

# 7. Create the INTAKE ticket directly in the Brief lane (--state defaults to Todo, which isn't an active state)
INTAKE_ID="INTAKE-1"
if [ -f "$PROJECT_ROOT/kanban/${INTAKE_ID}.md" ]; then
  echo "warn: $INTAKE_ID already exists — will not recreate" >&2
else
  symphony board new "$INTAKE_ID" "Symphony OneShot intake — convert prompt to brief" \
    --priority 1 --state Brief \
    --description "Read .oneshot/prompt.md and produce .oneshot/vault/brief.md per the Brief lane prompt in WORKFLOW.md."
fi

# 8. Preflight
echo "------ symphony doctor ------"
if ! symphony doctor "$PROJECT_ROOT/WORKFLOW.md"; then
  echo "doctor reported issues — fix before launching" >&2
  exit 1
fi

cat <<EOF

✓ Symphony OneShot bootstrapped at $PROJECT_ROOT/.oneshot/
✓ WORKFLOW.md installed (any prior one backed up)
✓ INTAKE-1 created in lane: Brief
✓ Project root pinned: $PROJECT_ROOT (also written to .oneshot/.project_root)
✓ Local API port: $SYMPHONY_PORT

Next step:

  # interactive (needs a TTY)
  symphony tui ./WORKFLOW.md

  # headless (recommended when an orchestrator session is driving)
  symphony ./WORKFLOW.md --port $SYMPHONY_PORT 2>> log/symphony.log &

Then poll:
  curl -s http://127.0.0.1:$SYMPHONY_PORT/api/v1/state | jq '.counts'

The loop is done when DELIVER-1 reaches state 'Delivered' AND
.oneshot/vault/delivery.md exists. For browser apps,
.oneshot/vault/artifacts/qa-report.pdf must also exist with the sha256
matching .oneshot/vault/artifacts/qa-report.pdf.sha256.
EOF
