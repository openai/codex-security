#!/usr/bin/env bash
# tui-open.sh — launch Symphony's Textual Kanban TUI in a new terminal window.
#
# Usage:
#   ./tui-open.sh [path/to/WORKFLOW.md]
#
# - Defaults to ./WORKFLOW.md in the script's directory.
# - Prefers the project venv at .venv/bin/symphony; falls back to PATH.
#   `pip install -e .` pulls textual automatically as a runtime dep — if
#   the launcher errors with `ModuleNotFoundError: textual`, your active
#   environment is stale; re-run `pip install -e .` inside .venv.
# - Runs `symphony --tui WORKFLOW.md`, which starts both the orchestrator
#   AND the TUI in a single process (the server port from WORKFLOW.md's
#   `server.port` is also exposed).
# - Quit the TUI with `q` from inside the app (drains workers cleanly) or
#   close the spawned terminal window. Ctrl-C also works.
#
# Platform behaviour:
#   macOS                   -> opens a new iTerm.app window if installed,
#                              otherwise Terminal.app, via a .command launcher
#   Linux + $TERMINAL set   -> spawns $TERMINAL -e ...
#   Linux + DISPLAY         -> tries gnome-terminal, konsole, xterm in order
#   anywhere else           -> runs in current shell (foreground)
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKFLOW="${1:-${SCRIPT_DIR}/WORKFLOW.md}"

if [[ ! -f "${WORKFLOW}" ]]; then
  echo "tui-open: workflow not found: ${WORKFLOW}" >&2
  exit 2
fi

# Resolve WORKFLOW to an absolute path and remember its directory.
# tracker.board_root is a path relative to the working directory, so we
# must launch from the workflow's own directory — not SCRIPT_DIR — or
# external/demo workflows will read the wrong board.
WORKFLOW_ABS="$(cd "$(dirname "${WORKFLOW}")" && pwd)/$(basename "${WORKFLOW}")"
WORKFLOW_DIR="$(dirname "${WORKFLOW_ABS}")"

if [[ -x "${SCRIPT_DIR}/.venv/bin/symphony" ]]; then
  SYMPHONY="${SCRIPT_DIR}/.venv/bin/symphony"
elif command -v symphony >/dev/null 2>&1; then
  SYMPHONY="$(command -v symphony)"
else
  echo "tui-open: 'symphony' not found on PATH and no .venv/bin/symphony" >&2
  echo "tui-open: install with: python3 -m venv .venv && .venv/bin/pip install -e ." >&2
  exit 3
fi

# Detect whether a TUI for this workflow's port is already running. If so,
# focus the user on that window instead of launching a duplicate (which
# would just collide on the port and crash with EADDRINUSE).
PORT="$(awk '
  /^server:/                       { in_server = 1; next }
  in_server && /^[^[:space:]]/     { in_server = 0 }
  in_server && /^[[:space:]]+port:/ { gsub(/[^0-9]/, "", $2); if ($2 != "") { print $2; exit } }
' "${WORKFLOW_ABS}")"
PORT="${PORT:-9999}"

EXISTING_PID=""
if command -v lsof >/dev/null 2>&1; then
  EXISTING_PID="$(lsof -tiTCP:"${PORT}" -sTCP:LISTEN 2>/dev/null | head -n1 || true)"
fi

if [[ -n "${EXISTING_PID}" ]]; then
  EXISTING_CMD="$(ps -o command= -p "${EXISTING_PID}" 2>/dev/null || true)"
  if [[ "${EXISTING_CMD}" == *"--tui"* ]]; then
    echo "tui-open: TUI already running on port ${PORT} (PID ${EXISTING_PID})."
    echo "tui-open: bringing the existing terminal app to the front instead of duplicating."
    case "$(uname -s)" in
      Darwin)
        # Best-effort raise. We can't pinpoint the exact window without
        # tracking window ids, so just bring the most likely terminal app
        # frontmost and let the user pick the right window.
        if [[ -d "/Applications/iTerm.app" ]] || mdfind "kMDItemCFBundleIdentifier == 'com.googlecode.iterm2'" 2>/dev/null | grep -q iTerm; then
          osascript -e 'tell application "iTerm" to activate' 2>/dev/null || true
        else
          osascript -e 'tell application "Terminal" to activate' 2>/dev/null || true
        fi
        ;;
      *)
        # No portable, non-X11-specific way to raise a foreign terminal
        # window; the message above is the best we can do.
        :
        ;;
    esac
    exit 0
  else
    echo "tui-open: port ${PORT} is held by PID ${EXISTING_PID}, but its argv has no --tui:" >&2
    echo "  ${EXISTING_CMD}" >&2
    echo "tui-open: stop that process (or change server.port in ${WORKFLOW_ABS}) and retry." >&2
    exit 5
  fi
fi

# Preflight in current terminal so the user sees doctor output before the
# TUI repaints the screen.
echo "tui-open: running doctor preflight..."
"${SYMPHONY}" doctor "${WORKFLOW_ABS}" || {
  echo "tui-open: doctor reported FAIL — aborting launch" >&2
  exit 4
}

# The browser board is the orchestrator's own admin web app on
# `server.port` — there is no separate viewer process to start. (The old
# `tools/board-viewer/` subsystem was removed; this launcher used to try to
# start it, which was a silent no-op guarded by a file test.)

# The actual command we want a new terminal to run. cd into WORKFLOW_DIR
# (not SCRIPT_DIR) so tracker.board_root resolves correctly.
LAUNCH_CMD="cd '${WORKFLOW_DIR}' && '${SYMPHONY}' --tui '${WORKFLOW_ABS}'"

case "$(uname -s)" in
  Darwin)
    # macOS: write a .command launcher and `open` it in a NEW window.
    # Prefer iTerm if installed; fall back to Terminal.app. Both apps
    # register as handlers for .command files and ALWAYS open them in
    # a new window — unlike `osascript do script`, which silently adds
    # a tab to the frontmost existing window (often invisible behind
    # another Space or minimised).
    LAUNCHER="${SCRIPT_DIR}/.tui-launcher.command"
    cat >"${LAUNCHER}" <<EOF
#!/usr/bin/env bash
cd "${WORKFLOW_DIR}"
exec "${SYMPHONY}" --tui "${WORKFLOW_ABS}"
EOF
    chmod +x "${LAUNCHER}"
    if [[ -d "/Applications/iTerm.app" ]] || mdfind "kMDItemCFBundleIdentifier == 'com.googlecode.iterm2'" 2>/dev/null | grep -q iTerm; then
      TERMINAL_APP="iTerm"
    else
      TERMINAL_APP="Terminal"
    fi
    echo "tui-open: opening new ${TERMINAL_APP} window via ${LAUNCHER}..."
    open -a "${TERMINAL_APP}" "${LAUNCHER}"
    ;;
  Linux)
    if [[ -n "${TERMINAL:-}" ]]; then
      "${TERMINAL}" -e bash -lc "${LAUNCH_CMD}; exec bash" &
    elif command -v gnome-terminal >/dev/null 2>&1; then
      gnome-terminal -- bash -lc "${LAUNCH_CMD}; exec bash" &
    elif command -v konsole >/dev/null 2>&1; then
      konsole -e bash -lc "${LAUNCH_CMD}; exec bash" &
    elif command -v xterm >/dev/null 2>&1; then
      xterm -e bash -lc "${LAUNCH_CMD}; exec bash" &
    else
      echo "tui-open: no known terminal emulator found, running foreground" >&2
      exec bash -lc "${LAUNCH_CMD}"
    fi
    ;;
  *)
    echo "tui-open: unknown OS '$(uname -s)', running foreground" >&2
    exec bash -lc "${LAUNCH_CMD}"
    ;;
esac

echo "tui-open: launched. Headless logs (if any) tail with:"
echo "  tail -F '${WORKFLOW_DIR}/log/symphony.log'"
