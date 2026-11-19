# Cross-platform compatibility (macOS / Linux / Windows)

Symphony's orchestrator runs on all three platforms. The agent CLIs
(Codex, Claude Code, Gemini, OpenCode, Pi) are themselves cross-platform. The
sharp edges are concentrated in three places:

1. the bash binary that runs your hooks,
2. the `Path.home()` semantics that the doctor relies on,
3. POSIX-only `os.WIF*` helpers in `_shell.safe_proc_wait`.

This page documents what to check on each platform, and which defects
have already been fixed.

## What "just works" on each platform

| Surface                       | macOS | Linux | Windows                                         |
|-------------------------------|-------|-------|-------------------------------------------------|
| `symphony` CLI                | ✓     | ✓     | ✓ (via `py -3.11 -m pip install -e .`)          |
| `symphony tui` (Textual)      | ✓     | ✓     | ✓ — Windows Terminal / ConHost; cmd.exe legacy console may glitch colors |
| `symphony doctor`             | ✓     | ✓     | ✓                                               |
| `tui-open.sh`                 | ✓     | ✓     | use `tui-open.bat`                              |
| `tui-open.bat`                | n/a   | n/a   | ✓                                               |
| JSON API on `:9999`           | ✓     | ✓     | ✓                                               |
| File-tracker (`tracker.kind: file`) | ✓ | ✓   | ✓                                               |
| Worktree-default `after_create` | ✓   | ✓     | ✓ since 2026-05-15 fix; see below              |

## Windows: required setup

- **Bash:** Git Bash (Git for Windows) MUST be installed. Symphony's
  `_shell.resolve_bash()` rejects the WSL launcher
  (`C:\Windows\System32\bash.exe` / `WindowsApps\bash.exe`) and prefers
  `C:\Program Files\Git\(usr\\)?bin\bash.exe`. If neither is present,
  `symphony doctor` reports `FAIL shell.bash` and dispatch is dead in
  the water. Install: <https://git-scm.com/download/win>.
- **Python:** any 3.11–3.13 on PATH. The worktree-default
  `after_create` hook walks the candidate list
  `python3.11 → python3.12 → python3.13 → python3 → python` and falls
  back to a clear warning if none are found (the dispatch continues —
  the venv is only used for editable installs during development).
- **PATH ordering:** make sure Git Bash's `usr\bin` is on PATH before
  `C:\Windows\System32`. Otherwise `subprocess.run(["bash", ...])` calls
  from outside Symphony's helpers can still hit the WSL launcher. This
  bit the test-suite until 2026-05-15.
- **Antivirus / file indexer:** Windows Defender (and equivalents) hold
  a transient handle on freshly-created directories. The 2026-05-15 fix
  removed the pre-`worktree add` `rmdir` that raced this scan. You do
  not need to add an AV exclusion for `~/symphony_workspaces` — but
  doing so makes hook startup faster.

## macOS: gotchas

- The Python 3.12 + asyncio + Textual SIGCHLD race that `safe_proc_wait`
  works around is the original reason that helper exists. Do NOT
  replace its `os.waitpid`-via-thread path with a plain `proc.wait()`
  on macOS — the watcher genuinely fails to reap and you'll see zombie
  `<defunct>` subprocesses + an event loop that hangs.
- `tui-open.sh` prefers `iTerm.app`, falls back to `Terminal.app`.
- If you use the `pi` backend, `~/.pi/agent/auth.json` lives under the
  real `$HOME`, not a Homebrew prefix.

## Linux: gotchas

- Distro-packaged Python without `venv` (Debian/Ubuntu: `python3-venv`)
  makes the worktree-default `after_create` hook log
  `after_create: pip install failed; ...` and continue. Install
  `python3-venv` to silence it, or replace the venv step in your fork.
- `tui-open.sh` looks for `x-terminal-emulator`, `gnome-terminal`,
  `konsole`, then falls back to in-place launch.

## The cross-platform parity tests

`tests/test_shell.py` carries paired POSIX-skipped + Windows-skipped
tests for `safe_proc_wait` so a regression on one platform cannot hide
behind green CI on the other:

| Test                                                  | POSIX | Windows |
|-------------------------------------------------------|:-----:|:-------:|
| `test_safe_proc_wait_reaps_via_thread`                | ✓     | skip    |
| `test_safe_proc_wait_short_circuits_when_returncode_set` | ✓  | skip    |
| `test_safe_proc_wait_timeout_returns_none`            | ✓     | skip    |
| `test_safe_proc_wait_windows_delegates_to_proc_wait`  | skip  | ✓       |
| `test_safe_proc_wait_windows_short_circuits_*`        | skip  | ✓       |
| `test_safe_proc_wait_windows_timeout_returns_none`    | skip  | ✓       |

`tests/test_doctor.py::_isolate_home` is the cross-platform
`monkeypatch` helper for any test that wants `Path.home()` to resolve
into a temp directory. Use it whenever you touch a doctor check that
walks `~`.

`tests/test_workspace.py` uses `_BASH = resolve_bash()` (imported from
`symphony._shell`) for subprocess calls. Do the same in any new test
that spawns bash for hook simulation — never hard-code `"bash"`.

## Defects fixed 2026-05-15 (regression history)

If you see the symptoms below on a Windows host, you're on a Symphony
build older than the round-2 cross-platform commits on `dev`. Update.

| Symptom                                                                              | Root cause                                                                             |
|--------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------|
| Doctor `agent.kind=pi.auth` reports `pass` even with `~/.pi/agent/auth.json` absent  | `Path.home()` ignores `HOME` on Windows; test monkeypatched only `HOME`                 |
| `test_after_run_amend_*` fails: `Author identity unknown`, no `wip:` commit          | Test invoked bare `bash`; resolved to WSL launcher, which dropped `GIT_AUTHOR_*` env    |
| `worker_exit reason=error error="module 'os' has no attribute 'WIFEXITED'"`         | `safe_proc_wait` used POSIX-only `os.WIF*`/`os.waitpid` unconditionally                 |
| `hook_failed after_create rc=1 stderr="rmdir: ... Device or resource busy"`         | Pre-`worktree add` `rmdir` raced the Windows file indexer scan on a fresh dir          |
| `hook_failed after_create rc=128 stderr="missing but already registered worktree"`   | Prior crashed attempt left `.git/worktrees/<ID>` registered; new add refused to overwrite |
| `hook_failed after_create rc=127 stderr="python3.11: command not found"`            | Worktree-default hook hardcoded `python3.11`; system shipped 3.12 only                  |

Each of these has a regression test (or a hook that fails loudly
instead of silently) so re-introducing them surfaces immediately rather
than putting tickets into a permanent retry loop.

## When porting Symphony to a new platform

1. Run `pytest -q` first — the suite encodes the parity invariants.
2. Run `symphony doctor ./WORKFLOW.md`. All checks should be PASS.
3. Create a smoke board (`symphony board init ./kanban_smoke && symphony
   board new MINI-1 "..."`), point an `examples/WORKFLOW.smoke.md` at it with
   `: noop` hooks, and launch headless on a free port. Watch
   `log/symphony.log` for `dispatch → hook_completed → agent_session_started
   → agent_turn_completed`. If all four fire, the orchestrator + backend
   pipeline is wired correctly.
4. Only after that, test the worktree-default `after_create` hook with
   a real ticket. That's where platform-specific path / handle issues
   surface first.
