@echo off
REM tui-open.bat - launch Symphony's Textual Kanban TUI in a new console window.
REM
REM Usage:
REM   tui-open.bat [path\to\WORKFLOW.md]
REM
REM - Defaults to .\WORKFLOW.md.
REM - Prefers .venv\Scripts\symphony.exe; falls back to PATH.
REM   `pip install -e .` pulls textual automatically as a runtime dep — if
REM   you see ModuleNotFoundError: textual, re-run pip install -e . inside .venv.
REM - Runs `symphony --tui WORKFLOW.md` (single process: orchestrator + TUI).
REM - Spawns a NEW console window via `start "title" cmd /k ...` so this
REM   script returns control to the caller immediately.
REM - Quit the TUI with `q` from inside the app (drains workers cleanly).

setlocal ENABLEDELAYEDEXPANSION

set "SCRIPT_DIR=%~dp0"
if "%SCRIPT_DIR:~-1%"=="\" set "SCRIPT_DIR=%SCRIPT_DIR:~0,-1%"

if "%~1"=="" (
  set "WORKFLOW=%SCRIPT_DIR%\WORKFLOW.md"
) else (
  set "WORKFLOW=%~f1"
)

if not exist "%WORKFLOW%" (
  echo tui-open: workflow not found: %WORKFLOW% 1>&2
  exit /b 2
)

REM Resolve WORKFLOW's directory. tracker.board_root is relative to the
REM working directory, so we must launch from the workflow's own directory
REM — not SCRIPT_DIR — or external/demo workflows read the wrong board.
for %%I in ("%WORKFLOW%") do set "WORKFLOW_DIR=%%~dpI"
if "%WORKFLOW_DIR:~-1%"=="\" set "WORKFLOW_DIR=%WORKFLOW_DIR:~0,-1%"

if exist "%SCRIPT_DIR%\.venv\Scripts\symphony.exe" (
  set "SYMPHONY=%SCRIPT_DIR%\.venv\Scripts\symphony.exe"
) else (
  where symphony >nul 2>&1
  if errorlevel 1 (
    echo tui-open: 'symphony' not found on PATH and no .venv\Scripts\symphony.exe 1>&2
    echo tui-open: install with: py -3.11 -m venv .venv ^&^& .venv\Scripts\pip install -e . 1>&2
    exit /b 3
  )
  for /f "delims=" %%i in ('where symphony') do set "SYMPHONY=%%i"
)

REM Detect whether a TUI is already running on this workflow's port.
REM Use PowerShell for the YAML port extraction + listener lookup; the
REM cmd-only equivalents are far more fragile.
set "PORT="
for /f %%P in ('powershell -NoProfile -Command "$y=Get-Content -Raw '%WORKFLOW%'; if ($y -match '(?ms)^server:\s*\r?\n(?:[ \t]+[^\r\n]*\r?\n)*?[ \t]+port:\s*(\d+)') { $matches[1] } else { '9999' }" 2^>nul') do set "PORT=%%P"
if "%PORT%"=="" set "PORT=9999"

set "EXISTING_PID="
for /f %%P in ('powershell -NoProfile -Command "(Get-NetTCPConnection -LocalPort %PORT% -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1).OwningProcess" 2^>nul') do set "EXISTING_PID=%%P"

if not "%EXISTING_PID%"=="" (
  set "EXISTING_HAS_TUI="
  for /f %%H in ('powershell -NoProfile -Command "$p=Get-CimInstance Win32_Process -Filter \"ProcessId=%EXISTING_PID%\" -ErrorAction SilentlyContinue; if ($p -and $p.CommandLine -like '*--tui*') { '1' } else { '0' }" 2^>nul') do set "EXISTING_HAS_TUI=%%H"
  if "!EXISTING_HAS_TUI!"=="1" (
    echo tui-open: TUI already running on port %PORT% (PID %EXISTING_PID%).
    echo tui-open: please switch to the existing console window instead of duplicating.
    exit /b 0
  )
  echo tui-open: port %PORT% is held by PID %EXISTING_PID%, but its cmdline has no --tui. 1>&2
  echo tui-open: stop that process (or change server.port in %WORKFLOW%) and retry. 1>&2
  exit /b 5
)

echo tui-open: running doctor preflight...
"%SYMPHONY%" doctor "%WORKFLOW%"
if errorlevel 1 (
  echo tui-open: doctor reported FAIL - aborting launch 1>&2
  exit /b 4
)

echo tui-open: opening new console window...
start "Symphony TUI" cmd /k "cd /d "%WORKFLOW_DIR%" && "%SYMPHONY%" --tui "%WORKFLOW%""

echo tui-open: launched. Headless logs (if any) tail with:
echo   powershell -c "Get-Content -Wait '%WORKFLOW_DIR%\log\symphony.log'"

endlocal
