@echo off
setlocal DisableDelayedExpansion

set "CODEX_SECURITY_MCP_SCRIPT=%~dp0..\mcp\server.mjs"

rem This process waits for Node and must not keep the installed plugin directory locked.
if "%~d0"=="" (cd /d "%SystemRoot%") else (cd /d "%~d0\")
if errorlevel 1 (
  echo Codex Security could not start: no safe Windows working directory. 1>&2
  exit /b 1
)

rem WindowsApps can expose a Node path that exists but cannot be executed.
rem Prefer relocated user-writable runtimes before probing packaged paths.
if defined LOCALAPPDATA for /d %%D in ("%LOCALAPPDATA%\OpenAI\Codex\runtimes\cua_node\*") do if exist "%%~fD\bin\node.exe" ("%%~fD\bin\node.exe" "%CODEX_SECURITY_MCP_SCRIPT%" %* & exit)
if defined XDG_CACHE_HOME if exist "%XDG_CACHE_HOME%\codex-runtimes\codex-primary-runtime\dependencies\node\bin\node.exe" ("%XDG_CACHE_HOME%\codex-runtimes\codex-primary-runtime\dependencies\node\bin\node.exe" "%CODEX_SECURITY_MCP_SCRIPT%" %* & exit)
if defined USERPROFILE if exist "%USERPROFILE%\.cache\codex-runtimes\codex-primary-runtime\dependencies\node\bin\node.exe" ("%USERPROFILE%\.cache\codex-runtimes\codex-primary-runtime\dependencies\node\bin\node.exe" "%CODEX_SECURITY_MCP_SCRIPT%" %* & exit)
if defined CODEX_MCP_NODE_PATH if exist "%CODEX_MCP_NODE_PATH%" ("%CODEX_MCP_NODE_PATH%" "%CODEX_SECURITY_MCP_SCRIPT%" %* & exit)
if defined CODEX_BROWSER_USE_NODE_PATH if exist "%CODEX_BROWSER_USE_NODE_PATH%" ("%CODEX_BROWSER_USE_NODE_PATH%" "%CODEX_SECURITY_MCP_SCRIPT%" %* & exit)
if defined CODEX_ELECTRON_RESOURCES_PATH if exist "%CODEX_ELECTRON_RESOURCES_PATH%\cua_node\bin\node.exe" ("%CODEX_ELECTRON_RESOURCES_PATH%\cua_node\bin\node.exe" "%CODEX_SECURITY_MCP_SCRIPT%" %* & exit)
if defined CODEX_CLI_PATH for %%I in ("%CODEX_CLI_PATH%") do if exist "%%~dpIcua_node\bin\node.exe" ("%%~dpIcua_node\bin\node.exe" "%CODEX_SECURITY_MCP_SCRIPT%" %* & exit)

where node >nul 2>&1
if not errorlevel 1 (node "%CODEX_SECURITY_MCP_SCRIPT%" %* & exit)

echo Codex Security could not find a Node runtime. Reinstall or update Codex, or set CODEX_MCP_NODE_PATH to an executable Node runtime. 1>&2
exit /b 127
