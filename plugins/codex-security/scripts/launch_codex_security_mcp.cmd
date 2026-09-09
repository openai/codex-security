@echo off
setlocal DisableDelayedExpansion

set "CODEX_SECURITY_MCP_SCRIPT=%~dp0..\mcp\server.mjs"
if "%~1"=="--helper" (
  set "CODEX_SECURITY_MCP_SCRIPT=%~dp0..\mcp\helpers.mjs"
  goto launch
)

rem This process waits for Node and must not keep the installed plugin directory locked.
if "%~d0"=="" (cd /d "%SystemRoot%") else (cd /d "%~d0\")
if errorlevel 1 (
  echo Codex Security could not start: no safe Windows working directory. 1>&2
  exit /b 1
)

:launch
rem WindowsApps can expose a Node path that exists but cannot be executed.
rem Prefer relocated user-writable runtimes before probing packaged paths.
if defined LOCALAPPDATA for /d %%D in ("%LOCALAPPDATA%\OpenAI\Codex\runtimes\cua_node\*") do if exist "%%~fD\bin\node.exe" (
  set "CODEX_SECURITY_MCP_NODE=%%~fD\bin\node.exe"
  goto run
)
if defined XDG_CACHE_HOME if exist "%XDG_CACHE_HOME%\codex-runtimes\codex-primary-runtime\dependencies\node\bin\node.exe" (
  set "CODEX_SECURITY_MCP_NODE=%XDG_CACHE_HOME%\codex-runtimes\codex-primary-runtime\dependencies\node\bin\node.exe"
  goto run
)
if defined USERPROFILE if exist "%USERPROFILE%\.cache\codex-runtimes\codex-primary-runtime\dependencies\node\bin\node.exe" (
  set "CODEX_SECURITY_MCP_NODE=%USERPROFILE%\.cache\codex-runtimes\codex-primary-runtime\dependencies\node\bin\node.exe"
  goto run
)
if defined CODEX_MCP_NODE_PATH if exist "%CODEX_MCP_NODE_PATH%" (
  set "CODEX_SECURITY_MCP_NODE=%CODEX_MCP_NODE_PATH%"
  goto run
)
if defined CODEX_BROWSER_USE_NODE_PATH if exist "%CODEX_BROWSER_USE_NODE_PATH%" (
  set "CODEX_SECURITY_MCP_NODE=%CODEX_BROWSER_USE_NODE_PATH%"
  goto run
)
if defined CODEX_ELECTRON_RESOURCES_PATH if exist "%CODEX_ELECTRON_RESOURCES_PATH%\cua_node\bin\node.exe" (
  set "CODEX_SECURITY_MCP_NODE=%CODEX_ELECTRON_RESOURCES_PATH%\cua_node\bin\node.exe"
  goto run
)
if defined CODEX_CLI_PATH for %%I in ("%CODEX_CLI_PATH%") do if exist "%%~dpIcua_node\bin\node.exe" (
  set "CODEX_SECURITY_MCP_NODE=%%~dpIcua_node\bin\node.exe"
  goto run
)

rem Search PATH explicitly: helper mode runs inside the scanned repository.
for /f "delims=" %%N in ('"%SystemRoot%\System32\where.exe" $PATH:node 2^>nul') do (
  set "CODEX_SECURITY_MCP_NODE=%%N"
  goto run
)

echo Codex Security could not find a Node runtime. Reinstall or update Codex, or set CODEX_MCP_NODE_PATH to an executable Node runtime. 1>&2
exit /b 127

:run
rem Direct invocation also chains batch shims without CALL reparsing paths.
"%CODEX_SECURITY_MCP_NODE%" "%CODEX_SECURITY_MCP_SCRIPT%" %*
if "%~1"=="--helper" exit /b %errorlevel%
exit
