Bind the supplied scope file into the draft manifest. Replace each placeholder inside single quotes with its literal value, doubling any single quote in the value.

```powershell
$env:scopePluginRoot = Convert-Path -LiteralPath '<plugin_dir>' -ErrorAction Stop
$env:scopeScanDir = Convert-Path -LiteralPath '<scan_dir>' -ErrorAction Stop
$env:scopeTargetPaths = Convert-Path -LiteralPath $env:CODEX_SECURITY_TARGET_PATHS_FILE -ErrorAction Stop
cmd.exe /d /v:off /s /c '""%scopePluginRoot%\scripts\launch_codex_security_mcp.cmd" --helper bind-repo-scopes --scopes-file "%scopeTargetPaths%" --manifest "%scopeScanDir%\scan-manifest.json""'
```

The temporary environment values resolve paths against PowerShell's current location, including UNC shares. CMD expands them once, preserving literal `%` and `!`.
