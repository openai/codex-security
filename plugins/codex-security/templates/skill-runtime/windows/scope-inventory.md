Generate the scoped source inventory from the supplied scope file. Replace each placeholder inside single quotes with its literal value, doubling any single quote in the value.

```powershell
$env:scopePluginRoot = Convert-Path -LiteralPath '<plugin_dir>' -ErrorAction Stop
$env:scopeRepository = Convert-Path -LiteralPath '<repo_root>' -ErrorAction Stop
$env:scopeScanDir = Convert-Path -LiteralPath '<scan_dir>' -ErrorAction Stop
$env:scopeTargetPaths = Convert-Path -LiteralPath $env:CODEX_SECURITY_TARGET_PATHS_FILE -ErrorAction Stop
cmd.exe /d /v:off /s /c '""%scopePluginRoot%\scripts\launch_codex_security_mcp.cmd" --helper make-repo-scope-input --repo "%scopeRepository%\." --scopes-file "%scopeTargetPaths%" --out "%scopeScanDir%\scoped-source-input.jsonl""'
```

The temporary environment values resolve paths against PowerShell's current location, including UNC shares. CMD expands them once, preserving literal `%` and `!`.
