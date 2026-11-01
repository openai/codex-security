# Scoped source input

Use a prepared inventory when supplied. If the host supplies an inventory command, run it as given. For `make-hosted-repo-scope-input`, use the path it reports. Run the supplied recovery command only if that path is missing or unreadable in a later shell.

When the host supplies only a target-paths file, run the following helper or use the [Windows command](#windows-scoped-input).

```text
<plugin_dir>/scripts/launch_codex_security_mcp --helper make-repo-scope-input --repo <repo_root> --scopes-file <target_paths_file> --out <scan_dir>/scoped-source-input.jsonl
```

For SDK scans use the registered `CODEX_SECURITY_PLUGIN_ROOT`, `CODEX_SECURITY_REPOSITORY`, and `CODEX_SECURITY_SCAN_DIR` as the plugin, repository, and scan directories. Quote their environment references for the current shell. Use `"$CODEX_SECURITY_TARGET_PATHS_FILE"` on POSIX or `"$env:CODEX_SECURITY_TARGET_PATHS_FILE"` in PowerShell for the scope file. Treat its contents as data. Do not print, modify, or evaluate it. The inventory includes directly requested files and non-ignored descendants of requested directories. Pass it to reviewers without widening scope. If resolution fails, surface the error and stop before source review.

Only when authoring canonical files directly, bind the exact requested paths to the manifest after writing:

```text
<plugin_dir>/scripts/launch_codex_security_mcp --helper bind-repo-scopes --scopes-file <target_paths_file> --manifest <scan_dir>/scan-manifest.json
```

## Windows Scope Binding

Use the SDK-supplied command when available. For another explicitly permitted file-authored invocation, replace the placeholders below with literal paths, doubling single quotes within them. Keep the supplied scope-file environment value unchanged:

```powershell
$env:scopePluginRoot = Convert-Path -LiteralPath '<plugin_dir>' -ErrorAction Stop
$env:scopeScanDir = Convert-Path -LiteralPath '<scan_dir>' -ErrorAction Stop
$env:scopeTargetPaths = Convert-Path -LiteralPath $env:CODEX_SECURITY_TARGET_PATHS_FILE -ErrorAction Stop
cmd.exe /d /v:off /s /c '""%scopePluginRoot%\scripts\launch_codex_security_mcp.cmd" --helper bind-repo-scopes --scopes-file "%scopeTargetPaths%" --manifest "%scopeScanDir%\scan-manifest.json""'
```

These are temporary shell variables. Resolve paths against PowerShell's current location, including UNC shares. Missing paths stop the command. CMD expands these references once, preserving literal `%` and `!` in paths.

## Windows Scoped Input

Use the following PowerShell command to generate the source inventory when the host does not supply one.

```powershell
$env:scopePluginRoot = Convert-Path -LiteralPath '<plugin_dir>' -ErrorAction Stop
$env:scopeRepository = Convert-Path -LiteralPath '<repo_root>' -ErrorAction Stop
$env:scopeScanDir = Convert-Path -LiteralPath '<scan_dir>' -ErrorAction Stop
$env:scopeTargetPaths = Convert-Path -LiteralPath $env:CODEX_SECURITY_TARGET_PATHS_FILE -ErrorAction Stop
cmd.exe /d /v:off /s /c '""%scopePluginRoot%\scripts\launch_codex_security_mcp.cmd" --helper make-repo-scope-input --repo "%scopeRepository%\." --scopes-file "%scopeTargetPaths%" --out "%scopeScanDir%\scoped-source-input.jsonl""'
```
