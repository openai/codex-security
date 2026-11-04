Generate the diff worklist in the prepared helper-output directory. Use the full commit object IDs resolved for this scan. Replace each placeholder inside single quotes with its literal value, doubling any single quote in the value.

```powershell
$env:worklistPluginRoot = Convert-Path -LiteralPath '<plugin_dir>' -ErrorAction Stop
$env:worklistRepoRoot = Convert-Path -LiteralPath '<repo_root>' -ErrorAction Stop
$env:worklistDiscoveryDir = Convert-Path -LiteralPath '<discovery_dir>' -ErrorAction Stop
$env:worklistBase = '<resolved_base_object_id>'
$env:worklistHead = '<resolved_head_object_id>'
cmd.exe /d /v:off /s /c '""%worklistPluginRoot%\scripts\launch_codex_security_mcp.cmd" --helper make-diff-rank-input --repo "%worklistRepoRoot%\." --base "%worklistBase%" --mode revisions --head "%worklistHead%" --out "%worklistDiscoveryDir%\rank_input.jsonl""'
```

The temporary environment values resolve paths against PowerShell's current location, including UNC shares. CMD expands them once, preserving literal `%` and `!`. The repository’s `\.` suffix preserves drive-root paths.
