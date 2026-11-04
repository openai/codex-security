Copy every row into the review worklist. Replace each placeholder inside single quotes with its literal value, doubling any single quote in the value.

```powershell
$env:worklistPluginRoot = Convert-Path -LiteralPath '<plugin_dir>' -ErrorAction Stop
$env:worklistDiscoveryDir = Convert-Path -LiteralPath '<discovery_dir>' -ErrorAction Stop
cmd.exe /d /v:off /s /c '""%worklistPluginRoot%\scripts\launch_codex_security_mcp.cmd" --helper copy-deep-review-input --rank-input "%worklistDiscoveryDir%\rank_input.jsonl" --out "%worklistDiscoveryDir%\deep_review_input.jsonl""'
```

The temporary environment values resolve paths against PowerShell's current location, including UNC shares. CMD expands them once, preserving literal `%` and `!`. The input directory and `rank_input.jsonl` must exist. The output file may be new.
