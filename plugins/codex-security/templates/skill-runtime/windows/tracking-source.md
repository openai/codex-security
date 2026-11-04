Validate the sealed scan. Set `<selection>` to `all`, `finding-id`, or `fingerprint`. Use the exact selected value, or an empty value for `all`. Double any single quote in a literal value.

```powershell
$env:trackingPluginRoot = Convert-Path -LiteralPath '<plugin-root>' -ErrorAction Stop
$env:trackingScanDir = Convert-Path -LiteralPath '<user-supplied-scan-dir>' -ErrorAction Stop
$env:trackingSelector = '<id_or_fingerprint>'
if ($env:trackingSelector -like '*"*') { throw 'Invalid finding selector.' }
$selection = switch ('<selection>') {
    'all' { '' }
    'finding-id' { ' --finding-id "%trackingSelector%"' }
    'fingerprint' { ' --fingerprint "%trackingSelector%"' }
    default { throw 'Unknown finding selector.' }
}
cmd.exe /d /v:off /s /c ('""%trackingPluginRoot%\scripts\launch_codex_security_mcp.cmd" --helper validate-tracking-source "%trackingScanDir%\."' + $selection + '"')
```

Stop tracking if validation fails.
