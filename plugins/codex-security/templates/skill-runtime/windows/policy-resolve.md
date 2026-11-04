Resolve the policy chain for the requested file or directory. Use an absolute repository path or a leading tilde for the helper to expand. Replace each placeholder inside single quotes with its literal value, doubling any single quote in the value.

```powershell
$env:policyPluginRoot = Convert-Path -LiteralPath '<plugin_dir>' -ErrorAction Stop
$env:policyRepository = '<repo_root>'
$env:policyScope = '<file_or_directory>' -replace '[\\/]$', '$0.'
$env:policyOutput = '<output_path_or_dash>'
cmd.exe /d /v:off /s /c '""%policyPluginRoot%\scripts\launch_codex_security_mcp.cmd" --helper resolve-security-md --repo="%policyRepository%\." --scope="%policyScope%" --out="%policyOutput%""'
```

Supply the scope relative to the repository or as an absolute path. The helper also expands a leading tilde in the scope. Use `-` for standard output. For file output, supply an absolute path, resolving any relative path against PowerShell's current location with tildes kept literal.
