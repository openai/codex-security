List the policy files under the repository. Use an absolute repository path or a leading tilde for the helper to expand. Replace each placeholder inside single quotes with its literal value, doubling any single quote in the value.

```powershell
$env:policyPluginRoot = Convert-Path -LiteralPath '<plugin_dir>' -ErrorAction Stop
$env:policyRepository = '<repo_root>'
cmd.exe /d /v:off /s /c '""%policyPluginRoot%\scripts\launch_codex_security_mcp.cmd" --helper resolve-security-md --repo "%policyRepository%\." --list"'
```
