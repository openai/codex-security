Validate the assessment from any working directory. Replace each placeholder inside single quotes with its literal value, doubling any single quote in the value.

```powershell
$env:patchRiskPluginRoot = Convert-Path -LiteralPath '<plugin-root>' -ErrorAction Stop
$env:patchRiskAssessment = '<assessment.json>'
if ($env:patchRiskAssessment -ne '-') {
    $env:patchRiskAssessment = Convert-Path -LiteralPath $env:patchRiskAssessment -ErrorAction Stop
}
cmd.exe /d /v:off /s /c '""%patchRiskPluginRoot%\scripts\launch_codex_security_mcp.cmd" --helper validate-patch-risk-assessment "%patchRiskAssessment%""'
```

The temporary environment values resolve paths against PowerShell's current location, including UNC shares. CMD expands them once, preserving literal `%` and `!`. Pass `-` as `<assessment.json>` to read from standard input.
