# Windows assessment validation

On Windows, use this PowerShell invocation. Replace the placeholders inside the single quotes with literal paths, doubling any single quote in a path:

```powershell
$env:patchRiskPluginRoot = Convert-Path -LiteralPath '<plugin-root>' -ErrorAction Stop
$env:patchRiskAssessment = '<assessment.json>'
if ($env:patchRiskAssessment -ne '-') {
    $env:patchRiskAssessment = Convert-Path -LiteralPath $env:patchRiskAssessment -ErrorAction Stop
}
cmd.exe /d /v:off /s /c '""%patchRiskPluginRoot%\scripts\launch_codex_security_mcp.cmd" --helper validate-patch-risk-assessment "%patchRiskAssessment%""'
```

These two environment variables are temporary values in the calling shell, not application settings. Resolve paths against PowerShell's current location before CMD starts, including when that location is a UNC share. Missing paths stop the invocation with PowerShell's path error. CMD expands the references once, preserving literal `%` and `!` in the paths. Pass `-` as `<assessment.json>` to read the assessment from standard input without creating a file. The validator uses the bundled Node runtime helper and does not require Python.
