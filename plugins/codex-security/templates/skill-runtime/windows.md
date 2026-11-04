Replace placeholders inside single quotes with literal values. Double each single quote. In CMD examples, `Convert-Path -LiteralPath` resolves existing paths against PowerShell's current location, including UNC shares. The temporary environment variables expand once, preserving literal `%` and `!`. Keep the shown `\.` suffixes on directory arguments to preserve drive roots.

## build-explorer

Build the standalone explorer using a local Python 3.12+ interpreter. The command honors `PYTHON` and otherwise uses `python` from the current environment.

```powershell
$explorerPython = if ($env:PYTHON) { $env:PYTHON } else { 'python' }
& $explorerPython '<skill-directory>\scripts\build_explorer.py' '<model.json>' --assessment '<threat-model.md>' --output '<explorer.html>'
```

## copy-worklist

```powershell
$env:worklistPluginRoot = Convert-Path -LiteralPath '<plugin_dir>' -ErrorAction Stop
$env:worklistDiscoveryDir = Convert-Path -LiteralPath '<discovery_dir>' -ErrorAction Stop
cmd.exe /d /v:off /s /c '""%worklistPluginRoot%\scripts\launch_codex_security_mcp.cmd" --helper copy-deep-review-input --rank-input "%worklistDiscoveryDir%\rank_input.jsonl" --out "%worklistDiscoveryDir%\deep_review_input.jsonl""'
```

The input directory and `rank_input.jsonl` must exist. The output file may be new.

## diff-local-patch

Use the prepared helper-output directory and the full commit object IDs resolved for this scan.

```powershell
$env:worklistPluginRoot = Convert-Path -LiteralPath '<plugin_dir>' -ErrorAction Stop
$env:worklistRepoRoot = Convert-Path -LiteralPath '<repo_root>' -ErrorAction Stop
$env:worklistDiscoveryDir = Convert-Path -LiteralPath '<discovery_dir>' -ErrorAction Stop
$env:worklistBase = '<resolved_base_object_id>'
cmd.exe /d /v:off /s /c '""%worklistPluginRoot%\scripts\launch_codex_security_mcp.cmd" --helper make-diff-rank-input --repo "%worklistRepoRoot%\." --base "%worklistBase%" --mode local-patch --out "%worklistDiscoveryDir%\rank_input.jsonl""'
```

## diff-revisions

Use the prepared helper-output directory and the full commit object IDs resolved for this scan.

```powershell
$env:worklistPluginRoot = Convert-Path -LiteralPath '<plugin_dir>' -ErrorAction Stop
$env:worklistRepoRoot = Convert-Path -LiteralPath '<repo_root>' -ErrorAction Stop
$env:worklistDiscoveryDir = Convert-Path -LiteralPath '<discovery_dir>' -ErrorAction Stop
$env:worklistBase = '<resolved_base_object_id>'
$env:worklistHead = '<resolved_head_object_id>'
cmd.exe /d /v:off /s /c '""%worklistPluginRoot%\scripts\launch_codex_security_mcp.cmd" --helper make-diff-rank-input --repo "%worklistRepoRoot%\." --base "%worklistBase%" --mode revisions --head "%worklistHead%" --out "%worklistDiscoveryDir%\rank_input.jsonl""'
```

## patch-risk-validation

Run from any working directory.

```powershell
$env:patchRiskPluginRoot = Convert-Path -LiteralPath '<plugin-root>' -ErrorAction Stop
$env:patchRiskAssessment = '<assessment.json>'
if ($env:patchRiskAssessment -ne '-') {
    $env:patchRiskAssessment = Convert-Path -LiteralPath $env:patchRiskAssessment -ErrorAction Stop
}
cmd.exe /d /v:off /s /c '""%patchRiskPluginRoot%\scripts\launch_codex_security_mcp.cmd" --helper validate-patch-risk-assessment "%patchRiskAssessment%""'
```

Pass `-` as `<assessment.json>` to read from standard input.

## policy-list

Use an absolute repository path or a leading tilde for the helper to expand.

```powershell
$env:policyPluginRoot = Convert-Path -LiteralPath '<plugin_dir>' -ErrorAction Stop
$env:policyRepository = '<repo_root>'
cmd.exe /d /v:off /s /c '""%policyPluginRoot%\scripts\launch_codex_security_mcp.cmd" --helper resolve-security-md --repo "%policyRepository%\." --list"'
```

## policy-resolve

Use an absolute repository path or a leading tilde for the helper to expand.

```powershell
$env:policyPluginRoot = Convert-Path -LiteralPath '<plugin_dir>' -ErrorAction Stop
$env:policyRepository = '<repo_root>'
$env:policyScope = '<file_or_directory>' -replace '[\\/]$', '$0.'
$env:policyOutput = '<output_path_or_dash>'
cmd.exe /d /v:off /s /c '""%policyPluginRoot%\scripts\launch_codex_security_mcp.cmd" --helper resolve-security-md --repo="%policyRepository%\." --scope="%policyScope%" --out="%policyOutput%""'
```

Supply the scope relative to the repository or as an absolute path. The helper also expands a leading tilde in the scope. Use `-` for standard output. For file output, supply an absolute path, resolving any relative path against PowerShell's current location with tildes kept literal.

## recover-scan-results

Recover retained checkpoints for the selected stopped scan. Use the host-selected interpreter when supplied. The command uses the configured `PYTHON` executable, falling back to `python`.

```powershell
$recoveryPython = if ($env:PYTHON) { $env:PYTHON } else { 'python' }
& $recoveryPython '<plugin_dir>\scripts\workbench_db.py' recover-scan-results --scan-id '<scan_id>'
```

## scope-binding

```powershell
$env:scopePluginRoot = Convert-Path -LiteralPath '<plugin_dir>' -ErrorAction Stop
$env:scopeScanDir = Convert-Path -LiteralPath '<scan_dir>' -ErrorAction Stop
$env:scopeTargetPaths = Convert-Path -LiteralPath $env:CODEX_SECURITY_TARGET_PATHS_FILE -ErrorAction Stop
cmd.exe /d /v:off /s /c '""%scopePluginRoot%\scripts\launch_codex_security_mcp.cmd" --helper bind-repo-scopes --scopes-file "%scopeTargetPaths%" --manifest "%scopeScanDir%\scan-manifest.json""'
```

## scope-inventory

```powershell
$env:scopePluginRoot = Convert-Path -LiteralPath '<plugin_dir>' -ErrorAction Stop
$env:scopeRepository = Convert-Path -LiteralPath '<repo_root>' -ErrorAction Stop
$env:scopeScanDir = Convert-Path -LiteralPath '<scan_dir>' -ErrorAction Stop
$env:scopeTargetPaths = Convert-Path -LiteralPath $env:CODEX_SECURITY_TARGET_PATHS_FILE -ErrorAction Stop
cmd.exe /d /v:off /s /c '""%scopePluginRoot%\scripts\launch_codex_security_mcp.cmd" --helper make-repo-scope-input --repo "%scopeRepository%\." --scopes-file "%scopeTargetPaths%" --out "%scopeScanDir%\scoped-source-input.jsonl""'
```

## tracking-source

Set `<selection>` to `all`, `finding-id`, or `fingerprint`. Use the exact selected value, or an empty value for `all`.

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
