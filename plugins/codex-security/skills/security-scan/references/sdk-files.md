# SDK scans without a bound draft tool

Write unsealed `scan-manifest.json` and `findings.json` in the exact `CODEX_SECURITY_SCAN_DIR`. Put review bookkeeping in `scan.reviewState`. Save the model in an early draft even if findings are empty. Update these files at subsequent checkpoints and at the final handoff. Use [the scan contract](../../../references/scan-contract.md) for unsealed fields. Each finding needs a stable `identity.anchor`. The SDK derives final IDs and fingerprints. Use the completed-scan examples for shape only.

Use the registered `CODEX_SECURITY_SCAN_ID` and the exact SDK values for `scan.target`: `CODEX_SECURITY_TARGET_ID`, `CODEX_SECURITY_TARGET_DISPLAY_NAME`, `CODEX_SECURITY_TARGET_KIND`, and the supplied revision and snapshot digest (`CODEX_SECURITY_TARGET_REVISION`, `CODEX_SECURITY_TARGET_SNAPSHOT_DIGEST`). Omit the digest for `git_revision`. Set the producer name to `codex-security-plugin`. Omit `scan.sealedAt` and `scan.artifacts`.

For a scoped target set `scan.mode` to `scoped_path`. After writing the manifest, run the supplied scope-binding command. If the SDK supplies only the registered environment, bind the exact scope file with the command for your shell.

```sh
"$CODEX_SECURITY_PLUGIN_ROOT/scripts/launch_codex_security_mcp" --helper bind-repo-scopes --scopes-file "$CODEX_SECURITY_TARGET_PATHS_FILE" --manifest "$CODEX_SECURITY_SCAN_DIR/scan-manifest.json"
```

In PowerShell, resolve the registered paths from the current location before calling CMD.

```powershell
$env:scopePluginRoot = Convert-Path -LiteralPath $env:CODEX_SECURITY_PLUGIN_ROOT -ErrorAction Stop
$env:scopeScanDir = Convert-Path -LiteralPath $env:CODEX_SECURITY_SCAN_DIR -ErrorAction Stop
$env:scopeTargetPaths = Convert-Path -LiteralPath $env:CODEX_SECURITY_TARGET_PATHS_FILE -ErrorAction Stop
cmd.exe /d /v:off /s /c '""%scopePluginRoot%\scripts\launch_codex_security_mcp.cmd" --helper bind-repo-scopes --scopes-file "%scopeTargetPaths%" --manifest "%scopeScanDir%\scan-manifest.json""'
```

For a whole repository set `scan.mode` to `repository`.

Verify both files exist and return control to the SDK. It generates the report and threat model and seals the scan.
