# SDK scans without a bound draft tool

Write unsealed `scan-manifest.json` and `findings.json` in the exact `CODEX_SECURITY_SCAN_DIR`. Put review bookkeeping in `scan.reviewState`. Save the model in an early draft even if findings are empty. Update these files at subsequent checkpoints and at the final handoff. Use [the scan contract](../../../references/scan-contract.md) for unsealed fields. Each finding needs a stable `identity.anchor`. The SDK derives final IDs and fingerprints. Use the completed-scan examples for shape only.

Use the registered `CODEX_SECURITY_SCAN_ID` and the exact SDK values for `scan.target`: `CODEX_SECURITY_TARGET_ID`, `CODEX_SECURITY_TARGET_DISPLAY_NAME`, `CODEX_SECURITY_TARGET_KIND`, and the supplied revision and snapshot digest (`CODEX_SECURITY_TARGET_REVISION`, `CODEX_SECURITY_TARGET_SNAPSHOT_DIGEST`). Omit the digest for `git_revision`. Set the producer name to `codex-security-plugin`. Omit `scan.sealedAt` and `scan.artifacts`.

For a scoped target set `scan.mode` to `scoped_path`. After writing the manifest, run the supplied scope-binding command. If the SDK supplies only the registered environment, bind the exact scope file with the [`scope-binding` command](../../../references/skill-runtime.md).

For a whole repository set `scan.mode` to `repository`.

Verify both files exist and return control to the SDK. It generates the report and threat model and seals the scan.
