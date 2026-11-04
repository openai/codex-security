Validate the sealed scan and list its findings. Replace the placeholders with literal values. Inside the shown single quotes, write each apostrophe as `'\''`.

```sh
'<plugin-root>/scripts/launch_codex_security_mcp' --helper validate-tracking-source '<user-supplied-scan-dir>'
```

For one selected finding, append `--finding-id '<id>'` or `--fingerprint '<fingerprint>'` using its exact value. Stop tracking if validation fails.
