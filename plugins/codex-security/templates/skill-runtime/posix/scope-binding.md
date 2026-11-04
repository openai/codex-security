Bind the supplied scope file into the draft manifest. Replace the placeholders with literal values. Inside the shown single quotes, write each apostrophe as `'\''`.

```sh
'<plugin_dir>/scripts/launch_codex_security_mcp' --helper bind-repo-scopes --scopes-file "$CODEX_SECURITY_TARGET_PATHS_FILE" --manifest '<scan_dir>/scan-manifest.json'
```
