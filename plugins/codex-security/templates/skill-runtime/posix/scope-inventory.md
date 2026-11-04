Generate the scoped source inventory from the supplied scope file. Replace the placeholders with literal values. Inside the shown single quotes, write each apostrophe as `'\''`.

```sh
'<plugin_dir>/scripts/launch_codex_security_mcp' --helper make-repo-scope-input --repo '<repo_root>' --scopes-file "$CODEX_SECURITY_TARGET_PATHS_FILE" --out '<scan_dir>/scoped-source-input.jsonl'
```
