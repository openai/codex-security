Generate the diff worklist in the prepared helper-output directory. Use the full commit object IDs resolved for this scan. Replace the placeholders with literal values. Inside the shown single quotes, write each apostrophe as `'\''`.

```sh
'<plugin_dir>/scripts/launch_codex_security_mcp' --helper make-diff-rank-input --repo '<repo_root>' --base '<resolved_base_object_id>' --mode local-patch --out '<discovery_dir>/rank_input.jsonl'
```
