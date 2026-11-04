Resolve the policy chain for the requested file or directory. Replace the placeholders with literal values. Inside the shown single quotes, write each apostrophe as `'\''`.

```sh
'<plugin_dir>/scripts/launch_codex_security_mcp' --helper resolve-security-md --repo='<repo_root>' --scope='<file_or_directory>' --out='<output_path_or_dash>'
```

Use `-` for standard output. The helper expands a leading tilde in the repository and scope arguments. The output path keeps tildes literal.
