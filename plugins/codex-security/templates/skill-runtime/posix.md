Replace placeholders inside single quotes with literal values. Write each apostrophe as `'\''`.

## build-explorer

Build the standalone explorer using a local Python 3.12+ interpreter. The command honors `PYTHON`, otherwise uses `python3` when it meets the version requirement and falls back to `python3.12`.

```sh
explorer_python=${PYTHON:-python3}
if [ -z "${PYTHON:-}" ] && ! python3 -c 'import sys; sys.exit(sys.version_info < (3, 12))'; then
  explorer_python=python3.12
fi
"$explorer_python" '<skill-directory>/scripts/build_explorer.py' '<model.json>' --assessment '<threat-model.md>' --output '<explorer.html>'
```

## copy-worklist

```sh
'<plugin_dir>/scripts/launch_codex_security_mcp' --helper copy-deep-review-input --rank-input '<discovery_dir>/rank_input.jsonl' --out '<discovery_dir>/deep_review_input.jsonl'
```

## diff-local-patch

Use the prepared helper-output directory and the full commit object IDs resolved for this scan.

```sh
'<plugin_dir>/scripts/launch_codex_security_mcp' --helper make-diff-rank-input --repo '<repo_root>' --base '<resolved_base_object_id>' --mode local-patch --out '<discovery_dir>/rank_input.jsonl'
```

## diff-revisions

Use the prepared helper-output directory and the full commit object IDs resolved for this scan.

```sh
'<plugin_dir>/scripts/launch_codex_security_mcp' --helper make-diff-rank-input --repo '<repo_root>' --base '<resolved_base_object_id>' --mode revisions --head '<resolved_head_object_id>' --out '<discovery_dir>/rank_input.jsonl'
```

## patch-risk-validation

Run from any working directory.

```sh
'<plugin-root>/scripts/launch_codex_security_mcp' --helper validate-patch-risk-assessment '<assessment.json>'
```

Pass `-` as `<assessment.json>` to read from standard input.

## policy-list

```sh
'<plugin_dir>/scripts/launch_codex_security_mcp' --helper resolve-security-md --repo='<repo_root>' --list
```

## policy-resolve

```sh
'<plugin_dir>/scripts/launch_codex_security_mcp' --helper resolve-security-md --repo='<repo_root>' --scope='<file_or_directory>' --out='<output_path_or_dash>'
```

Use `-` for standard output. The helper expands a leading tilde in the repository and scope arguments. The output path keeps tildes literal.

## recover-scan-results

Recover retained checkpoints for the selected stopped scan. Use the host-selected interpreter when supplied. The command uses the configured `PYTHON` executable, falling back to `python3`.

```sh
"${PYTHON:-python3}" '<plugin_dir>/scripts/workbench_db.py' recover-scan-results --scan-id '<scan_id>'
```

## scope-binding

```sh
"$CODEX_SECURITY_PLUGIN_ROOT/scripts/launch_codex_security_mcp" --helper bind-repo-scopes --scopes-file "$CODEX_SECURITY_TARGET_PATHS_FILE" --manifest "$CODEX_SECURITY_SCAN_DIR/scan-manifest.json"
```

## scope-inventory

```sh
"$CODEX_SECURITY_PLUGIN_ROOT/scripts/launch_codex_security_mcp" --helper make-repo-scope-input --repo "$CODEX_SECURITY_REPOSITORY" --scopes-file "$CODEX_SECURITY_TARGET_PATHS_FILE" --out "$CODEX_SECURITY_SCAN_DIR/scoped-source-input.jsonl"
```

## tracking-source

```sh
'<plugin-root>/scripts/launch_codex_security_mcp' --helper validate-tracking-source '<user-supplied-scan-dir>'
```

For one selected finding, append `--finding-id '<id>'` or `--fingerprint '<fingerprint>'` using its exact value. Stop tracking if validation fails.
