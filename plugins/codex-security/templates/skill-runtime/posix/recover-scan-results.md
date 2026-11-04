Recover retained checkpoints for the selected stopped scan. Use the host-selected interpreter when supplied. The command uses the configured `PYTHON` executable, falling back to `python3`. Replace the placeholders with literal values. Inside the shown single quotes, write each apostrophe as `'\''`.

```sh
"${PYTHON:-python3}" '<plugin_dir>/scripts/workbench_db.py' recover-scan-results --scan-id '<scan_id>'
```
