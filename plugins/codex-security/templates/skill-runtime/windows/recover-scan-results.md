Recover retained checkpoints for the selected stopped scan. Use the host-selected interpreter when supplied. The command uses the configured `PYTHON` executable, falling back to `python`. Replace each placeholder inside single quotes with its literal value, doubling any single quote in the value.

```powershell
$recoveryPython = if ($env:PYTHON) { $env:PYTHON } else { 'python' }
& $recoveryPython '<plugin_dir>\scripts\workbench_db.py' recover-scan-results --scan-id '<scan_id>'
```
