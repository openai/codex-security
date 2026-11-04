Build the standalone explorer using a local Python 3.12+ interpreter. The command honors `PYTHON` and otherwise uses `python` from the current environment. Replace the placeholders inside single quotes with literal paths, doubling any single quote in each value.

```powershell
$explorerPython = if ($env:PYTHON) { $env:PYTHON } else { 'python' }
& $explorerPython '<skill-directory>\scripts\build_explorer.py' '<model.json>' --assessment '<threat-model.md>' --output '<explorer.html>'
```
