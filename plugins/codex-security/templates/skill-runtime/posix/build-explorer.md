Build the standalone explorer using a local Python 3.12+ interpreter. The command honors `PYTHON`, otherwise uses `python3` when it meets the version requirement and falls back to `python3.12`. Replace the placeholders with literal paths. Inside the shown single quotes, write each apostrophe as `'\''`.

```sh
explorer_python=${PYTHON:-python3}
if [ -z "${PYTHON:-}" ] && ! python3 -c 'import sys; sys.exit(sys.version_info < (3, 12))'; then
  explorer_python=python3.12
fi
"$explorer_python" '<skill-directory>/scripts/build_explorer.py' '<model.json>' --assessment '<threat-model.md>' --output '<explorer.html>'
```
