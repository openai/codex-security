# Codex Security

Run Codex Security scans from the command line or Python.

> [!WARNING]
> Codex Security is in beta. APIs, CLI options, and output formats may change.

## Install and run

The current CLI requires Python 3.10 or later and Node.js on `PATH`. The
bundled plugin starts an MCP server with Node and runs Python helpers.

Before running a scan, set `OPENAI_API_KEY` or `CODEX_API_KEY`, or reuse an
existing file-backed Codex sign-in.

```bash
pip install --pre openai-codex-security
codex-security scan /path/to/repo
```

```python
from openai_codex_security import CodexSecurity

with CodexSecurity() as security:
    result = security.run("/path/to/repo")
    print(result.report_path)
```

See [`sdk/python`](sdk/python) for the full Python SDK and CLI reference.

This project is licensed under the [Apache-2.0 License](LICENSE).
