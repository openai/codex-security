# OpenAI Codex Security Python SDK (Beta)

Run Codex Security scans from Python or the CLI. The package includes the
plugin and recommended Codex configuration. This SDK is in beta, so APIs, CLI
options, and output formats may change.

## Install

Requires Python 3.10 or later and Node.js on `PATH`. The bundled plugin starts
an MCP server with Node and runs Python helpers.

```bash
pip install --pre openai-codex-security
```

Before running a scan, set `OPENAI_API_KEY` or `CODEX_API_KEY`, or reuse an
existing file-backed Codex sign-in.

## Quickstart

```python
from openai_codex_security import CodexSecurity

with CodexSecurity() as security:
    result = security.run("/path/to/repo")
    print(result.report_path)
    print(len(result.findings.findings))
```

The equivalent CLI command is:

```bash
codex-security scan /path/to/repo
```

By default, `security.run(...)` scans the full repository in standard mode.

## Targets and modes

```python
from openai_codex_security import CodexSecurity, DiffTarget

with CodexSecurity() as security:
    # Deep repository scan.
    deep_result = security.run("/path/to/repo", mode="deep")

    # Scan selected paths.
    path_result = security.run(
        "/path/to/repo",
        target=["src", "packages/auth"],
    )

    # Scan a committed diff.
    branch_result = security.run(
        "/path/to/repo",
        target=DiffTarget.refs(base="origin/main", head="HEAD"),
    )

    # Scan staged and unstaged working-tree changes.
    working_tree_result = security.run(
        "/path/to/repo",
        target=DiffTarget.working_tree(base="HEAD"),
    )
```

Deep mode supports repository and path targets. Diff targets use standard mode.

## Results and streaming

`security.run(...)` returns the structured scan contract and the underlying
Codex SDK turn result:

```python
from openai_codex_security import CodexSecurity

with CodexSecurity() as security:
    result = security.run("/path/to/repo")

    print(result.manifest.scan.id)
    print(len(result.findings.findings))
    print(result.coverage.completeness.value)

    print(result.thread_id)
    print(result.turn_result.status)
    print(result.turn_result.usage)
    print(result.turn_result.duration_ms)
    print(result.turn_result.final_response)
```

Use `security.turn(...)` to stream progress or control a scan through the
underlying Codex SDK handle:

```python
from openai_codex_security import CodexSecurity

with CodexSecurity() as security:
    handle = security.turn("/path/to/repo")

    for notification in handle.stream():
        print(notification)
```

## Configuration

Override Codex configuration or use a custom Codex Security plugin directory
or ZIP:

```python
from openai_codex_security import CodexSecurity, CodexSecurityConfig

config = CodexSecurityConfig(
    plugin_path="/path/to/codex-security.zip",
    codex_overrides={
        "features": {"multi_agent_v2": {"max_concurrent_threads_per_session": 8}},
        "model_reasoning_effort": "high",
    },
)

with CodexSecurity(config) as security:
    result = security.run("/path/to/repo")
```

## Async

`AsyncCodexSecurity` corresponds to `AsyncCodex` in the Codex SDK:

```python
import asyncio

from openai_codex_security import AsyncCodexSecurity


async def main() -> None:
    async with AsyncCodexSecurity() as security:
        result = await security.run("/path/to/repo")
        print(result.report_path)


asyncio.run(main())
```

## CLI

The CLI exposes the same targets and modes:

```bash
codex-security scan /path/to/repo
codex-security scan . --path src --path packages/auth
codex-security scan . --diff origin/main --head HEAD
codex-security scan . --working-tree --base HEAD
codex-security scan . --mode deep --output-dir ./scan
codex-security scan . --json
```

This project is licensed under the [Apache-2.0 License](LICENSE).
