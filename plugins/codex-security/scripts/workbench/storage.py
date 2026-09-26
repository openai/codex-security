"""Storage paths shared by workbench persistence and MCP artifact selection."""

from __future__ import annotations

import os
from pathlib import Path


def state_dir() -> Path:
    state_dir = os.environ.get("CODEX_SECURITY_STATE_DIR")
    if state_dir:
        return Path(state_dir).expanduser().resolve()
    codex_home = Path(os.environ.get("CODEX_HOME", "~/.codex")).expanduser()
    return (codex_home / "state" / "plugins" / "codex-security").resolve()


def resolve_scan_root(scan_root: str | None) -> Path:
    return Path(scan_root).expanduser().resolve() if scan_root else state_dir() / "scans"
