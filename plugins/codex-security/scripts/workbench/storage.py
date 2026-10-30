"""Storage paths shared by workbench persistence and MCP artifact selection."""

from __future__ import annotations

import os
from pathlib import Path


def state_dir(*, canonical: bool = True) -> Path:
    configured = os.environ.get("CODEX_SECURITY_STATE_DIR")
    if configured:
        path = Path(configured).expanduser()
    else:
        codex_home = Path(
            os.environ["CODEX_HOME"] if os.environ.get("CODEX_HOME", "").strip() else "~/.codex"
        ).expanduser()
        path = codex_home / "state" / "plugins" / "codex-security"
    return path.resolve() if canonical else path.absolute()


def resolve_scan_root(scan_root: str | None) -> Path:
    return Path(scan_root).expanduser().resolve() if scan_root else state_dir() / "scans"


def create_private_directory(path: Path) -> None:
    """Create missing directories privately without changing existing permissions."""
    try:
        path.mkdir(mode=0o700, exist_ok=True)
    except FileNotFoundError:
        if path.parent == path:
            raise
        create_private_directory(path.parent)
        path.mkdir(mode=0o700, exist_ok=True)
