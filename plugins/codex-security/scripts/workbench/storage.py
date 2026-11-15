"""Storage paths shared by workbench persistence and MCP artifact selection."""

from __future__ import annotations

import os
import sqlite3
import sys
from pathlib import Path
from typing import Any

# SDK hosts also load this file directly with runpy, outside the workbench package.
if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from windows_paths import (
    extended_path,
    filesystem_path,
    portable_path,
    portable_relative_path,
    uses_windows_namespace,
)


def state_dir(*, canonical: bool = True) -> Path:
    """Return the workbench state path, resolving symlinks unless canonical is false."""
    configured = os.environ.get("CODEX_SECURITY_STATE_DIR")
    if configured:
        path = Path(configured).expanduser()
    else:
        codex_home = Path(
            os.environ["CODEX_HOME"] if os.environ.get("CODEX_HOME", "").strip() else "~/.codex"
        ).expanduser()
        path = codex_home / "state" / "plugins" / "codex-security"
    return filesystem_path(path).resolve() if canonical else path.absolute()


def resolve_scan_root(scan_root: str | None) -> Path:
    """Resolve an explicit scan output root, defaulting to the scans directory under workbench state."""
    return (
        filesystem_path(Path(scan_root).expanduser()).resolve()
        if scan_root
        else filesystem_path(state_dir() / "scans")
    )


def worker_usage_directory(scan_id: str) -> Path:
    """Bind host-observed receipts beneath the persistent protected native home."""
    return state_dir() / "codex-home" / "worker-usage" / scan_id


def relocate_scan_path(scan_dir: Path, archive_dir: Path, value: str | None) -> str | None:
    """Move a stored scan-local path to the archive, preserving verbatim-only names."""
    if value is None:
        return None
    path = Path(value)
    try:
        relative = portable_relative_path(path, portable_path(scan_dir))
    except ValueError:
        return value
    if uses_windows_namespace(path):
        return str(portable_path(extended_path(archive_dir) / relative))
    return str(portable_path(archive_dir) / relative)


def archived_deep_path(scan_dir: Path, value: str | None) -> str | None:
    """Resolve old archive rows that still name the original sibling output."""
    if value is None or ".previous-" not in scan_dir.name:
        return value
    try:
        parts = portable_relative_path(Path(value), portable_path(scan_dir.parent)).parts
    except ValueError:
        return value
    if not parts or ".." in parts or not scan_dir.name.startswith(f"{parts[0]}.previous-"):
        return value
    # Keep missing files inside the archive too. Never follow the replacement scan's output.
    return relocate_scan_path(scan_dir.parent / parts[0], scan_dir, value)


def saved_deep_workers(connection: sqlite3.Connection, scan: sqlite3.Row) -> list[Any]:
    workers = connection.execute(
        "SELECT * FROM deep_scan_workers WHERE scan_id = ? ORDER BY created_at, id",
        (scan["id"],),
    ).fetchall()
    scan_dir = Path(scan["scan_dir"])
    if ".previous-" not in scan_dir.name:
        return workers
    return [
        {
            **worker,
            **{
                key: archived_deep_path(scan_dir, worker[key])
                for key in ("artifact_dir", "prompt_path", "result_manifest_path")
            },
        }
        for worker in workers
    ]


def create_private_directory(path: Path) -> None:
    """Create missing directories privately without changing existing permissions."""
    try:
        path.mkdir(mode=0o700, exist_ok=True)
    except FileNotFoundError:
        if path.parent == path:
            raise
        create_private_directory(path.parent)
        path.mkdir(mode=0o700, exist_ok=True)
