"""Storage paths shared by workbench persistence and MCP artifact selection."""

from __future__ import annotations

import os
import sqlite3
import tempfile
from pathlib import Path
from typing import Any

if os.name == "nt":
    import windows_scan_local_files as windows_files


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
    return path.resolve() if canonical else path.absolute()


def resolve_scan_root(scan_root: str | None) -> Path:
    """Resolve an explicit scan output root, defaulting to the scans directory under workbench state."""
    return Path(scan_root).expanduser().resolve() if scan_root else state_dir() / "scans"


def worker_usage_directory(scan_id: str) -> Path:
    """Bind host-observed receipts beneath the persistent protected native home."""
    return state_dir() / "codex-home" / "worker-usage" / scan_id


def archived_deep_path(scan_dir: Path, value: str | None) -> str | None:
    """Resolve old archive rows that still name the original sibling output."""
    if value is None or ".previous-" not in scan_dir.name:
        return value
    path = Path(value)
    if not path.is_relative_to(scan_dir.parent):
        return value
    parts = path.relative_to(scan_dir.parent).parts
    if not parts or ".." in parts or not scan_dir.name.startswith(f"{parts[0]}.previous-"):
        return value
    # Keep missing files inside the archive too. Never follow the replacement scan's output.
    return str(scan_dir.joinpath(*parts[1:]))


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


def create_private_directory(path: Path, *, scan_output: bool = False) -> None:
    """Create missing directories privately without changing existing permissions."""
    if path.parent != path and not path.parent.is_dir():
        create_private_directory(path.parent, scan_output=scan_output)
    if os.name != "nt":
        path.mkdir(mode=0o700, exist_ok=True)
    elif not path.is_dir():
        windows_files.create_private_directory(path, exist_ok=True, scan_output=scan_output)
    elif scan_output:
        windows_files.require_windows_output_path(path)


def create_private_temporary_directory(parent: Path, *, prefix: str) -> Path:
    """Create a unique private child without inheriting a permissive Windows DACL."""
    if os.name != "nt":
        return Path(tempfile.mkdtemp(prefix=prefix, dir=parent)).resolve()

    import secrets

    for _ in range(100):
        path = parent / f"{prefix}{secrets.token_hex(4)}"
        try:
            return windows_files.create_private_directory(path, exist_ok=False, scan_output=True)
        except FileExistsError:
            continue
    raise FileExistsError(f"Could not create a unique directory beneath {parent}.")
