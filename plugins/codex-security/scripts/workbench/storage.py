"""Storage paths shared by workbench persistence and MCP artifact selection."""

from __future__ import annotations

import hashlib
import os
import sqlite3
import tempfile
from contextlib import suppress
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


def require_host_deep_scan_output(connection: sqlite3.Connection, scan: sqlite3.Row) -> None:
    """Keep a running SDK composition from being adopted as a fresh host run."""
    from finalize_scan_contract import (
        ContractError,
        MissingScanLocalFileError,
        open_scan_local_file_descriptor,
        scan_root_identity,
    )

    scan_dir = Path(scan["scan_dir"])
    try:
        with suppress(MissingScanLocalFileError):
            descriptor = open_scan_local_file_descriptor(
                scan_dir, "artifacts/deep-scan/checkpoint.json", "Deep Scan preview checkpoint"
            )
            os.close(descriptor)
            raise SystemExit(
                "This scan has a Deep Scan preview checkpoint. Finish it with its original "
                "SDK version or start a new scan in another output directory."
            )
        # A native missing-path error can also mean the root vanished while opening the file.
        scan_root_identity(scan_dir)
    except (ContractError, OSError) as exc:
        raise SystemExit(f"Cannot inspect the saved Deep Scan checkpoint: {exc}") from exc
    # A lost checkpoint can still have persisted preview child membership.
    if (
        connection.execute(
            "SELECT 1 FROM pragma_table_info('scans') WHERE name = 'parent_scan_role'"
        ).fetchone()
        and connection.execute(
            "SELECT 1 FROM scans WHERE parent_scan_id = ? AND parent_scan_role = 'deep_pass' LIMIT 1",
            (scan["id"],),
        ).fetchone()
    ):
        raise SystemExit(
            "This scan contains work from the Deep Scan preview. Recover it with its original SDK version."
        )


def short_archive_prefix(original_name: str) -> str:
    """Bind a short archive name to the complete original filename."""
    return f".previous-{hashlib.sha256(os.fsencode(original_name)).hexdigest()}-"


def archive_source_directory(archive: Path, source: Path) -> Path | None:
    """Return the original sibling when the archived name identifies it."""
    if not source.is_relative_to(archive.parent):
        return None
    parts = source.relative_to(archive.parent).parts
    if not parts or ".." in parts:
        return None
    name = parts[0]
    if archive.name.startswith(f"{name}.previous-") or (
        archive.name.startswith(".previous-")
        and archive.name.startswith(short_archive_prefix(name))
    ):
        return archive.parent / name
    return None


def archived_deep_path(scan_dir: Path, value: str | None) -> str | None:
    """Resolve old archive rows that still name the original sibling output."""
    if value is None or ".previous-" not in scan_dir.name:
        return value
    path = Path(value)
    original = archive_source_directory(scan_dir, path)
    if original is None:
        return value
    # Keep missing files inside the archive too. Never follow the replacement scan's output.
    return str(scan_dir / path.relative_to(original))


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
