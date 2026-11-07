"""Storage paths shared by workbench persistence and MCP artifact selection."""

from __future__ import annotations

import os
import sqlite3
import tempfile
from pathlib import Path
from typing import Any


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


def _create_private_windows_directory(path: Path, *, exist_ok: bool, scan_output: bool) -> Path:
    """Create one Windows directory with a protected inheritable DACL."""
    import ctypes
    import ctypes.wintypes

    from windows_scan_local_files import (
        create_windows_output_directory,
        current_user_sid,
        require_windows_output_path,
        verify_private_scan_root,
    )

    class SecurityAttributes(ctypes.Structure):
        _fields_ = [
            ("length", ctypes.wintypes.DWORD),
            ("descriptor", ctypes.wintypes.LPVOID),
            ("inherit", ctypes.wintypes.BOOL),
        ]

    # Older supported Python releases ignore mkdir's 0700 mode on Windows.
    # Apply the same owner/SYSTEM/Administrators policy at creation so a
    # writable parent never becomes an inheritance window.
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    volume = ctypes.create_unicode_buffer(32768)
    flags = ctypes.wintypes.DWORD()
    if not kernel.GetVolumePathNameW(str(path.parent.resolve()), volume, len(volume)):
        raise ctypes.WinError(ctypes.get_last_error())
    if not kernel.GetVolumeInformationW(volume, None, 0, None, None, ctypes.byref(flags), None, 0):
        raise ctypes.WinError(ctypes.get_last_error())
    if not flags.value & 0x8:  # FILE_PERSISTENT_ACLS
        raise ValueError("Select a directory on a Windows volume that supports ACLs.")

    security = ctypes.WinDLL("advapi32", use_last_error=True)
    sid = current_user_sid()
    owner = "" if exist_ok else f"O:{sid}"
    dacl = f"{owner}D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{sid})"

    descriptor = ctypes.wintypes.LPVOID()
    if not security.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        dacl, 1, ctypes.byref(descriptor), None
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        if scan_output:
            error = create_windows_output_directory(path, descriptor)
        else:
            attributes = SecurityAttributes(ctypes.sizeof(SecurityAttributes), descriptor, False)
            error = (
                0
                if kernel.CreateDirectoryW(str(path), ctypes.byref(attributes))
                else ctypes.get_last_error()
            )
        if not error:
            return path if exist_ok else verify_private_scan_root(path, descriptor)
        if exist_ok and error == 183 and path.is_dir():  # ERROR_ALREADY_EXISTS
            if scan_output:
                require_windows_output_path(path)
            return path
        raise ctypes.WinError(error)
    finally:
        kernel.LocalFree(descriptor)


def create_private_directory(path: Path, *, scan_output: bool = False) -> None:
    """Create missing directories privately without changing existing permissions."""
    if os.name == "nt" and path.is_dir():
        if scan_output:
            from windows_scan_local_files import require_windows_output_path

            require_windows_output_path(path)
        return
    if os.name == "nt" and scan_output and not path.parent.is_dir():
        create_private_directory(path.parent, scan_output=True)
    try:
        if os.name == "nt":
            _create_private_windows_directory(path, exist_ok=True, scan_output=scan_output)
        else:
            path.mkdir(mode=0o700, exist_ok=True)
    except FileNotFoundError:
        if path.parent == path:
            raise
        create_private_directory(path.parent, scan_output=scan_output)
        if os.name == "nt":
            _create_private_windows_directory(path, exist_ok=True, scan_output=scan_output)
        else:
            path.mkdir(mode=0o700, exist_ok=True)


def create_private_temporary_directory(parent: Path, *, prefix: str) -> Path:
    """Create a unique private child without inheriting a permissive Windows DACL."""
    if os.name != "nt":
        return Path(tempfile.mkdtemp(prefix=prefix, dir=parent)).resolve()

    import secrets

    for _ in range(100):
        path = parent / f"{prefix}{secrets.token_hex(4)}"
        try:
            return _create_private_windows_directory(path, exist_ok=False, scan_output=True)
        except FileExistsError:
            continue
    raise FileExistsError(f"Could not create a unique directory beneath {parent}.")
