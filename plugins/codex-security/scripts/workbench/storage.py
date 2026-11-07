"""Storage paths and scan locks shared by workbench persistence and MCP artifact selection."""

from __future__ import annotations

import errno
import os
import sqlite3
import stat
import tempfile
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path, PurePosixPath
from typing import Any

from finalize_scan_contract import ContractError, open_scan_local_file_descriptor

try:
    import fcntl as posix_file_lock
except ModuleNotFoundError:  # pragma: no cover
    posix_file_lock = None

try:
    import msvcrt as windows_file_lock
except ModuleNotFoundError:  # pragma: no cover
    windows_file_lock = None

_completion_locks = threading.local()


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


@contextmanager
def scan_completion_lock(scan_id: str) -> Iterator[None]:
    from workbench_validation import require_uuid

    lock_dir = state_dir() / "completion-locks"
    create_private_directory(lock_dir)
    lock_path = lock_dir / f"{require_uuid(scan_id, 'scan-id')}.lock"
    key = (os.getpid(), lock_path)
    held = getattr(_completion_locks, "held", set())
    if key in held:
        yield
        return
    descriptor = os.open(
        lock_path,
        os.O_RDWR | os.O_CREAT | getattr(os, "O_BINARY", 0),
        0o600,
    )
    locked = False
    try:
        acquire_completion_file_lock(descriptor)
        locked = True
        held.add(key)
        _completion_locks.held = held
        yield
    finally:
        try:
            if locked:
                held.remove(key)
                release_completion_file_lock(descriptor)
        finally:
            os.close(descriptor)


def is_file_lock_contention(error: OSError) -> bool:
    return error.errno in {errno.EACCES, errno.EAGAIN, errno.EDEADLK}


def acquire_completion_file_lock(descriptor: int) -> None:
    if posix_file_lock is not None:
        posix_file_lock.flock(descriptor, posix_file_lock.LOCK_EX)
        return
    if windows_file_lock is None:
        raise SystemExit("Scan completion requires operating-system file locking support.")

    while os.fstat(descriptor).st_size == 0:
        os.lseek(descriptor, 0, os.SEEK_SET)
        try:
            os.write(descriptor, b"\0")
        except OSError as exc:
            if not is_file_lock_contention(exc):
                raise
            time.sleep(0.05)

    while True:
        os.lseek(descriptor, 0, os.SEEK_SET)
        try:
            windows_file_lock.locking(descriptor, windows_file_lock.LK_NBLCK, 1)
            return
        except OSError as exc:
            if not is_file_lock_contention(exc):
                raise
            time.sleep(0.05)


def release_completion_file_lock(descriptor: int) -> None:
    if posix_file_lock is not None:
        posix_file_lock.flock(descriptor, posix_file_lock.LOCK_UN)
        return
    if windows_file_lock is None:
        return
    os.lseek(descriptor, 0, os.SEEK_SET)
    windows_file_lock.locking(descriptor, windows_file_lock.LK_UNLCK, 1)


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


def _create_private_windows_directory(path: Path, *, exist_ok: bool) -> Path:
    """Create one Windows directory with a protected inheritable DACL."""
    import ctypes
    import ctypes.wintypes

    from windows_scan_local_files import verify_private_scan_root

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
    # GetCurrentProcessToken() is a Windows pseudo-handle and does not need closing.
    token = ctypes.wintypes.HANDLE(-4)
    token_user = 1  # TOKEN_INFORMATION_CLASS.TokenUser
    size = ctypes.wintypes.DWORD()
    security.GetTokenInformation(token, token_user, None, 0, ctypes.byref(size))
    if ctypes.get_last_error() != 122:  # ERROR_INSUFFICIENT_BUFFER
        raise ctypes.WinError(ctypes.get_last_error())
    user = ctypes.create_string_buffer(size.value)
    if not security.GetTokenInformation(token, token_user, user, size, ctypes.byref(size)):
        raise ctypes.WinError(ctypes.get_last_error())
    # TOKEN_USER starts with SID_AND_ATTRIBUTES.Sid.
    sid = ctypes.wintypes.LPWSTR()
    if not security.ConvertSidToStringSidW(
        ctypes.wintypes.LPVOID.from_buffer(user), ctypes.byref(sid)
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        owner = "" if exist_ok else f"O:{sid.value}"
        dacl = f"{owner}D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{sid.value})"
    finally:
        kernel.LocalFree(sid)

    descriptor = ctypes.wintypes.LPVOID()
    if not security.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        dacl, 1, ctypes.byref(descriptor), None
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        attributes = SecurityAttributes(ctypes.sizeof(SecurityAttributes), descriptor, False)
        if kernel.CreateDirectoryW(str(path), ctypes.byref(attributes)):
            if exist_ok:
                return path
            return verify_private_scan_root(path, descriptor)
        error = ctypes.get_last_error()
        if exist_ok and error == 183 and path.is_dir():  # ERROR_ALREADY_EXISTS
            return path
        raise ctypes.WinError(error)
    finally:
        kernel.LocalFree(descriptor)


def create_private_directory(path: Path) -> None:
    """Create missing directories privately without changing existing permissions."""
    if os.name == "nt" and path.is_dir():
        return
    try:
        if os.name == "nt":
            _create_private_windows_directory(path, exist_ok=True)
        else:
            path.mkdir(mode=0o700, exist_ok=True)
    except FileNotFoundError:
        if path.parent == path:
            raise
        create_private_directory(path.parent)
        if os.name == "nt":
            _create_private_windows_directory(path, exist_ok=True)
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
            return _create_private_windows_directory(path, exist_ok=False)
        except FileExistsError:
            continue
    raise FileExistsError(f"Could not create a unique directory beneath {parent}.")


def require_canonical_scan_directory(scan_dir: Path) -> Path:
    scan_dir = scan_dir.absolute()
    try:
        metadata = scan_dir.lstat()
        resolved = scan_dir.resolve(strict=True)
    except OSError as exc:
        raise SystemExit(
            "Scan directory must be an existing canonical non-symlink directory."
        ) from exc
    if not stat.S_ISDIR(metadata.st_mode) or os.path.normcase(resolved) != os.path.normcase(
        scan_dir
    ):
        raise SystemExit("Scan directory must be an existing canonical non-symlink directory.")
    # Re-check ownership and parents so the scan directory cannot be substituted.
    if os.name != "nt":
        geteuid = getattr(os, "geteuid", None)
        effective_uid = geteuid() if geteuid is not None else None
        if effective_uid is not None and metadata.st_uid != effective_uid:
            raise SystemExit("Scan directory must be owned by the current user.")
        for parent in scan_dir.parents:
            try:
                parent_metadata = parent.lstat()
            except OSError as exc:
                raise SystemExit("Scan output parent could not be inspected.") from exc
            if not stat.S_ISDIR(parent_metadata.st_mode) or stat.S_ISLNK(parent_metadata.st_mode):
                raise SystemExit("Scan output parent must be a non-symlink directory.")
            if effective_uid is not None and parent_metadata.st_uid not in {
                0,
                effective_uid,
            }:
                raise SystemExit("Scan output parent must have a trusted owner.")
            if (
                stat.S_IMODE(parent_metadata.st_mode) & 0o022
                and not parent_metadata.st_mode & stat.S_ISVTX
            ):
                raise SystemExit(
                    "Scan output parent must not be group- or world-writable without the sticky bit."
                )
    return scan_dir


def available_artifact_path(scan_dir: Path, candidate: Path) -> Path | None:
    try:
        resolved_scan_dir = require_canonical_scan_directory(scan_dir)
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(resolved_scan_dir)
    except (FileNotFoundError, RuntimeError, SystemExit, ValueError):
        return None
    if os.path.normcase(resolved) != os.path.normcase(candidate) or not candidate.is_file():
        return None
    return resolved


def artifact_path(scan_dir: Path, file_name: str, *, required: bool) -> Path | None:
    scan_dir = require_canonical_scan_directory(scan_dir)
    candidate = scan_dir / file_name
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(scan_dir.resolve())
    except (FileNotFoundError, RuntimeError, ValueError) as exc:
        if not required and isinstance(exc, FileNotFoundError):
            return None
        raise SystemExit(
            f"{file_name}: expected a regular file inside the scan directory."
        ) from exc
    if os.path.normcase(resolved) != os.path.normcase(candidate) or not candidate.is_file():
        raise SystemExit(f"{file_name}: expected a regular non-symlink file.")
    return resolved


def require_scan_relative_file(scan: sqlite3.Row, value: str) -> str:
    if len(value) > 4096:
        raise SystemExit("Text value must be no longer than 4096 characters.")
    if not value.strip() or "\\" in value:
        raise SystemExit("Patch path must identify a scan-local regular file.")
    parsed = PurePosixPath(value)
    if parsed.is_absolute() or ".." in parsed.parts:
        raise SystemExit("Patch path must identify a scan-local regular file.")
    artifact_path(Path(scan["scan_dir"]), parsed.as_posix(), required=True)
    return parsed.as_posix()


def open_scan_local_file(scan_dir: Path, relative_path: str) -> Any:
    parsed = PurePosixPath(relative_path)
    if parsed.is_absolute() or not parsed.parts or ".." in parsed.parts:
        raise SystemExit("Patch path must identify a scan-local regular file.")
    scan_dir = require_canonical_scan_directory(scan_dir)
    try:
        file_fd = open_scan_local_file_descriptor(
            scan_dir,
            parsed.as_posix(),
            "Patch path",
        )
        return os.fdopen(file_fd, "rb")
    except (ContractError, OSError) as exc:
        raise SystemExit("Patch path must identify a scan-local regular file.") from exc
