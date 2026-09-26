"""Storage paths and scan locks shared by workbench persistence and MCP artifact selection."""

from __future__ import annotations

import errno
import os
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from workbench_validation import require_uuid

try:
    import fcntl as posix_file_lock
except ModuleNotFoundError:  # pragma: no cover
    posix_file_lock = None

try:
    import msvcrt as windows_file_lock
except ModuleNotFoundError:  # pragma: no cover
    windows_file_lock = None

_completion_locks = threading.local()


def state_dir() -> Path:
    state_dir = os.environ.get("CODEX_SECURITY_STATE_DIR")
    if state_dir:
        return Path(state_dir).expanduser().resolve()
    codex_home = Path(os.environ.get("CODEX_HOME", "~/.codex")).expanduser()
    return (codex_home / "state" / "plugins" / "codex-security").resolve()


def resolve_scan_root(scan_root: str | None) -> Path:
    return Path(scan_root).expanduser().resolve() if scan_root else state_dir() / "scans"


@contextmanager
def scan_completion_lock(scan_id: str) -> Iterator[None]:
    lock_dir = state_dir() / "completion-locks"
    lock_dir.mkdir(parents=True, exist_ok=True)
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
