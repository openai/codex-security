"""Stage and publish POSIX scan-local files through verified directory descriptors."""

from __future__ import annotations

import argparse
import errno
import os
import secrets
import stat
import sys
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path, PurePosixPath


def descriptor_relative_writes_available() -> bool:
    # os.replace accepts src_dir_fd/dst_dir_fd wherever descriptor-relative
    # os.rename is supported, but Python lists only os.rename in supports_dir_fd.
    required_operations = (os.mkdir, os.open, os.rename, os.stat, os.unlink)
    return hasattr(os, "O_NOFOLLOW") and all(
        operation in os.supports_dir_fd for operation in required_operations
    )


@contextmanager
def managed_fd(descriptor: int) -> Iterator[int]:
    try:
        yield descriptor
    finally:
        os.close(descriptor)


@contextmanager
def stage_file(
    parent_fd: int, filename: str, payload: bytes, owner_read_write: bool
) -> Iterator[int]:
    descriptor = os.open(filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=parent_fd)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            if owner_read_write:
                os.fchmod(descriptor, 0o600)
            handle.write(payload)
            handle.flush()
            os.fsync(descriptor)
        yield descriptor
    finally:
        try:
            entry = os.stat(filename, dir_fd=parent_fd, follow_symlinks=False)
            if os.path.samestat(os.fstat(descriptor), entry):
                os.unlink(filename, dir_fd=parent_fd)
        except FileNotFoundError:
            # Successful publication has already removed the temporary name.
            pass
        finally:
            os.close(descriptor)


def _rename_exclusive(parent_fd: int, source: str, destination: str) -> None:
    import ctypes

    libc = ctypes.CDLL(None, use_errno=True)
    if sys.platform == "linux":
        rename = getattr(libc, "renameat2", None)
        flag = 1  # RENAME_NOREPLACE
    elif sys.platform == "darwin":
        rename = getattr(libc, "renameatx_np", None)
        flag = 4  # RENAME_EXCL
    else:
        rename = None
    code = errno.ENOSYS
    if rename is not None:
        rename.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        rename.restype = ctypes.c_int
        if rename(parent_fd, os.fsencode(source), parent_fd, os.fsencode(destination), flag) == 0:
            return
        code = ctypes.get_errno()
    detail = os.strerror(code)
    if code in {errno.ENOSYS, errno.ENOTSUP, errno.EOPNOTSUPP, errno.EINVAL}:
        detail = f"cannot publish a new file atomically without hard links or exclusive rename ({detail})"
    raise OSError(code, detail, destination)


def publish_new_file(parent_fd: int, source: str, destination: str) -> None:
    try:
        os.link(
            source, destination, src_dir_fd=parent_fd, dst_dir_fd=parent_fd, follow_symlinks=False
        )
    except OSError as exc:
        if exc.errno not in {
            errno.EPERM,
            errno.ENOTSUP,
            errno.EOPNOTSUPP,
            errno.ENOSYS,
            errno.EXDEV,
            errno.EMLINK,
        }:
            raise
        _rename_exclusive(parent_fd, source, destination)
    else:
        os.unlink(source, dir_fd=parent_fd)


@contextmanager
def stage_write(
    parent_fd: int,
    relative_path: str,
    payload: bytes,
    *,
    owner_read_write: bool,
    replace_existing: bool,
    compare_existing: bool,
    check_parent: Callable[[Path], None],
    contract_error: type[ValueError],
) -> Iterator[Callable[..., tuple[os.stat_result, int]]]:
    name = PurePosixPath(relative_path).name
    # Stage through the held parent so a replacement path cannot redirect the write.
    try:
        metadata = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        pass
    else:
        if not replace_existing:
            raise FileExistsError(errno.EEXIST, os.strerror(errno.EEXIST), relative_path)
        if not stat.S_ISREG(metadata.st_mode):
            raise contract_error(f"{relative_path}: expected a regular non-symlink file")
        try:
            existing_fd = os.open(
                name,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0),
                dir_fd=parent_fd,
            )
        except OSError as exc:
            if exc.errno not in {errno.ENOENT, errno.EACCES, errno.EPERM}:
                raise
        else:
            with managed_fd(existing_fd):
                opened = os.fstat(existing_fd)
                if not stat.S_ISREG(opened.st_mode):
                    raise contract_error(f"{relative_path}: expected a regular non-symlink file")
                if not os.path.samestat(opened, metadata):
                    raise contract_error(f"{relative_path}: changed while it was being opened")
                if compare_existing and opened.st_size == len(payload):
                    from windows_scan_local_files import stream_matches_payload

                    try:
                        with os.fdopen(existing_fd, "rb", closefd=False) as handle:
                            matches = stream_matches_payload(handle, payload)
                    except OSError:
                        # A failed content comparison still allows an atomic replacement.
                        matches = False
                    if matches:
                        yield lambda _directory=None: (opened, opened.st_ctime_ns)
                        return
    candidate = f".{name}.{secrets.token_hex(8)}.tmp"

    with stage_file(parent_fd, candidate, payload, owner_read_write) as staged_fd:
        staged = os.fstat(staged_fd)

        def publish(directory: Path | None = None) -> tuple[os.stat_result, int]:
            if directory is not None:
                check_parent(directory)
            if replace_existing:
                os.replace(candidate, name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
                return staged, staged.st_ctime_ns
            named = os.stat(candidate, dir_fd=parent_fd, follow_symlinks=False)
            if not os.path.samestat(staged, named) or staged.st_ctime_ns != named.st_ctime_ns:
                raise contract_error(f"{relative_path}: staged file changed before publication")
            publish_new_file(parent_fd, candidate, name)
            published = os.fstat(staged_fd)
            if (staged.st_size, staged.st_mtime_ns) != (
                published.st_size,
                published.st_mtime_ns,
            ):
                raise contract_error(f"{relative_path}: staged contents changed during publication")
            return published, published.st_ctime_ns

        yield publish


if __name__ == "__main__":
    argparse.ArgumentParser(description=__doc__).parse_args()
