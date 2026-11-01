from __future__ import annotations

import errno
import os
from pathlib import Path
from unittest import mock

import pytest
from workbench_test_support import load_script

FINALIZER = load_script("finalize_scan_contract")
pytestmark = [
    pytest.mark.native_macos,
    pytest.mark.skipif(
        not FINALIZER._descriptor_relative_writes_available(),
        reason="requires descriptor-relative file operations",
    ),
]


@pytest.mark.parametrize("failure", [None, "write", "write_and_unlink", "parent_close"])
def test_atomic_write_closes_directories_after_cleanup_failures(
    tmp_path: Path, failure: str | None
) -> None:
    destination = tmp_path / "report.md"
    destination.write_bytes(b"original")
    directory_fds: list[int] = []
    open_root = FINALIZER._open_verified_scan_directory
    open_parent = FINALIZER._open_scan_local_directory
    close = os.close
    fsync = os.fsync
    unlink = os.unlink
    write_error = OSError(errno.ENOSPC, "synthetic write failure")
    unlink_error = OSError(errno.EIO, "synthetic temporary-file cleanup failure")
    close_error = OSError(errno.EIO, "synthetic parent-directory close failure")

    def record_root(*args, **kwargs):
        descriptor = open_root(*args, **kwargs)
        directory_fds.append(descriptor)
        return descriptor

    def record_parent(*args, **kwargs):
        descriptor = open_parent(*args, **kwargs)
        directory_fds.append(descriptor)
        return descriptor

    def sync_file(descriptor: int) -> None:
        if failure in {"write", "write_and_unlink"}:
            raise write_error
        fsync(descriptor)

    def remove_temp(path, *, dir_fd=None) -> None:
        if failure == "write_and_unlink":
            raise unlink_error
        unlink(path, dir_fd=dir_fd)

    def close_directory(descriptor: int) -> None:
        close(descriptor)
        if failure == "parent_close" and descriptor == directory_fds[-1]:
            raise close_error

    try:
        with (
            mock.patch.object(FINALIZER, "_open_verified_scan_directory", record_root),
            mock.patch.object(FINALIZER, "_open_scan_local_directory", record_parent),
            mock.patch.object(os, "fsync", sync_file),
            mock.patch.object(os, "unlink", remove_temp),
            mock.patch.object(os, "supports_dir_fd", os.supports_dir_fd | {remove_temp}),
            mock.patch.object(os, "close", close_directory),
        ):
            if failure is None:
                FINALIZER.write_scan_local_bytes(tmp_path, "report.md", b"replacement")
            else:
                with pytest.raises(OSError) as raised:
                    FINALIZER.write_scan_local_bytes(tmp_path, "report.md", b"replacement")
                if failure == "write":
                    assert raised.value is write_error
                elif failure == "write_and_unlink":
                    assert raised.value is unlink_error
                    assert raised.value.__context__ is write_error
                else:
                    assert raised.value is close_error

        assert len(directory_fds) == 2
        for descriptor in directory_fds:
            with pytest.raises(OSError) as closed:
                os.fstat(descriptor)
            assert closed.value.errno == errno.EBADF
        if failure in {"write", "write_and_unlink"}:
            assert destination.read_bytes() == b"original"
        else:
            assert destination.read_bytes() == b"replacement"
        staging = list(tmp_path.glob(".report.md.*.tmp"))
        assert len(staging) == (1 if failure == "write_and_unlink" else 0)
    finally:
        # Keep a failed regression assertion from leaking descriptors in the test runner.
        for descriptor in directory_fds:
            try:
                os.fstat(descriptor)
            except OSError as error:
                if error.errno != errno.EBADF:
                    raise
            else:
                close(descriptor)
