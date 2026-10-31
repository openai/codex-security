from __future__ import annotations

import ctypes
import errno
import os
import secrets
from contextlib import ExitStack
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


def test_write_retries_after_umask_denies_owner_write(tmp_path: Path) -> None:
    relative_path = "remediation/request/generated.patch"
    patch = b"--- a/source.txt\n+++ b/source.txt\n@@ -1 +1 @@\n-old\n+new\n"
    previous_umask = os.umask(0o200)
    try:
        with pytest.raises(FINALIZER.ScanLocalIOError):
            FINALIZER.write_scan_local_bytes(tmp_path, relative_path, patch, owner_read_write=True)
        assert not (tmp_path / "remediation").exists()

        os.umask(0o022)
        FINALIZER.write_scan_local_bytes(tmp_path, relative_path, patch, owner_read_write=True)
    finally:
        os.umask(previous_umask)
    assert (tmp_path / relative_path).read_bytes() == patch


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


@pytest.mark.parametrize("outcome", ["saved", "collision", "no-rename", "link-out-of-space"])
def test_new_patch_on_a_filesystem_without_hardlinks(tmp_path, monkeypatch, outcome):
    destination = tmp_path / "generated.patch"
    patch = b"--- a/source.txt\n+++ b/source.txt\n@@ -1 +1 @@\n-old\n+new\n"
    winner = b"concurrent patch"
    with ExitStack() as files:
        staged = None

        def unavailable(source, _destination, *, src_dir_fd, **_kwargs):
            nonlocal staged
            # Hold the flushed inode so a direct copy cannot reuse its inode number.
            staged = files.enter_context(
                open(
                    source, "rb", opener=lambda name, flags: os.open(name, flags, dir_fd=src_dir_fd)
                )
            )
            if outcome == "link-out-of-space":
                raise OSError(errno.ENOSPC, "hardlink failed for a storage error")
            if outcome == "collision":
                destination.write_bytes(winner)
            raise OSError(errno.ENOTSUP, "hardlink unavailable")

        monkeypatch.setattr(os, "link", unavailable)
        if outcome == "no-rename":
            monkeypatch.setattr(ctypes, "CDLL", lambda *args, **kwargs: object())
        if outcome == "saved":
            FINALIZER.write_scan_local_bytes(
                tmp_path, destination.name, patch, replace_existing=False
            )
            assert os.path.samestat(os.fstat(staged.fileno()), destination.stat())
            assert destination.read_bytes() == patch
        else:
            with pytest.raises(OSError) as failed:
                FINALIZER.write_scan_local_bytes(
                    tmp_path, destination.name, patch, replace_existing=False
                )
            if outcome == "collision":
                assert isinstance(failed.value, FileExistsError)
                assert destination.read_bytes() == winner
            else:
                assert not destination.exists()
                if outcome == "no-rename":
                    assert "exclusive rename" in str(failed.value)
                else:
                    assert failed.value.errno == errno.ENOSPC
    assert not list(tmp_path.glob(".*.tmp"))


@pytest.mark.parametrize("moved", ["parent", "scan"])
def test_new_patch_rejects_directory_moved_outside_the_admitted_scan(tmp_path, moved):
    scan = tmp_path / "scan"
    scan.mkdir()
    path = "artifacts/remediation/request/generated.patch"
    destination = scan / path
    outside = tmp_path / "outside"
    with FINALIZER.stage_scan_local_bytes(scan, path, b"patch") as publish:
        directory = destination.parent if moved == "parent" else scan
        directory.rename(outside)
        directory.mkdir()
        with pytest.raises(FINALIZER.ContractError, match="changed"):
            publish(scan)
    assert not destination.exists()
    assert not list(outside.rglob("*.patch"))
    assert not list(outside.rglob("*.tmp"))


def test_new_patch_rejects_same_size_edit_during_publication(tmp_path, monkeypatch):
    destination = tmp_path / "generated.patch"
    link = os.link

    def edit_after_publication(*args, **kwargs):
        link(*args, **kwargs)
        before = destination.stat()
        destination.write_bytes(b"other")
        # Make the modification visible even on filesystems with coarse timestamps.
        os.utime(destination, ns=(before.st_atime_ns, before.st_mtime_ns + 2_000_000_000))

    monkeypatch.setattr(os, "link", edit_after_publication)
    with pytest.raises(FINALIZER.ContractError, match="staged contents changed during publication"):
        FINALIZER.write_scan_local_bytes(
            tmp_path, destination.name, b"first", replace_existing=False
        )
    assert destination.read_bytes() == b"other"
    assert list(tmp_path.iterdir()) == [destination]


def test_existing_temporary_file_survives_a_name_collision(tmp_path, monkeypatch):
    monkeypatch.setattr(secrets, "token_hex", lambda _: "collision")
    existing = tmp_path / ".generated.patch.collision.tmp"
    existing.write_bytes(b"another writer")
    with pytest.raises(FileExistsError):
        FINALIZER.write_scan_local_bytes(
            tmp_path, "generated.patch", b"new", replace_existing=False
        )
    assert existing.read_bytes() == b"another writer"
    assert not (tmp_path / "generated.patch").exists()
