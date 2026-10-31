from __future__ import annotations

import argparse
import errno
import os
import shutil
import sqlite3
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack, contextmanager
from pathlib import Path
from threading import Event

import pytest
from test_deep_scan_publication_authority import emulate_windows_atomic_write
from test_workbench_archive import recipe, register
from test_workbench_remediation_retry import pending_generation as pending_generation
from workbench_test_support import load_script

pytestmark = pytest.mark.native_windows

WINDOWS_FILES = load_script("windows_scan_local_files")


@pytest.mark.parametrize(
    "relative_path",
    (
        "artifacts/result.json:stream",
        "artifacts/C:result.json",
        "artifacts/NUL.json",
        "artifacts/COM1",
        "artifacts/COM¹.txt",
        "artifacts/trailing-dot.",
        "artifacts/trailing-space ",
    ),
)
def test_rejects_windows_filesystem_aliases(relative_path: str) -> None:
    with pytest.raises(WINDOWS_FILES.WindowsScanLocalFileError):
        WINDOWS_FILES._validated_parts(relative_path)


def test_accepts_normal_scan_local_path() -> None:
    assert WINDOWS_FILES._validated_parts("artifacts/02_discovery/work.jsonl") == (
        "artifacts",
        "02_discovery",
        "work.jsonl",
    )


@pytest.mark.skipif(os.name != "nt", reason="requires native Win32 security APIs")
def test_directory_acl_copy_does_not_create_from_a_missing_source(tmp_path: Path) -> None:
    destination = tmp_path / "replacement"
    with pytest.raises(WINDOWS_FILES.WindowsScanLocalFileError):
        WINDOWS_FILES.create_directory_with_same_dacl(destination, tmp_path / "missing")
    assert not destination.exists()


@pytest.mark.skipif(os.name != "nt", reason="requires native Win32 security APIs")
def test_directory_acl_copy_does_not_reuse_an_existing_destination(tmp_path: Path) -> None:
    source = tmp_path / "original"
    destination = tmp_path / "replacement"
    source.mkdir()
    destination.mkdir()
    marker = destination / "retained.txt"
    marker.write_text("synthetic retained data", encoding="utf-8")
    with pytest.raises(WINDOWS_FILES.WindowsScanLocalFileError):
        WINDOWS_FILES.create_directory_with_same_dacl(destination, source)
    assert marker.read_text(encoding="utf-8") == "synthetic retained data"


@pytest.mark.skipif(os.name != "nt", reason="requires native Win32 file APIs")
def test_native_windows_backend_writes_reads_replaces_and_deletes(tmp_path: Path) -> None:
    scan_dir = tmp_path / "scan"
    scan_dir.mkdir()

    WINDOWS_FILES.atomic_write(scan_dir, "exports/results.sarif", b"first")
    descriptor = WINDOWS_FILES.open_read_fd(
        scan_dir, "exports/results.sarif", "native Windows test"
    )
    with os.fdopen(descriptor, "rb") as handle:
        assert handle.read() == b"first"

    descriptor, filename = WINDOWS_FILES.open_read_fd_with_path(
        scan_dir, "exports/RESULTS.sarif", "native Windows spelling test"
    )
    with os.fdopen(descriptor, "rb") as handle:
        assert handle.read() == b"first"
    assert filename == "exports/results.sarif"

    WINDOWS_FILES.atomic_write(scan_dir, "exports/results.sarif", b"replacement")
    assert (scan_dir / "exports" / "results.sarif").read_bytes() == b"replacement"

    WINDOWS_FILES.unlink_if_exists(scan_dir, "exports/results.sarif")
    assert not (scan_dir / "exports" / "results.sarif").exists()
    WINDOWS_FILES.unlink_if_exists(scan_dir, "exports/results.sarif")


@pytest.mark.skipif(os.name != "nt", reason="requires native Win32 file APIs")
def test_create_only_write_reports_existing_patch_when_disk_is_full(
    tmp_path: Path, monkeypatch
) -> None:
    destination = tmp_path / "reviewed.patch"
    patch = b"previously saved patch"
    destination.write_bytes(patch)

    def disk_full(*args):
        raise OSError(errno.ENOSPC, "synthetic disk full")

    monkeypatch.setattr(WINDOWS_FILES, "_write_all", disk_full)
    with pytest.raises(FileExistsError):
        WINDOWS_FILES.atomic_write(tmp_path, destination.name, patch, replace_existing=False)
    assert destination.read_bytes() == patch


@pytest.mark.parametrize("outcome", ["publish", "archive", "abandon", "collision", "substitution"])
def test_staged_patch_is_visible_only_after_publication(tmp_path, monkeypatch, outcome):
    scan_dir = tmp_path / "scan"
    scan_dir.mkdir()
    destination = scan_dir / "reviewed.patch"
    patch = b"generated patch\n"
    with ExitStack() as files:
        backend = WINDOWS_FILES
        if os.name != "nt":
            backend = emulate_windows_atomic_write(
                monkeypatch, load_script("finalize_scan_contract"), files
            )
        with backend.stage_write(scan_dir, destination.name, patch) as publish:
            assert not destination.exists()
            if outcome in {"publish", "archive"}:
                if outcome == "archive":
                    archived = tmp_path / "archived-scan"
                    scan_dir.rename(archived)
                    scan_dir.mkdir()
                    destination = archived / destination.name
                saved, change = publish(destination.parent)
                assert destination.read_bytes() == patch
                with destination.open("rb") as current:
                    metadata = os.fstat(current.fileno())
                    assert os.path.samestat(saved, metadata)
                    assert (saved.st_size, saved.st_mtime_ns) == (
                        metadata.st_size,
                        metadata.st_mtime_ns,
                    )
                    assert change == backend.file_change_time(current.fileno())
            elif outcome == "collision":
                destination.write_bytes(b"competing patch\n")
                with pytest.raises(FileExistsError):
                    publish()
            elif outcome == "substitution":
                (temp,) = scan_dir.glob(".*.tmp")
                # Keep the original inode alive. Match the temp size and timestamp.
                original = temp.rename(scan_dir / "original")
                temp.write_bytes(b"different bytes\n")
                original_stat = original.stat()
                os.utime(temp, ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns))
                with pytest.raises(backend.WindowsScanLocalPathError, match="staged patch changed"):
                    publish()
        if outcome == "substitution":
            assert temp.read_bytes() == b"different bytes\n"
            assert not destination.exists()
        else:
            assert not list(destination.parent.glob(".*.tmp"))
        if outcome == "abandon":
            assert not destination.exists()
        elif outcome == "collision":
            assert destination.read_bytes() == b"competing patch\n"
        elif outcome == "archive":
            assert not list(scan_dir.iterdir())


@pytest.mark.parametrize("other_state", [False, True])
def test_canceled_generation_removes_its_staged_patch_after_archive(
    pending_generation, workbench_api, tmp_path, monkeypatch, other_state
):
    database, scan_dir, _, args, _ = pending_generation
    remediation = workbench_api["remediation_state"]
    stage = remediation.stage_scan_local_bytes
    archived = None
    replacement = None

    @contextmanager
    def archive_and_cancel(*stage_args, **options):
        nonlocal archived, replacement
        with ExitStack() as files:
            if os.name != "nt":
                emulation = files.enter_context(monkeypatch.context())
                backend = emulate_windows_atomic_write(
                    emulation, sys.modules[stage.__module__], files
                )
                emulation.setattr(backend, "_create_directory", Path.mkdir)
            with stage(*stage_args, **options) as publish:
                registered = register(
                    tmp_path / "other-state" if other_state else database.parent,
                    tmp_path / "target",
                    scan_dir,
                    "--archive-existing",
                )
                archived = Path(registered["archivedScanDir"])
                (temp,) = archived.rglob("*.tmp")
                replacement = scan_dir / temp.relative_to(archived)
                replacement.parent.mkdir(parents=True)
                replacement.write_bytes(b"new scan's file")
                with sqlite3.connect(database) as other:
                    other.row_factory = sqlite3.Row
                    remediation.cancel_finding_remediation_request(other, args)
                yield publish

    monkeypatch.setattr(remediation, "stage_scan_local_bytes", archive_and_cancel)
    with sqlite3.connect(database) as connection:
        connection.row_factory = sqlite3.Row
        with pytest.raises(SystemExit, match="remediation request changed"):
            workbench_api["set_finding_remediation"](connection, args)
    assert not list(archived.rglob("*.tmp"))
    assert not list(archived.rglob("*.patch"))
    assert replacement.read_bytes() == b"new scan's file"


def test_staging_metadata_failure_removes_the_flushed_file(tmp_path, monkeypatch):
    with ExitStack() as files:
        backend = WINDOWS_FILES
        if os.name != "nt":
            backend = emulate_windows_atomic_write(
                monkeypatch, load_script("finalize_scan_contract"), files
            )

        def fail_metadata(_):
            raise OSError(errno.EIO, "metadata unavailable")

        monkeypatch.setattr(backend, "file_change_time", fail_metadata)
        with pytest.raises(OSError, match="metadata unavailable"):
            with backend.stage_write(tmp_path, "reviewed.patch", b"reviewed bytes"):
                pytest.fail("staging should have failed")
    assert not list(tmp_path.iterdir())


@pytest.mark.skipif(os.name != "nt", reason="requires native Win32 archive sharing semantics")
@pytest.mark.parametrize("timeout", [5, 0], ids=["retry", "no-wait"])
def test_archive_contention_during_windows_patch_write(
    pending_generation, workbench_api, tmp_path, monkeypatch, timeout
):
    database, scan_dir, _, args, patch = pending_generation
    backend = sys.modules["windows_scan_local_files"]
    write_all = backend._write_all
    rename = Path.rename
    writing, rename_denied = Event(), Event()

    def write_while_archiving(handle, data):
        if data == patch:
            writing.set()
            assert rename_denied.wait(10)
            # A different writer can commit before the patch releases its open handles.
            with sqlite3.connect(database) as other:
                other.execute("BEGIN IMMEDIATE")
                other.execute("CREATE TABLE unrelated_write (value INTEGER)")
        return write_all(handle, data)

    def observe_rename(source, destination):
        try:
            return rename(source, destination)
        except PermissionError as exc:
            if source == scan_dir and exc.winerror in {5, 32}:
                rename_denied.set()
            raise

    def archive():
        assert writing.wait(10)
        target = tmp_path / "target"
        registration = argparse.Namespace(
            repository=str(target),
            scan_dir=str(scan_dir),
            archive_existing=True,
            archived_scan_dir=None,
            recipe_json=recipe(target),
            recipe_json_stdin=False,
            registration_json_stdin=False,
            parent_scan_id=None,
        )
        with sqlite3.connect(database, timeout=timeout) as connection:
            connection.row_factory = sqlite3.Row
            return Path(
                workbench_api["register_cli_scan"](connection, registration)["archivedScanDir"]
            )

    monkeypatch.setattr(backend, "_write_all", write_while_archiving)
    monkeypatch.setattr(Path, "rename", observe_rename)
    with ThreadPoolExecutor(max_workers=1) as pool, sqlite3.connect(database) as connection:
        future = pool.submit(archive)
        connection.row_factory = sqlite3.Row
        result = workbench_api["set_finding_remediation"](connection, args)
        if timeout:
            archived = future.result(timeout=10)
        else:
            with pytest.raises(PermissionError) as denied:
                future.result(timeout=10)
            assert denied.value.winerror in {5, 32}
            assert not list(scan_dir.parent.glob(f"{scan_dir.name}.previous-*"))
            archived = scan_dir
    recorded = result["scan"]["findings"][0]["remediationState"]["patchPath"]
    assert (archived / recorded).read_bytes() == patch
    if timeout:
        assert not (scan_dir / recorded).exists()


@pytest.mark.skipif(os.name != "nt", reason="requires native Win32 reparse-point behavior")
def test_native_windows_backend_rejects_symlink_ancestor(tmp_path: Path) -> None:
    scan_dir = tmp_path / "scan"
    external_dir = tmp_path / "external"
    scan_dir.mkdir()
    external_dir.mkdir()
    try:
        (scan_dir / "exports").symlink_to(external_dir, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"creating a Windows directory symlink requires host support: {exc}")

    with pytest.raises(WINDOWS_FILES.WindowsScanLocalFileError):
        WINDOWS_FILES.atomic_write(scan_dir, "exports/results.sarif", b"blocked")
    assert not (external_dir / "results.sarif").exists()


@pytest.mark.skipif(os.name != "nt", reason="requires native Win32 junction APIs")
@pytest.mark.parametrize("dangling", [False, True], ids=["unicode", "dangling"])
def test_native_copy_junction_retains_raw_target_and_cleanup(
    tmp_path: Path, dangling: bool
) -> None:
    target = tmp_path / "Mixed-Case-日本語"
    target.mkdir()
    source = tmp_path / "source"
    subprocess.run(["cmd", "/c", "mklink", "/J", str(source), str(target)], check=True)
    if dangling:
        target.rmdir()
    else:
        (target / "keep.txt").write_text("external contents\n")
    copied_tree = tmp_path / "copy"
    copied_tree.mkdir()
    destination = copied_tree / "linked"
    destination.mkdir()
    WINDOWS_FILES.copy_directory_junction(source, destination)
    assert os.readlink(destination) == os.readlink(source)
    assert destination.lstat().st_reparse_tag == source.lstat().st_reparse_tag
    shutil.rmtree(copied_tree)
    if dangling:
        assert not target.exists()
    else:
        assert (target / "keep.txt").read_text() == "external contents\n"


@pytest.mark.skipif(os.name != "nt", reason="requires native Win32 junction APIs")
def test_native_copy_junction_rejects_nonempty_destination(tmp_path: Path) -> None:
    target = tmp_path / "outside"
    target.mkdir()
    source = tmp_path / "source"
    subprocess.run(["cmd", "/c", "mklink", "/J", str(source), str(target)], check=True)
    destination = tmp_path / "destination"
    destination.mkdir()
    (destination / "keep.txt").write_text("placeholder contents\n")
    with pytest.raises(WINDOWS_FILES.WindowsScanLocalFileError):
        WINDOWS_FILES.copy_directory_junction(source, destination)
    assert (destination / "keep.txt").read_text() == "placeholder contents\n"
    assert not (target / "keep.txt").exists()


@pytest.mark.parametrize("changed", ["root", "ancestor"])
@pytest.mark.parametrize("replacement", ["missing", "file"])
def test_native_directory_change_after_probe_remains_a_path_error(
    tmp_path: Path, monkeypatch, changed: str, replacement: str
) -> None:
    finalizer = load_script("finalize_scan_contract")
    ancestor = tmp_path / "ancestor"
    scan_dir = ancestor / "scan"
    scan_dir.mkdir(parents=True)
    (scan_dir / "keep.txt").write_bytes(b"Accepted content")
    finalizer.write_scan_local_bytes(scan_dir, "new-parent/receipt.json", b"Ordinary creation")
    assert (scan_dir / "new-parent/receipt.json").read_bytes() == b"Ordinary creation"
    moved = tmp_path / "retained"
    target = scan_dir if changed == "root" else ancestor
    retained_scan = moved if changed == "root" else moved / "scan"
    mutated = False
    # Windows exercises the actual CreateFileW boundary; POSIX is a native
    # control at its existing directory-validation boundary.
    owner = finalizer._windows_scan_local_files() if os.name == "nt" else finalizer
    name = "_canonical_scan_directory" if os.name == "nt" else "_require_scan_directory"
    original = getattr(owner, name)

    def replace_after_probe(path):
        nonlocal mutated
        result = original(path)
        if path == scan_dir and not mutated:
            mutated = True
            target.rename(moved)
            if replacement == "file":
                target.write_bytes(b"Replacement file")
        return result

    monkeypatch.setattr(owner, name, replace_after_probe)
    with pytest.raises(finalizer.ContractError) as rejected:
        finalizer.write_scan_local_bytes(scan_dir, "drafts/receipt.json", b"receipt")
    assert not isinstance(rejected.value, finalizer.ScanLocalIOError)
    assert mutated
    assert (retained_scan / "keep.txt").read_bytes() == b"Accepted content"
    assert not (retained_scan / "drafts/receipt.json").exists()
