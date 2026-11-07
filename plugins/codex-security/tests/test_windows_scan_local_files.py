"""Exercise Windows scan-local path handling across aliases, junctions, and replacement races."""

from __future__ import annotations

import argparse
import ctypes
import errno
import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack, contextmanager
from pathlib import Path
from threading import Event
from types import SimpleNamespace
from unittest import mock
from unittest.mock import Mock

import pytest
from test_workbench_archive import recipe, register
from test_workbench_remediation_retry import pending_generation as pending_generation
from workbench_test_support import load_script

pytestmark = pytest.mark.native_windows


WINDOWS_FILES = load_script("windows_scan_local_files")


@pytest.mark.parametrize("error_code", [2, 3, 5, errno.EINVAL])
def test_saved_checkpoint_fallback_classifies_windows_missing_errors(
    tmp_path: Path, workbench_api, monkeypatch: pytest.MonkeyPatch, error_code: int
) -> None:
    saved = workbench_api["saved_results"]
    finalizer = sys.modules[saved._read_scan_local_json.__module__]
    payload = {"scanId": "fixture-scan", "findings": [], "reviewState": {}}
    contents = json.dumps(payload).encode()
    name = hashlib.sha256(contents).hexdigest() + ".json"
    relative = f"checkpoints/{name}"
    staged = "drafts/01234567-89ab-cdef-0123-456789abcdef.checkpoint.json"
    (tmp_path / "checkpoints/pending").mkdir(parents=True)
    (tmp_path / "drafts").mkdir()
    (tmp_path / staged).write_bytes(contents)
    (tmp_path / "checkpoints/pending" / name).write_text(staged)
    error = WINDOWS_FILES.WindowsScanLocalFileError(error_code, "synthetic Windows read error")

    def open_read_fd(root: Path, path: str, _context: str) -> int:
        if path == relative:
            raise error
        return os.open(root / path, os.O_RDONLY)

    monkeypatch.setattr(finalizer.os, "supports_dir_fd", set())
    monkeypatch.setattr(finalizer, "_is_windows", lambda: True)
    monkeypatch.setattr(finalizer, "_windows_scan_local_files", lambda: WINDOWS_FILES)
    monkeypatch.setattr(WINDOWS_FILES, "open_read_fd", open_read_fd)
    if error_code in WINDOWS_FILES._MISSING_ERRORS:
        assert saved._read_saved_result(tmp_path, relative, "fixture-scan")[0] == payload
    else:
        with pytest.raises(finalizer.ContractError) as caught:
            saved._read_saved_result(tmp_path, relative, "fixture-scan")
        assert caught.value.__cause__ is error


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


@pytest.mark.parametrize("relative_path", ["missing.bin", "missing/artifact.bin"])
def test_missing_scan_local_file_reports_a_portable_error(
    tmp_path: Path, relative_path: str
) -> None:
    finalizer = load_script("finalize_scan_contract")

    with pytest.raises(finalizer.MissingScanLocalFileError) as error:
        finalizer.open_scan_local_file_descriptor(tmp_path, relative_path, "Saved artifact")

    assert str(error.value) == "Saved artifact: expected a file inside the scan directory"


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
def test_native_windows_replacement_preserves_an_open_read_snapshot(tmp_path: Path) -> None:
    scan_dir = tmp_path / "scan"
    scan_dir.mkdir()
    path = scan_dir / "scan-manifest.json"
    original = b'{"generation": "original"}\n'
    replacement = b'{"generation": "replacement", "complete": true}\n'
    path.write_bytes(original)

    descriptor = WINDOWS_FILES.open_read_fd(scan_dir, path.name, "held manifest")
    with os.fdopen(descriptor, "rb") as snapshot:
        with pytest.raises(WINDOWS_FILES.WindowsScanLocalFileError) as denied:
            with WINDOWS_FILES._create_file(
                path,
                access=WINDOWS_FILES._GENERIC_WRITE,
                share=(
                    WINDOWS_FILES._FILE_SHARE_READ
                    | WINDOWS_FILES._FILE_SHARE_WRITE
                    | WINDOWS_FILES._FILE_SHARE_DELETE
                ),
                disposition=WINDOWS_FILES._OPEN_EXISTING,
                flags=WINDOWS_FILES._FILE_ATTRIBUTE_NORMAL,
            ):
                pytest.fail("A held snapshot must deny in-place writes")
        assert denied.value.errno == WINDOWS_FILES._ERROR_SHARING_VIOLATION

        WINDOWS_FILES.atomic_write(scan_dir, path.name, replacement)
        assert snapshot.read() == original
        fresh = WINDOWS_FILES.open_read_fd(scan_dir, path.name, "new manifest")
        with os.fdopen(fresh, "rb") as current:
            assert current.read() == replacement
    assert path.read_bytes() == replacement
    assert not list(scan_dir.glob(".codex-security-*.tmp"))


@pytest.mark.skipif(os.name != "nt", reason="requires native Win32 file APIs")
@pytest.mark.parametrize("stage", ["validation", "resolved-name"])
def test_native_windows_read_pins_leaf_until_name_capture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, stage: str
) -> None:
    scan_dir = tmp_path / "scan"
    scan_dir.mkdir()
    path = scan_dir / "manifest.json"
    replacement = scan_dir / "replacement.json"
    path.write_bytes(b"original")
    replacement.write_bytes(b"replacement")
    verify = WINDOWS_FILES._verify_regular_file
    final_path = WINDOWS_FILES._final_path
    attempted = []
    leaf_name_reads = 0

    def replace_while_pinned() -> None:
        with pytest.raises(OSError) as denied:
            os.replace(replacement, path)
        assert denied.value.winerror in {5, 32}
        attempted.append(stage)

    def verify_with_replacement(handle: int, expected: Path) -> None:
        if stage == "validation":
            replace_while_pinned()
        verify(handle, expected)

    def final_path_with_replacement(handle: int, *, opened_name: bool = False) -> str:
        nonlocal leaf_name_reads
        result = final_path(handle, opened_name=opened_name)
        if WINDOWS_FILES._normalized_windows_path(result) == WINDOWS_FILES._normalized_windows_path(
            path
        ):
            leaf_name_reads += 1
            # The first call verifies the path; the second captures its actual spelling.
            if stage == "resolved-name" and leaf_name_reads == 2:
                replace_while_pinned()
        return result

    monkeypatch.setattr(WINDOWS_FILES, "_verify_regular_file", verify_with_replacement)
    monkeypatch.setattr(WINDOWS_FILES, "_final_path", final_path_with_replacement)
    descriptor, spelling = WINDOWS_FILES.open_read_fd_with_path(
        scan_dir, "MANIFEST.json", "pinned manifest"
    )
    with os.fdopen(descriptor, "rb") as snapshot:
        assert snapshot.read() == b"original"
    assert attempted == [stage]
    assert spelling == "manifest.json"
    os.replace(replacement, path)
    assert path.read_bytes() == b"replacement"


@pytest.mark.skipif(os.name != "nt", reason="requires native Win32 file APIs")
@pytest.mark.parametrize("failure", ["reopen", "descriptor"])
def test_native_windows_snapshot_open_failure_closes_owned_handles(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    scan_dir = tmp_path / "scan"
    scan_dir.mkdir()
    path = scan_dir / "manifest.json"
    path.write_bytes(b"original")
    reopen = WINDOWS_FILES._ReOpenFile
    close = WINDOWS_FILES._close_handle
    original_handles = []
    snapshot_handles = []
    closed = []
    conversion_error = OSError(errno.EMFILE, "synthetic descriptor conversion failure")

    def reopen_with_failure(handle, access, share, flags):
        original_handles.append(handle)
        if failure == "reopen":
            ctypes.set_last_error(WINDOWS_FILES._ERROR_ACCESS_DENIED)
            return WINDOWS_FILES._INVALID_HANDLE_VALUE
        snapshot = reopen(handle, access, share, flags)
        assert snapshot != WINDOWS_FILES._INVALID_HANDLE_VALUE
        snapshot_handles.append(snapshot)
        return snapshot

    def close_recorded(handle):
        closed.append(handle)
        close(handle)

    monkeypatch.setattr(WINDOWS_FILES, "_ReOpenFile", reopen_with_failure)
    monkeypatch.setattr(WINDOWS_FILES, "_close_handle", close_recorded)
    if failure == "descriptor":
        monkeypatch.setattr(
            WINDOWS_FILES._msvcrt, "open_osfhandle", mock.Mock(side_effect=conversion_error)
        )
    with pytest.raises(OSError) as caught:
        WINDOWS_FILES.open_read_fd(scan_dir, path.name, "snapshot failure")
    if failure == "reopen":
        assert caught.value.errno == WINDOWS_FILES._ERROR_ACCESS_DENIED
        assert "snapshot failure: ReOpenFile" in str(caught.value)
        assert caught.value.filename == str(path)
    else:
        assert caught.value is conversion_error
    assert len(original_handles) == 1
    for handle in original_handles + snapshot_handles:
        assert closed.count(handle) == 1
    moved = scan_dir / "moved.json"
    path.rename(moved)
    assert moved.read_bytes() == b"original"


@pytest.mark.parametrize("replace_existing", [False, True])
@pytest.mark.parametrize(
    ("extended_error", "classic_error"),
    [
        (0, None),
        (1, 0),
        (1, 5),
        (50, 0),
        (50, 5),
        (87, 0),
        (87, 5),
        (5, None),
        (32, None),
        (80, None),
        (183, None),
        (1, 80),
        (1, 183),
    ],
)
def test_rename_uses_classic_semantics_only_when_extended_operation_is_unsupported(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    replace_existing: bool,
    extended_error: int,
    classic_error: int | None,
) -> None:
    calls = []
    last_error = 0
    destination = tmp_path / "manifest-日本語.json"

    def set_information(handle, information_class, buffer, size):
        nonlocal last_error
        info = ctypes.cast(buffer, ctypes.POINTER(WINDOWS_FILES._FileRenameInfo)).contents
        name = ctypes.string_at(
            ctypes.addressof(buffer) + WINDOWS_FILES._FileRenameInfo.FileName.offset,
            info.FileNameLength,
        ).decode("utf-16-le")
        calls.append((handle, information_class, info.FlagsOrReplaceIfExists, name))
        last_error = extended_error if len(calls) == 1 else classic_error
        assert last_error is not None
        return last_error == 0

    monkeypatch.setattr(
        WINDOWS_FILES, "_SetFileInformationByHandle", set_information, raising=False
    )
    monkeypatch.setattr(ctypes, "get_last_error", lambda: last_error, raising=False)
    monkeypatch.setattr(
        ctypes, "FormatError", lambda code: f"synthetic native error {code}", raising=False
    )
    unsupported = extended_error in {1, 50, 87}
    expected_error = classic_error if unsupported else extended_error
    if not replace_existing and expected_error in (80, 183):
        with pytest.raises(FileExistsError) as collision:
            WINDOWS_FILES._rename_handle(123, destination, replace_existing)
        assert collision.value.errno == errno.EEXIST
        assert collision.value.filename == str(destination)
    elif expected_error:
        with pytest.raises(WINDOWS_FILES.WindowsScanLocalFileError) as caught:
            WINDOWS_FILES._rename_handle(123, destination, replace_existing)
        assert caught.value.errno == expected_error
        operation = "FileRenameInfo" if unsupported else "FileRenameInfoEx"
        assert caught.value.strerror == (
            f"SetFileInformationByHandle({operation}): synthetic native error {expected_error}"
        )
    else:
        WINDOWS_FILES._rename_handle(123, destination, replace_existing)
    target = WINDOWS_FILES._extended_path(destination)
    replace_flag = int(replace_existing)
    assert calls == [(123, 22, replace_flag | 2, target)] + (
        [(123, 3, replace_flag, target)] if unsupported else []
    )


@pytest.mark.skipif(os.name != "nt", reason="requires native Win32 file APIs")
def test_native_windows_replacement_failure_preserves_destination_and_cleans_temp(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    scan_dir = tmp_path / "scan"
    scan_dir.mkdir()
    path = scan_dir / "scan-manifest.json"
    path.write_bytes(b"original")
    native_set_information = WINDOWS_FILES._SetFileInformationByHandle
    rename_calls = []

    def deny_rename(handle, information_class, buffer, size):
        if information_class in {3, 22}:
            rename_calls.append(information_class)
            ctypes.set_last_error(WINDOWS_FILES._ERROR_ACCESS_DENIED)
            return False
        return native_set_information(handle, information_class, buffer, size)

    monkeypatch.setattr(WINDOWS_FILES, "_SetFileInformationByHandle", deny_rename)
    with pytest.raises(WINDOWS_FILES.WindowsScanLocalFileError) as caught:
        WINDOWS_FILES.atomic_write(scan_dir, path.name, b"replacement")
    assert caught.value.errno == WINDOWS_FILES._ERROR_ACCESS_DENIED
    assert "FileRenameInfoEx" in str(caught.value)
    assert rename_calls == [22]
    assert path.read_bytes() == b"original"
    assert sorted(p.name for p in scan_dir.iterdir()) == [path.name]


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
    before_archive = Mock()

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
                workbench_api["register_cli_scan"](
                    connection, registration, before_archive=before_archive
                )["archivedScanDir"]
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
    before_archive.assert_called_once_with()
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

    def replace_after_probe(path, *args):
        nonlocal mutated
        result = original(path, *args)
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


def emulate_windows_atomic_write(monkeypatch, finalizer, files, *, reparse_point=False):
    """Run the real Windows atomic writer with emulated handles, not native Win32 I/O."""
    backend = finalizer._windows_scan_local_files()
    paths = {}
    streams = {}
    movable_directories = {}
    pending_deletions = set()
    next_directory_handle = -1

    def create_file(path, **kwargs):
        nonlocal next_directory_handle
        if kwargs["disposition"] == backend._OPEN_EXISTING:
            if kwargs.get("missing_ok") and not path.exists():
                return None
            descriptor = next_directory_handle
            next_directory_handle -= 1
        else:
            stream = open(path, "xb", opener=lambda path, flags: os.open(path, flags, 0o600))
            try:
                descriptor = stream.fileno()
                streams[descriptor] = files.enter_context(stream)
            except BaseException:
                stream.close()
                raise
        paths[descriptor] = path
        if path.is_dir() and kwargs["share"] & backend._FILE_SHARE_DELETE:
            movable_directories[descriptor] = path.stat()
        return backend._OwnedHandle(descriptor)

    def rename_handle(handle, destination, replace_existing):
        if replace_existing:
            os.replace(paths[handle], destination)
        else:
            os.link(paths[handle], destination)
            paths[handle].unlink()
        paths[handle] = destination

    def close_handle(handle):
        if handle in streams:
            streams.pop(handle).close()
        elif handle >= 0:
            os.close(handle)
        if handle in pending_deletions:
            pending_deletions.remove(handle)
            paths[handle].unlink()

    def attributes(handle):
        path = paths[handle]
        flags = backend._FILE_ATTRIBUTE_DIRECTORY if path.is_dir() else 0
        if path.is_symlink() or (reparse_point and not path.is_dir()):
            flags |= backend._FILE_ATTRIBUTE_REPARSE_POINT
        return SimpleNamespace(FileAttributes=flags)

    monkeypatch.setattr(finalizer, "_descriptor_relative_writes_available", lambda: False)
    monkeypatch.setattr(finalizer, "_is_windows", lambda: True)
    monkeypatch.setattr(backend, "_require_windows", lambda: None)
    monkeypatch.setattr(backend, "_validate_existing_output", lambda path: None)
    monkeypatch.setattr(backend, "_create_file", create_file)

    def reopen_file(handle, *_):
        fd = os.open(paths[handle], os.O_RDONLY) if handle < 0 else os.dup(handle)
        paths[fd] = paths[handle]
        return fd

    monkeypatch.setattr(backend, "_ReOpenFile", reopen_file, raising=False)
    monkeypatch.setattr(backend, "file_change_time", lambda fd: os.fstat(fd).st_ctime_ns)
    monkeypatch.setattr(
        backend,
        "_msvcrt",
        SimpleNamespace(
            open_osfhandle=lambda handle, flags: (
                os.open(paths[handle], flags) if handle < 0 else handle
            )
        ),
    )
    monkeypatch.setattr(os, "O_BINARY", getattr(os, "O_BINARY", 0), raising=False)
    monkeypatch.setattr(backend, "_close_handle", close_handle)
    monkeypatch.setattr(backend, "_attributes", attributes)
    monkeypatch.setattr(
        backend, "_GetFileType", lambda handle: backend._FILE_TYPE_DISK, raising=False
    )

    def final_path(handle, **kwargs):
        path = paths[handle]
        if handle in movable_directories:
            for sibling in path.parent.iterdir():
                if os.path.samestat(movable_directories[handle], sibling.lstat()):
                    return str(sibling)
        return str(path)

    monkeypatch.setattr(backend, "_final_path", final_path)
    monkeypatch.setattr(backend, "_write_all", os.write)
    monkeypatch.setattr(backend, "_rename_handle", rename_handle)
    monkeypatch.setattr(backend, "_mark_handle_for_deletion", pending_deletions.add)
    return backend
