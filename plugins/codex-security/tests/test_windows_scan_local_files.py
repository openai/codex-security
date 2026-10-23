from __future__ import annotations

import ctypes
import errno
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from unittest import mock

import pytest
from workbench_test_support import load_script

pytestmark = pytest.mark.native_windows

WINDOWS_FILES = load_script("windows_scan_local_files")


@pytest.mark.parametrize("error_code", [2, 3, 5, errno.EINVAL])
def test_saved_checkpoint_fallback_classifies_windows_missing_errors(
    tmp_path: Path, workbench_api, monkeypatch: pytest.MonkeyPatch, error_code: int
) -> None:
    saved = workbench_api["saved_results"]
    finalizer = sys.modules[saved._read_scan_local_json.__module__]
    payload = {"scanId": "fixture-scan", "findings": [], "coverage": {}}
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


@pytest.mark.parametrize("error_code", [2, 3, 5, errno.EINVAL])
def test_read_preserves_missing_file_semantics(
    tmp_path: Path, monkeypatch, error_code: int
) -> None:
    scan_dir = tmp_path / "scan"
    missing_path = scan_dir / "artifacts" / "deep-scan"
    error = WINDOWS_FILES.WindowsScanLocalFileError(
        error_code, "synthetic error", str(missing_path)
    )
    monkeypatch.setattr(WINDOWS_FILES, "_locked_parent", mock.Mock(side_effect=error))
    expected = (
        FileNotFoundError if error_code in {2, 3} else WINDOWS_FILES.WindowsScanLocalFileError
    )
    with pytest.raises(expected) as caught:
        WINDOWS_FILES.open_read_fd(scan_dir, "artifacts/deep-scan/checkpoint.json", "checkpoint")
    assert caught.value.filename == str(missing_path)
    assert caught.value.__cause__ is error


@pytest.mark.skipif(os.name != "nt", reason="requires native Win32 file APIs")
@pytest.mark.parametrize("parent_exists", [False, True])
def test_native_windows_read_reports_missing_checkpoint(
    tmp_path: Path, parent_exists: bool
) -> None:
    scan_dir = tmp_path / "scan"
    scan_dir.mkdir()
    parent = scan_dir / "artifacts" / "deep-scan"
    if parent_exists:
        parent.mkdir(parents=True)
    with pytest.raises(FileNotFoundError) as caught:
        WINDOWS_FILES.open_read_fd(scan_dir, "artifacts/deep-scan/checkpoint.json", "checkpoint")
    expected = parent / "checkpoint.json" if parent_exists else scan_dir / "artifacts"
    assert caught.value.filename == str(expected)
    assert caught.value.errno == errno.ENOENT


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


@pytest.mark.parametrize(
    ("extended_error", "classic_error"),
    [(0, None), (1, 0), (1, 5), (50, 0), (50, 5), (87, 0), (87, 5), (5, None), (32, None)],
)
def test_rename_uses_classic_semantics_only_when_extended_operation_is_unsupported(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
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
    if expected_error:
        with pytest.raises(WINDOWS_FILES.WindowsScanLocalFileError) as caught:
            WINDOWS_FILES._rename_handle(123, destination)
        assert caught.value.errno == expected_error
        operation = "FileRenameInfo" if unsupported else "FileRenameInfoEx"
        assert caught.value.strerror == (
            f"SetFileInformationByHandle({operation}): synthetic native error {expected_error}"
        )
    else:
        WINDOWS_FILES._rename_handle(123, destination)
    target = WINDOWS_FILES._extended_path(destination)
    assert calls == [(123, 22, 3, target)] + ([(123, 3, 1, target)] if unsupported else [])


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
