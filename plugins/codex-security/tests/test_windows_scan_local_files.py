from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest
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
