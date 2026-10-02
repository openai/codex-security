from __future__ import annotations

import errno
import importlib.util
import os
from pathlib import Path
from types import ModuleType
from unittest import mock

import pytest


def load_windows_scan_local_files() -> ModuleType:
    script = Path(__file__).resolve().parent.parent / "scripts" / "windows_scan_local_files.py"
    spec = importlib.util.spec_from_file_location("windows_scan_local_files", script)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {script}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


WINDOWS_FILES = load_windows_scan_local_files()


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
