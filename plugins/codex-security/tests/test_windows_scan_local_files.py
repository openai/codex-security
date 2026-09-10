from __future__ import annotations

import contextlib
import errno
import importlib.util
import os
from pathlib import Path
from types import ModuleType

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


@pytest.mark.parametrize("error_code", [2, 3, 5, 32, 123])
def test_read_missing_errors_preserve_filesystem_exception_kind(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, error_code: int
) -> None:
    @contextlib.contextmanager
    def locked_parent(*_args: object, **_kwargs: object):
        yield tmp_path, "missing.json"

    monkeypatch.setattr(WINDOWS_FILES, "_locked_parent", locked_parent)
    monkeypatch.setattr(WINDOWS_FILES, "_kernel32", object())
    monkeypatch.setattr(
        WINDOWS_FILES,
        "_CreateFileW",
        lambda *_args: WINDOWS_FILES._INVALID_HANDLE_VALUE,
        raising=False,
    )
    monkeypatch.setattr(WINDOWS_FILES.ctypes, "get_last_error", lambda: error_code, raising=False)
    monkeypatch.setattr(
        WINDOWS_FILES.ctypes, "FormatError", lambda _code: "Native file error", raising=False
    )

    expected = (
        FileNotFoundError if error_code in {2, 3} else WINDOWS_FILES.WindowsScanLocalFileError
    )
    with pytest.raises(expected) as caught:
        WINDOWS_FILES.open_read_fd(tmp_path, "missing.json", "Saved checkpoint artifact")
    assert "Saved checkpoint artifact" in str(caught.value)
    if error_code in {2, 3}:
        assert caught.value.errno == errno.ENOENT
        assert caught.value.__cause__.errno == error_code
    else:
        assert not isinstance(caught.value, FileNotFoundError)
        assert caught.value.errno == error_code


@pytest.mark.skipif(os.name != "nt", reason="requires native Win32 file APIs")
@pytest.mark.parametrize("relative_path", ["missing.json", "missing/proof.json"])
def test_native_windows_backend_reports_missing_read_as_file_not_found(
    tmp_path: Path, relative_path: str
) -> None:
    with pytest.raises(FileNotFoundError) as caught:
        WINDOWS_FILES.open_read_fd(tmp_path, relative_path, "Saved checkpoint artifact")
    assert caught.value.errno == errno.ENOENT
    assert caught.value.__cause__.errno in {2, 3}
