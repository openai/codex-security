from __future__ import annotations

import copy
import os
from unittest import mock

import pytest
from workbench_test_support import load_script, windows_file_backend

FINALIZER = load_script("finalize_scan_contract")


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlinks and file permissions")
@pytest.mark.parametrize(
    "kind", ["unsafe", "symlink", "dangling-symlink", "parent-symlink", "directory", "unreadable"]
)
def test_missing_writeup_recovery_rejects_other_file_errors(tmp_path, kind):
    scan_dir = tmp_path / "scan"
    scan_dir.mkdir()
    report = scan_dir / "findings" / "report.md"
    report.parent.mkdir()
    outside = tmp_path / "outside.md"
    outside.write_text("# Outside the scan\n")
    report_path = "findings/report.md"
    if kind == "unsafe":
        report_path = "../outside.md"
    elif kind == "symlink":
        report.symlink_to(outside)
    elif kind == "dangling-symlink":
        report.symlink_to(report.parent / "missing.md")
    elif kind == "parent-symlink":
        report.parent.rmdir()
        report.parent.symlink_to(tmp_path, target_is_directory=True)
    elif kind == "directory":
        report.mkdir()
    else:
        if os.geteuid() == 0:
            pytest.skip("root can read files without permission bits")
        report.write_text("# Unreadable writeup\n")
        report.chmod(0)
    findings = {"findings": [{"writeup": {"reportPath": report_path}}]}
    original = copy.deepcopy(findings)
    with pytest.raises(FINALIZER.ContractError):
        FINALIZER._prepare_derived_writeups(scan_dir, findings, allow_missing=True)
    assert findings == original


@pytest.mark.cross_platform
@pytest.mark.parametrize("error_code", [2, 3, 5, 22, 32, 33])
def test_windows_writeup_recovery_only_omits_missing_files(tmp_path, monkeypatch, error_code):
    backend = windows_file_backend()
    windows_error = load_script("windows_scan_local_files").WindowsScanLocalFileError
    backend.open_read_fd.side_effect = windows_error(error_code, "Synthetic Windows file error")
    monkeypatch.setattr(FINALIZER.os, "supports_dir_fd", set())
    monkeypatch.setattr(FINALIZER, "_is_windows", lambda: True)
    monkeypatch.setattr(FINALIZER, "_windows_scan_local_files", lambda: backend)
    findings = {"findings": [{"writeup": {"reportPath": "findings/report.md"}}]}
    if error_code in {2, 3}:
        warnings = FINALIZER._prepare_derived_writeups(tmp_path, findings, allow_missing=True)
        assert findings == {"findings": [{}]}
        assert len(warnings) == 1
    else:
        with pytest.raises(FINALIZER.ContractError):
            FINALIZER._prepare_derived_writeups(tmp_path, findings, allow_missing=True)
        assert "writeup" in findings["findings"][0]


@pytest.mark.cross_platform
@pytest.mark.parametrize("error_code", [2, 3])
def test_windows_writeup_recovery_omits_missing_parent_directories(
    tmp_path, monkeypatch, error_code
):
    backend = load_script("windows_scan_local_files")
    scan_dir = tmp_path.resolve()
    missing_parent = scan_dir / "findings" / "missing"

    def open_directory(path, **_options):
        if path == missing_parent:
            raise backend.WindowsScanLocalFileError(
                error_code, "Synthetic missing parent directory", str(path)
            )
        return mock.Mock(value=1)

    monkeypatch.setattr(backend, "_require_windows", lambda: None)
    monkeypatch.setattr(backend, "_create_file", open_directory)
    monkeypatch.setattr(backend, "_verify_directory", lambda *_args: None)
    monkeypatch.setattr(FINALIZER.os, "supports_dir_fd", set())
    monkeypatch.setattr(FINALIZER, "_is_windows", lambda: True)
    monkeypatch.setattr(FINALIZER, "_windows_scan_local_files", lambda: backend)
    findings = {"findings": [{"writeup": {"reportPath": "findings/missing/report.md"}}]}

    warnings = FINALIZER._prepare_derived_writeups(scan_dir, findings, allow_missing=True)

    assert findings == {"findings": [{}]}
    assert len(warnings) == 1
