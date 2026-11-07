"""Exercise native Windows direct-plugin output creation races."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

import windows_scan_local_files  # noqa: E402
from workbench import storage  # noqa: E402

pytestmark = [
    pytest.mark.native_windows,
    pytest.mark.skipif(os.name != "nt", reason="requires native Windows ACLs and junctions"),
]


@pytest.mark.parametrize("junction", [False, True], ids=["ordinary-directory", "junction"])
def test_private_temporary_directory_rejects_post_creation_substitution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, junction: bool
) -> None:
    parent = tmp_path / "shared"
    parent.mkdir()
    subprocess.run(
        ["icacls.exe", str(parent), "/grant", "*S-1-1-0:(OI)(CI)R"],
        check=True,
        capture_output=True,
    )
    external = tmp_path / "external"
    external.mkdir()
    substituted: list[Path] = []
    verify = windows_scan_local_files.verify_private_scan_root

    def replace_before_verification(path: Path, descriptor: object) -> Path:
        path.rmdir()
        if junction:
            subprocess.run(
                ["cmd", "/c", "mklink", "/J", str(path), str(external)],
                check=True,
                capture_output=True,
                text=True,
            )
        else:
            path.mkdir()  # An ordinary replacement inherits its parent's DACL.
        substituted.append(path)
        return verify(path, descriptor)

    monkeypatch.setattr(
        windows_scan_local_files, "verify_private_scan_root", replace_before_verification
    )
    try:
        reason = "canonical and non-reparse" if junction else "private owner or DACL"
        with pytest.raises(OSError, match=reason):
            storage.create_private_temporary_directory(parent, prefix="scan_")
    finally:
        for path in substituted:
            path.rmdir()

    assert list(external.iterdir()) == []


def test_parent_remains_in_place_while_verifying_new_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    parent = tmp_path / "parent"
    moved = tmp_path / "moved"
    parent.mkdir()

    def rename_parent(_path: Path, _information: int) -> None:
        parent.rename(moved)
        pytest.fail("Renamed the parent during verification")

    monkeypatch.setattr(windows_scan_local_files, "_directory_security_descriptor", rename_parent)
    with pytest.raises(PermissionError) as error:
        storage.create_private_temporary_directory(parent, prefix="scan_")
    assert error.value.winerror == 32  # ERROR_SHARING_VIOLATION
    parent.rename(moved)
