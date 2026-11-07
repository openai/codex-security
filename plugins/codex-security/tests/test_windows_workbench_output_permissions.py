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
import workbench_db  # noqa: E402
from workbench import storage  # noqa: E402

pytestmark = [
    pytest.mark.native_windows,
    pytest.mark.skipif(os.name != "nt", reason="requires native Windows ACLs and junctions"),
]


def test_scan_directory_checks_parent_replacement_rights(tmp_path: Path) -> None:
    shared = tmp_path / "shared"
    selected = shared / "selected"
    selected.mkdir(parents=True)
    subprocess.run(
        ["icacls.exe", str(shared), "/grant", "*S-1-1-0:(AD)"],
        check=True,
        capture_output=True,
    )
    scan = storage.create_private_temporary_directory(selected, prefix="scan_")
    assert workbench_db.require_canonical_scan_directory(scan) == scan
    subprocess.run(
        ["icacls.exe", str(selected), "/grant", "*S-1-1-0:(DE)"],
        check=True,
        capture_output=True,
    )
    with pytest.raises(OSError, match="can be replaced"):
        storage.create_private_temporary_directory(selected, prefix="next_")
    with pytest.raises(SystemExit, match="can be replaced"):
        workbench_db.require_canonical_scan_directory(scan)


@pytest.mark.parametrize("existing", [True, False], ids=["initial-selection", "concurrent-create"])
def test_generated_target_name_must_be_an_ordinary_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, existing: bool
) -> None:
    root = tmp_path / "output"
    root.mkdir()
    other = tmp_path / "other"
    other.mkdir()
    project = tmp_path / "project"
    segment = root / project.name

    def create_junction() -> None:
        subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(segment), str(other)],
            check=True,
            capture_output=True,
        )

    if existing:
        create_junction()
    else:
        open_relative = windows_scan_local_files._relative_output_directory

        def create_competing_directory(parent, basename, descriptor=None):
            if descriptor is not None and basename == project.name:
                create_junction()
            return open_relative(parent, basename, descriptor)

        monkeypatch.setattr(
            windows_scan_local_files, "_relative_output_directory", create_competing_directory
        )
    try:
        directory = workbench_db.scan_target_root(str(root), project)
        with pytest.raises(OSError):
            storage.create_private_directory(directory, scan_output=True)
    finally:
        segment.rmdir()
    assert not list(other.iterdir())


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
