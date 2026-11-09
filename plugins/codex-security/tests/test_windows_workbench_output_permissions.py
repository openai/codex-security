"""Exercise native Windows direct-plugin output creation races."""

from __future__ import annotations

import argparse
import base64
import os
import string
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


def grant(path: Path, rights: str) -> None:
    subprocess.run(["icacls.exe", str(path), "/grant", f"*S-1-1-0:{rights}"], check=True)


def make_junction(path: Path, target: Path) -> None:
    subprocess.run(["cmd", "/c", "mklink", "/J", str(path), str(target)], check=True)


def test_missing_output_drive_reports_a_filesystem_error() -> None:
    for letter in reversed(string.ascii_uppercase):
        drive = Path(f"{letter}:/")
        if not drive.is_dir():
            with pytest.raises(OSError):
                storage.create_private_directory(drive, scan_output=True)
            return
    pytest.skip("requires an unavailable drive letter")


def test_scan_directory_checks_parent_replacement_rights(tmp_path: Path) -> None:
    shared = tmp_path / "shared"
    selected = shared / "selected"
    selected.mkdir(parents=True)
    grant(shared, "(AD)")
    scan = storage.create_private_temporary_directory(selected, prefix="scan_")
    assert workbench_db.require_canonical_scan_directory(scan) == scan
    grant(selected, "(DE)")
    with pytest.raises(OSError, match="can be replaced"):
        storage.create_private_temporary_directory(selected, prefix="next_")
    with pytest.raises(SystemExit, match="can be replaced"):
        workbench_db.require_canonical_scan_directory(scan)


@pytest.mark.parametrize("right", ["WA", "WD"])
def test_registration_checks_reparse_access_before_archiving(tmp_path: Path, right: str) -> None:
    output = tmp_path / "output"
    output.mkdir()
    grant(output, f"({right})")
    args = argparse.Namespace(scan_dir=output, archive_existing=False, archived_scan_dir=None)
    with pytest.raises(SystemExit, match="reparse point"):
        workbench_db.require_cli_scan_directory(tmp_path / "repo", args)

    saved = output / "result"
    saved.write_text("synthetic result")
    assert workbench_db.require_canonical_scan_directory(output) == output
    args.archive_existing = True
    with pytest.raises(SystemExit, match="reparse point"):
        workbench_db.require_cli_scan_directory(tmp_path / "repo", args)
    assert saved.read_text() == "synthetic result"


@pytest.mark.skipif(
    os.environ.get("GITHUB_ACTIONS") != "true",
    reason="creates a disposable local account on a hosted Windows runner",
)
def test_native_directory_write_rights_for_setting_reparse_data(tmp_path: Path) -> None:
    grant(tmp_path, "(OI)(CI)RX")
    target = tmp_path / "synthetic target"
    target.mkdir()
    (target / "src").mkdir()
    make_junction(tmp_path / "source junction", target)
    leaves = {
        "write attributes": "(WA)",
        "write data": "(WD)",
        "write data and attributes": "(WD,WA)",
        "writable control": "M",
    }
    for name, rights in leaves.items():
        leaf = tmp_path / name
        leaf.mkdir()
        grant(leaf, rights)

    intermediate = tmp_path / "intermediate"
    child = intermediate / "src"
    storage.create_private_directory(child)
    grant(child, "RX")
    grant(intermediate, "(RD,RA,REA,RC,S,X,DC,WA)")
    with pytest.raises(SystemExit, match="can be replaced"):
        workbench_db.require_canonical_scan_directory(child)

    script = Path(__file__).with_name("windows-other-user-access.ps1").read_text(encoding="utf-8")
    powershell = Path(os.environ["SystemRoot"]) / "System32/WindowsPowerShell/v1.0/powershell.exe"
    subprocess.run(
        [
            str(powershell),
            "-NoProfile",
            "-NonInteractive",
            "-EncodedCommand",
            base64.b64encode(script.encode("utf-16-le")).decode("ascii"),
        ],
        env={**os.environ, "CODEX_SECURITY_TEST_REPARSE_PARENT": str(tmp_path)},
        check=True,
    )
    for name in leaves:
        assert (tmp_path / name).resolve() == target
    assert child.resolve() == target / "src"


def test_delete_child_and_parent_reparse_rights_require_no_create_grant(tmp_path: Path) -> None:
    parent = tmp_path / "parent"
    output = parent / "output"
    output.mkdir(parents=True)
    grant(parent, "(DC,WA)")
    with pytest.raises(SystemExit, match="can be replaced"):
        workbench_db.require_canonical_scan_directory(output)


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

    if existing:
        make_junction(segment, other)
    else:
        open_relative = windows_scan_local_files._relative_output_directory

        def create_competing_directory(parent, basename, descriptor=None):
            if descriptor is not None and basename == project.name:
                make_junction(segment, other)
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
    grant(parent, "(OI)(CI)R")
    external = tmp_path / "external"
    external.mkdir()
    substituted: list[Path] = []
    verify = windows_scan_local_files.verify_private_scan_root

    def replace_before_verification(path: Path, descriptor: object) -> Path:
        path.rmdir()
        if junction:
            make_junction(path, external)
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
