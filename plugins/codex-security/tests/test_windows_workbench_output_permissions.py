"""Exercise native Windows direct-plugin output creation races."""

from __future__ import annotations

import argparse
import base64
import ctypes
import json
import os
import sqlite3
import string
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path

import pytest
from workbench_test_support import run_workbench, scan_command

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


@pytest.fixture
def deep_registration(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "source.py").write_text("# synthetic source\n")
    output = tmp_path / "output"
    output.mkdir()
    state = tmp_path / "state"
    recipe = {
        "config": {},
        "repository": str(repository),
        "target": {"kind": "repository", "paths": []},
    }

    def register(mode="deep", *, archive=False, connection=None, **options):
        arguments = [
            "register-cli-scan",
            "--repository",
            str(repository),
            "--scan-dir",
            str(output),
            "--recipe-json",
            json.dumps({**recipe, "mode": mode}),
        ]
        if archive:
            arguments.append("--archive-existing")
        if connection is None:
            return run_workbench(state, *arguments, **options)
        with monkeypatch.context() as patch:
            patch.setattr(sys, "argv", ["workbench", *arguments])
            return workbench_db.register_cli_scan(
                connection, workbench_db.parse_args("test workbench")
            )

    return state, output, register


@pytest.mark.parametrize("legacy_ids", [False, True], ids=["full-file-id", "legacy-file-index"])
def test_deep_resume_reads_both_pinned_directory_identities(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, legacy_ids: bool
) -> None:
    output = tmp_path / "output"
    output.mkdir()
    child = output / windows_scan_local_files.DEEP_RESUME_DIRECTORY
    lstat = Path.lstat

    def directory_entry_stat(path: Path) -> os.stat_result:
        if path not in (output, child):
            return lstat(path)
        # Windows directory enumeration can supply attributes without a file index.
        with os.scandir(path.parent) as entries:
            entry = next(entry for entry in entries if entry.name == path.name)
            return entry.stat(follow_symlinks=False)

    monkeypatch.setattr(Path, "lstat", directory_entry_stat)
    if legacy_ids:
        get_info = windows_scan_local_files._GetFileInformationByHandleEx

        def without_file_id(handle, info_class, *arguments):
            if info_class == windows_scan_local_files._FILE_ID_INFO_CLASS:
                ctypes.set_last_error(50)  # ERROR_NOT_SUPPORTED.
                return False
            return get_info(handle, info_class, *arguments)

        monkeypatch.setattr(
            windows_scan_local_files, "_GetFileInformationByHandleEx", without_file_id
        )

    with windows_scan_local_files.create_deep_resume_output(output, lambda: False) as saved:
        assert output.lstat().st_ino == child.lstat().st_ino == 0
        root_volume, root_id, child_volume, child_id = saved
        assert root_volume == child_volume
        assert root_id and child_id and root_id != child_id
    assert windows_scan_local_files.deep_resume_output_identity(output) == saved


@pytest.mark.parametrize(
    "change",
    [
        "replaced root",
        "replaced child",
        "different recorded volume",
        "missing child",
        "deletable child",
        "delete child right",
    ],
)
def test_deep_resume_requires_the_registered_protected_directories(
    deep_registration, tmp_path: Path, change: str
) -> None:
    state, output, register = deep_registration
    scan_id = register()["scanId"]
    scan_command(state, "set-scan-thread", scan_id, "--thread-id", "original-thread")
    retained = output / windows_scan_local_files.DEEP_RESUME_DIRECTORY
    assert list(output.iterdir()) == [retained]
    assert list(retained.iterdir()) == []
    grant(output, "(OI)(CI)M")
    assert scan_command(state, "get-cli-scan-resume", scan_id)["threadId"] == "original-thread"

    if change == "replaced root":
        previous = tmp_path / "original root"
        output.rename(previous)
        output.mkdir()
        (previous / retained.name).rename(retained)
    elif change == "replaced child":
        retained.rename(tmp_path / "original child")
        windows_scan_local_files.create_private_directory(
            retained, exist_ok=False, scan_output=True
        )
    elif change == "different recorded volume":
        identity = windows_scan_local_files.deep_resume_output_identity(output)
        identity[0] ^= 1 << 32  # The low 32 bits and both file IDs still match.
        with closing(sqlite3.connect(state / "workbench.sqlite3")) as connection, connection:
            connection.execute(
                "UPDATE scans SET windows_resume_output_identity = ? WHERE id = ?",
                (json.dumps(identity), scan_id),
            )
    elif change == "missing child":
        retained.rmdir()
    elif change == "deletable child":
        grant(retained, "(DE)")
    else:
        grant(output, "(DC)")

    # Even a populated replacement cannot downgrade a recorded binding to legacy recovery.
    (output / "checkpoint.json").write_text("{}")
    rejected = scan_command(state, "get-cli-scan-resume", scan_id, check=False)
    assert rejected["returncode"] != 0
    assert "Windows" in rejected["stderr"]
    assert (output / "checkpoint.json").read_text() == "{}"


def test_legacy_windows_resume_keeps_populated_output_and_rejects_unbound_empty_output(
    deep_registration,
) -> None:
    state, output, register = deep_registration
    scan_id = register()["scanId"]
    scan_command(state, "set-scan-thread", scan_id, "--thread-id", "original-thread")
    with closing(sqlite3.connect(state / "workbench.sqlite3")) as connection, connection:
        connection.execute(
            "UPDATE scans SET windows_resume_output_identity = NULL WHERE id = ?", (scan_id,)
        )
    retained = output / windows_scan_local_files.DEEP_RESUME_DIRECTORY
    # Neither a private directory nor a lookalike retained child proves legacy ownership.
    for has_guard in (True, False):
        if not has_guard:
            retained.rmdir()
            grant(output, "(OI)(CI)M")
        rejected = scan_command(state, "get-cli-scan-resume", scan_id, check=False)
        assert rejected["returncode"] != 0
        assert f"scans rerun {scan_id}" in rejected["stderr"]
    (output / "checkpoint.json").write_text("{}")
    assert scan_command(state, "get-cli-scan-resume", scan_id)["scanDir"] == str(output)


def test_deep_registration_rolls_back_the_retained_child(deep_registration) -> None:
    state, output, register = deep_registration
    run_workbench(state, "list-scans")
    with closing(sqlite3.connect(state / "workbench.sqlite3")) as connection, connection:
        connection.execute(
            "CREATE TRIGGER fail_binding BEFORE UPDATE OF windows_resume_output_identity ON scans "
            "BEGIN SELECT RAISE(ABORT, 'synthetic registration failure'); END"
        )
    assert "synthetic registration failure" in register(check=False)["stderr"]
    assert list(output.iterdir()) == []
    with closing(sqlite3.connect(state / "workbench.sqlite3")) as connection, connection:
        assert connection.execute("SELECT count(*) FROM scans").fetchone()[0] == 0
        connection.execute("DROP TRIGGER fail_binding")
    with ThreadPoolExecutor(max_workers=2) as retries:
        outcomes = [retries.submit(register, check=False) for _ in range(2)]
        assert sorted(outcome.result()["returncode"] for outcome in outcomes) == [0, 1]
    with closing(sqlite3.connect(state / "workbench.sqlite3")) as connection:
        [(scan_id,)] = connection.execute("SELECT id FROM scans").fetchall()
    scan_command(state, "set-scan-thread", scan_id, "--thread-id", "original-thread")
    assert scan_command(state, "get-cli-scan-resume", scan_id)["scanId"] == scan_id


@pytest.mark.parametrize("archive", [False, True], ids=["fresh", "archive-existing"])
def test_resume_verification_failure_rolls_back_the_created_handle(
    deep_registration, monkeypatch: pytest.MonkeyPatch, archive: bool
) -> None:
    state, output, register = deep_registration
    monkeypatch.setenv("CODEX_SECURITY_STATE_DIR", str(state))
    retained = output / windows_scan_local_files.DEEP_RESUME_DIRECTORY
    previous_file = output / "previous result"

    with closing(workbench_db.connect()) as connection:
        old_id = None
        if archive:
            old_id = register("standard", connection=connection)["scanId"]
            connection.execute("UPDATE scans SET status = 'failed' WHERE id = ?", (old_id,))
            connection.commit()
            previous_file.write_bytes(b"original result")
        original_grants = windows_scan_local_files._output_directory_grants

        def competing_reader(handle, path, **options):
            if path == retained and "expected_descriptor" in options:
                # The original handle is already held when verification starts.
                # Propagate the real sharing error to interrupt this registration.
                contender = windows_scan_local_files._create_file(
                    retained,
                    access=windows_scan_local_files._FILE_TRAVERSE,
                    share=0,
                    disposition=windows_scan_local_files._OPEN_EXISTING,
                    flags=windows_scan_local_files._FILE_FLAG_BACKUP_SEMANTICS
                    | windows_scan_local_files._FILE_FLAG_OPEN_REPARSE_POINT,
                )
                with contender:
                    pytest.fail("An exclusive reader opened the tentative resume directory")
            return original_grants(handle, path, **options)

        with monkeypatch.context() as patch:
            patch.setattr(windows_scan_local_files, "_output_directory_grants", competing_reader)
            with pytest.raises(OSError) as failure:
                register(archive=archive, connection=connection)
        assert (getattr(failure.value, "winerror", None) or failure.value.errno) == 32
        assert not retained.exists()
        assert not list(output.parent.glob(f"{output.name}.previous-*"))
        rows = connection.execute("SELECT id, scan_dir FROM scans").fetchall()
        if archive:
            assert [tuple(row) for row in rows] == [(old_id, str(output))]
            assert previous_file.read_bytes() == b"original result"
        else:
            assert rows == []
            assert list(output.iterdir()) == []
        assert register(archive=archive, connection=connection)["scanDir"] == str(output)


def test_resume_cleanup_cannot_remove_an_existing_or_substituted_child(tmp_path: Path) -> None:
    output = tmp_path / "output"
    output.mkdir()
    retained = output / windows_scan_local_files.DEEP_RESUME_DIRECTORY
    original = tmp_path / "another directory"
    original.mkdir()
    sentinel = original / "keep"
    sentinel.write_bytes(b"owned by another operation")
    original.rename(retained)
    with (
        pytest.raises(FileExistsError),
        windows_scan_local_files.create_deep_resume_output(output, lambda: False),
    ):
        pytest.fail("An existing child was adopted")
    retained.rename(original)
    with (
        pytest.raises(PermissionError) as failure,
        windows_scan_local_files.create_deep_resume_output(output, lambda: False),
    ):
        retained.rename(tmp_path / "moved")
    assert failure.value.winerror == 32
    assert not retained.exists()
    assert sentinel.read_bytes() == b"owned by another operation"


def test_post_commit_interrupt_keeps_the_registered_resume_directory(deep_registration) -> None:
    state, output, register = deep_registration
    run_workbench(state, "list-scans")

    class InterruptedCommit(sqlite3.Connection):
        def commit(self):
            super().commit()
            raise KeyboardInterrupt

    with closing(
        sqlite3.connect(state / "workbench.sqlite3", factory=InterruptedCommit)
    ) as connection:
        connection.row_factory = sqlite3.Row
        with pytest.raises(KeyboardInterrupt):
            register(connection=connection)
        [(scan_id,)] = connection.execute("SELECT id FROM scans").fetchall()
    scan_command(state, "set-scan-thread", scan_id, "--thread-id", "original-thread")
    assert scan_command(state, "get-cli-scan-resume", scan_id)["scanDir"] == str(output)


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
