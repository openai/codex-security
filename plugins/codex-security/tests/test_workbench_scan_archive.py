from __future__ import annotations

import argparse
import json
import sqlite3
import threading
import uuid
from pathlib import Path

import pytest
from workbench_test_support import fail_scan, run_workbench


def register_scan(
    state_dir: Path, repository: Path, scan_dir: Path, *arguments: str, check: bool = True
) -> dict[str, object]:
    return run_workbench(
        state_dir,
        "register-cli-scan",
        "--repository",
        str(repository),
        "--scan-dir",
        str(scan_dir),
        "--recipe-json",
        json.dumps(
            {
                "config": {},
                "mode": "standard",
                "repository": str(repository),
                "target": {"kind": "repository", "paths": []},
            }
        ),
        *arguments,
        check=check,
    )


def test_archived_output_preserves_old_scan_and_allows_fresh_registration(
    tmp_path: Path,
) -> None:
    state_dir = tmp_path / "state"
    repository = tmp_path / "repository"
    scan_dir = tmp_path / "scan"
    repository.mkdir()
    scan_dir.mkdir(mode=0o700)
    previous = register_scan(state_dir, repository, scan_dir)
    fail_scan(state_dir, str(previous["scanId"]), "The previous scan was interrupted.")
    (scan_dir / "previous.txt").write_text("keep the previous scan\n")
    report_path = scan_dir / "report.md"
    report_path.write_text("# Previous scan\n")
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.execute(
            "INSERT INTO scan_artifacts (scan_id, kind, path, created_at) VALUES (?, ?, ?, ?)",
            (
                str(previous["scanId"]),
                "markdownReport",
                str(report_path),
                "2026-08-13T00:00:00Z",
            ),
        )
    archived_scan_dir = tmp_path / "scan.previous-test"
    scan_dir.rename(archived_scan_dir)
    scan_dir.mkdir(mode=0o700)

    current = register_scan(
        state_dir,
        repository,
        scan_dir,
        "--archive-existing",
        "--archived-scan-dir",
        str(archived_scan_dir),
    )

    assert current["scanId"] != previous["scanId"]
    assert current["scanDir"] == str(scan_dir)
    assert (archived_scan_dir / "previous.txt").read_text() == "keep the previous scan\n"
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        assert connection.execute(
            "SELECT scan_dir, status FROM scans WHERE id = ?",
            (str(previous["scanId"]),),
        ).fetchone() == (str(archived_scan_dir), "failed")
        assert connection.execute(
            "SELECT scan_dir, status FROM scans WHERE id = ?",
            (str(current["scanId"]),),
        ).fetchone() == (str(scan_dir), "running")
        assert connection.execute(
            "SELECT path FROM scan_artifacts WHERE scan_id = ?",
            (str(previous["scanId"]),),
        ).fetchone() == (str(archived_scan_dir / "report.md"),)


def test_empty_failed_scan_can_be_archived_and_reused(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    repository = tmp_path / "repository"
    scan_dir = tmp_path / "scan"
    repository.mkdir()
    scan_dir.mkdir(mode=0o700)
    previous = register_scan(state_dir, repository, scan_dir)
    fail_scan(
        state_dir, str(previous["scanId"]), "The previous scan failed before writing artifacts."
    )

    current = register_scan(state_dir, repository, scan_dir, "--archive-existing")

    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        previous_directory = connection.execute(
            "SELECT scan_dir FROM scans WHERE id = ?", (str(previous["scanId"]),)
        ).fetchone()
    assert previous_directory is not None
    archived_scan_dir = Path(previous_directory[0])
    assert archived_scan_dir.parent == scan_dir.parent
    assert archived_scan_dir.name.startswith("scan.previous-")
    assert archived_scan_dir.is_dir()
    assert not any(archived_scan_dir.iterdir())
    assert current["scanDir"] == str(scan_dir)


def test_archive_requires_previous_directory_when_artifacts_exist(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    repository = tmp_path / "repository"
    scan_dir = tmp_path / "scan"
    repository.mkdir()
    scan_dir.mkdir(mode=0o700)
    previous = register_scan(state_dir, repository, scan_dir)
    fail_scan(state_dir, str(previous["scanId"]), "The previous scan was interrupted.")
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.execute(
            "INSERT INTO scan_artifacts (scan_id, kind, path, created_at) VALUES (?, ?, ?, ?)",
            (
                str(previous["scanId"]),
                "markdownReport",
                str(scan_dir / "report.md"),
                "2026-08-13T00:00:00Z",
            ),
        )

    rejected = register_scan(state_dir, repository, scan_dir, "--archive-existing", check=False)

    assert rejected["returncode"] != 0
    assert "archived scan directory is required" in str(rejected["stderr"])


def test_archive_does_not_replace_a_running_scan(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    repository = tmp_path / "repository"
    scan_dir = tmp_path / "scan"
    repository.mkdir()
    scan_dir.mkdir(mode=0o700)
    previous = register_scan(state_dir, repository, scan_dir)

    rejected = register_scan(state_dir, repository, scan_dir, "--archive-existing", check=False)

    assert rejected["returncode"] != 0
    assert "Cannot archive the output of a running scan." in str(rejected["stderr"])
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        assert connection.execute(
            "SELECT scan_dir, status FROM scans WHERE id = ?", (str(previous["scanId"]),)
        ).fetchone() == (str(scan_dir), "running")


@pytest.mark.parametrize("archived", [False, True])
def test_nonempty_output_is_rejected_before_parsing_the_recipe(
    tmp_path: Path, archived: bool
) -> None:
    repository, scan_dir = tmp_path / "repository", tmp_path / "scan"
    repository.mkdir()
    scan_dir.mkdir(mode=0o700)
    (scan_dir / "checkpoint.txt").write_text("preserved output")
    arguments = []
    if archived:
        previous_dir = tmp_path / "scan.previous-test"
        previous_dir.mkdir(mode=0o700)
        arguments = ["--archive-existing", "--archived-scan-dir", str(previous_dir)]

    rejected = run_workbench(
        tmp_path / "state",
        "register-cli-scan",
        "--repository",
        str(repository),
        "--scan-dir",
        str(scan_dir),
        "--recipe-json",
        "{}",
        *arguments,
        check=False,
    )

    assert rejected["returncode"] != 0
    assert "must be empty before the scan starts" in str(rejected["stderr"])
    assert (scan_dir / "checkpoint.txt").read_text() == "preserved output"


@pytest.mark.parametrize(
    "state_subdirectory",
    [".", "state", "linked-state", "aliased-state", "aliased-state-child", "linked-parent"],
)
def test_archive_cannot_move_the_active_workbench_database(
    tmp_path: Path, state_subdirectory: str
) -> None:
    repository = tmp_path / "repository"
    scan_dir = tmp_path / "scan"
    state_dir = scan_dir / state_subdirectory
    previous_dir = tmp_path / "previous"
    repository.mkdir()
    scan_dir.mkdir(mode=0o700)
    previous_dir.mkdir(mode=0o700)
    if state_subdirectory in {
        "linked-state",
        "aliased-state",
        "aliased-state-child",
        "linked-parent",
    }:
        external_state = tmp_path / "external-state"
        external_state.mkdir(mode=0o700)
        state_dir.symlink_to(external_state, target_is_directory=True)
        if state_subdirectory == "linked-parent":
            child = scan_dir / "child"
            child.mkdir(mode=0o700)
            alias = tmp_path / "alias"
            alias.symlink_to(child, target_is_directory=True)
            state_dir = alias / ".." / state_subdirectory
        elif state_subdirectory.startswith("aliased-state"):
            alias = tmp_path / "alias"
            alias.symlink_to(tmp_path, target_is_directory=True)
            state_dir = alias / "scan" / state_subdirectory
            if state_subdirectory == "aliased-state-child":
                state_dir /= "child"
    previous = register_scan(state_dir, repository, previous_dir)
    (scan_dir / "previous.txt").write_text("keep existing output")

    rejected = run_workbench(
        state_dir,
        "register-cli-scan",
        "--repository",
        str(repository),
        "--scan-dir",
        str(scan_dir),
        "--recipe-json",
        json.dumps(
            {
                "config": {},
                "mode": "standard",
                "repository": str(repository),
                "target": {"kind": "repository", "paths": []},
            }
        ),
        "--archive-existing",
        check=False,
    )

    assert rejected["returncode"] != 0
    assert "workbench state or active database" in str(rejected["stderr"])
    assert (scan_dir / "previous.txt").read_text() == "keep existing output"
    assert not list(tmp_path.glob("scan.previous-*"))
    saved = run_workbench(state_dir, "get-scan", "--scan-id", str(previous["scanId"]))
    assert saved["scan"]["scanId"] == previous["scanId"]
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        assert connection.execute("SELECT COUNT(*) FROM scans").fetchone()[0] == 1


def test_registration_rechecks_empty_output_after_competing_archive_rolls_back(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    workbench_api,
    workbench_schema,
) -> None:
    repository, scan_dir = tmp_path / "repository", tmp_path / "scan"
    repository.mkdir()
    scan_dir.mkdir(mode=0o700)
    checkpoint = scan_dir / "checkpoint.txt"
    checkpoint.write_text("preserved bytes")
    database = tmp_path / "workbench.sqlite3"
    arguments = argparse.Namespace(
        repository=str(repository),
        scan_dir=str(scan_dir),
        archive_existing=True,
        archived_scan_dir=None,
        registration_json_stdin=False,
        recipe_json_stdin=False,
        parent_scan_id=str(uuid.uuid4()),
        recipe_json=json.dumps(
            {
                "config": {},
                "mode": "standard",
                "repository": str(repository),
                "target": {"kind": "repository", "paths": []},
            }
        ),
    )
    register = workbench_api["register_cli_scan"]
    waiting = threading.Event()
    outcomes = []

    class WaitingConnection(sqlite3.Connection):
        def execute(self, statement, *args, **kwargs):
            if statement == "BEGIN IMMEDIATE":
                waiting.set()
            return super().execute(statement, *args, **kwargs)

    def compete():
        with sqlite3.connect(database, factory=WaitingConnection) as connection:
            connection.row_factory = sqlite3.Row
            second = argparse.Namespace(**vars(arguments))
            second.archive_existing, second.parent_scan_id = False, None
            try:
                outcomes.append(register(connection, second))
            except BaseException as error:
                outcomes.append(error)

    mkdir = Path.mkdir
    competitor = threading.Thread(target=compete)

    def replacement(path, *args, **kwargs):
        result = mkdir(path, *args, **kwargs)
        if path == scan_dir:
            competitor.start()
            assert waiting.wait(5)
        return result

    with sqlite3.connect(database) as first:
        workbench_schema.backup(first)
        first.row_factory = sqlite3.Row
        with monkeypatch.context() as patch:
            patch.setattr(Path, "mkdir", replacement)
            with pytest.raises(SystemExit, match="not found"):
                register(first, arguments)
        competitor.join(10)
        assert not competitor.is_alive()
        assert len(outcomes) == 1
        assert isinstance(outcomes[0], SystemExit)
        assert "must be empty" in str(outcomes[0])
        assert first.execute("SELECT COUNT(*) FROM scans").fetchone()[0] == 0
    assert checkpoint.read_text() == "preserved bytes"
    assert not list(tmp_path.glob("scan.previous-*"))
