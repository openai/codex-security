import json
import sqlite3
from pathlib import Path

import pytest
from workbench_test_support import empty_target_scan, run_workbench, start_saved_scan


def evidence(path: str, thread_id: str = "parent", call_id: str = "read-1") -> dict:
    return {"path": path, "threadId": thread_id, "callId": call_id}


def record(state: Path, scan_id: str, files: list[dict], *, check: bool = True) -> dict:
    return run_workbench(
        state,
        "record-observed-files",
        "--scan-id",
        scan_id,
        input_text=json.dumps({"files": files}),
        check=check,
    )


def test_observations_union_across_workers_restarts_and_scans(tmp_path: Path) -> None:
    state, target, scan_id, _ = empty_target_scan(tmp_path)
    initial = run_workbench(state, "get-scan", "--scan-id", scan_id)["scan"]
    assert initial["observedFilesRead"] == {"count": None, "observedAt": None}
    first = record(state, scan_id, [evidence("src/a.py"), evidence("src/a.py")])
    assert first["count"] == 1
    assert first["observedAt"]

    # Each command starts a new process and reopens persisted state.
    second = record(
        state,
        scan_id,
        [evidence("src/a.py", "worker"), evidence("src/b.py", "worker")],
    )
    assert second["count"] == 2
    resumed = record(state, scan_id, [evidence("src/c.py", "resumed-worker")])
    assert resumed["count"] == 3
    assert record(state, scan_id, [])["count"] == 3
    saved = run_workbench(state, "get-scan", "--scan-id", scan_id)["scan"]
    assert saved["observedFilesRead"]["count"] == 3
    assert saved["progress"]["coverage"] == initial["progress"]["coverage"]
    assert "files" not in saved["observedFilesRead"]

    other_scan, _ = start_saved_scan(state, target, tmp_path / "other-scans")
    assert record(state, other_scan, [evidence("src/a.py")])["count"] == 1
    assert record(state, scan_id, [])["count"] == 3
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        assert connection.execute(
            "SELECT thread_id, call_id FROM scan_observed_files WHERE scan_id = ? AND path = ?",
            (scan_id, "src/a.py"),
        ).fetchone() == ("parent", "read-1")


def test_empty_observation_is_zero_and_unobserved_history_is_unavailable(tmp_path: Path) -> None:
    state, _, scan_id, _ = empty_target_scan(tmp_path)
    assert record(state, scan_id, [])["count"] == 0
    saved = run_workbench(state, "get-scan", "--scan-id", scan_id)["scan"]
    assert saved["observedFilesRead"]["count"] == 0
    assert saved["observedFilesRead"]["observedAt"]
    assert saved["startedAt"]
    assert saved["completedAt"] is None


def test_existing_scan_migrates_without_inventing_observations(tmp_path: Path) -> None:
    state, _, scan_id, _ = empty_target_scan(tmp_path)
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.execute("DROP TABLE scan_observed_files")
        connection.execute("ALTER TABLE scans DROP COLUMN observed_files_read_at")
        connection.execute("DELETE FROM schema_migrations WHERE version = 58")
    saved = run_workbench(state, "get-scan", "--scan-id", scan_id)["scan"]
    assert saved["scanId"] == scan_id
    assert saved["observedFilesRead"] == {"count": None, "observedAt": None}
    assert record(state, scan_id, [evidence("legacy.py")])["count"] == 1


@pytest.mark.parametrize(
    "path",
    [
        "../secret",
        "/outside.py",
        "C:/outside.py",
        "src\\a.py",
        "",
        ".",
        "src/../a.py",
        "./a.py",
        "bad\0name",
    ],
)
def test_invalid_paths_do_not_partially_record_observations(tmp_path: Path, path: str) -> None:
    state, _, scan_id, _ = empty_target_scan(tmp_path)
    failed = record(state, scan_id, [evidence("src/valid.py"), evidence(path)], check=False)
    assert failed["returncode"] != 0
    saved = run_workbench(state, "get-scan", "--scan-id", scan_id)["scan"]
    assert saved["observedFilesRead"] == {"count": None, "observedAt": None}
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        assert connection.execute("SELECT COUNT(*) FROM scan_observed_files").fetchone()[0] == 0


def test_deleting_scan_removes_its_observed_paths(tmp_path: Path) -> None:
    state, _, scan_id, _ = empty_target_scan(tmp_path)
    record(state, scan_id, [evidence("src/a.py")])
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        assert connection.execute("SELECT COUNT(*) FROM scan_observed_files").fetchone()[0] == 0
