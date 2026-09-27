from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest
from test_workbench_deep_scan import begin_target_scan
from workbench_test_support import mark_deep_coordinator_succeeded, run_workbench


@pytest.mark.parametrize(
    ("first_context", "next_context"),
    (
        ("Review authentication only.", "Review SQL injection only."),
        ("Review authentication only.", None),
        (None, "Review SQL injection only."),
    ),
)
def test_target_request_does_not_reuse_different_user_context(
    tmp_path: Path, first_context: str | None, next_context: str | None
) -> None:
    state_dir = tmp_path / "state"
    codex_home = tmp_path / "codex-home"
    target = tmp_path / "target"
    target.mkdir()
    scan_root = tmp_path / "scans"
    first = begin_target_scan(state_dir, codex_home, target, scan_root, user_context=first_context)
    first_scan_id = str(first["deepScan"]["scanId"])
    mark_deep_coordinator_succeeded(
        state_dir, first_scan_id, Path(str(first["deepScan"]["scanDir"]))
    )

    requested = begin_target_scan(
        state_dir,
        codex_home,
        target,
        scan_root,
        thread_id="thread-new-request",
        user_context=next_context,
    )

    assert requested["startDisposition"] == "created"
    assert requested["deepScan"]["scanId"] != first_scan_id
    assert requested["deepScan"]["userContext"] == next_context
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        assert dict(connection.execute("SELECT id, user_context FROM scans")) == {
            first_scan_id: first_context,
            requested["deepScan"]["scanId"]: next_context,
        }


@pytest.mark.parametrize(
    ("original_context", "edited_context"),
    (
        ("Review authentication only.", "Review SQL injection only."),
        ("Review authentication only.", None),
        (None, "Review SQL injection only."),
    ),
)
@pytest.mark.parametrize("request_original", (False, True))
def test_terminal_reuse_matches_discovery_context_after_edit(
    tmp_path: Path,
    original_context: str | None,
    edited_context: str | None,
    request_original: bool,
) -> None:
    state_dir, codex_home = tmp_path / "state", tmp_path / "codex-home"
    target, scan_root = tmp_path / "target", tmp_path / "scans"
    target.mkdir()
    first = begin_target_scan(
        state_dir, codex_home, target, scan_root, user_context=original_context
    )["deepScan"]
    scan_id = str(first["scanId"])
    mark_deep_coordinator_succeeded(state_dir, scan_id, Path(str(first["scanDir"])))
    edited = run_workbench(
        state_dir,
        "update-scan-context",
        "--scan-id",
        scan_id,
        "--thread-id",
        "thread-deep-scan",
        "--user-context-stdin",
        input_text=edited_context or "",
        environment={"CODEX_HOME": str(codex_home)},
    )
    assert edited["scan"]["userContext"] == edited_context

    requested = begin_target_scan(
        state_dir,
        codex_home,
        target,
        scan_root,
        thread_id="thread-new-request",
        user_context=original_context if request_original else edited_context,
    )
    assert requested["startDisposition"] == ("joined" if request_original else "created")
    assert (requested["deepScan"]["scanId"] == scan_id) is request_original
    assert requested["deepScan"]["userContext"] == (
        original_context if request_original else edited_context
    )
    assert (
        run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]["userContext"]
        == edited_context
    )


@pytest.mark.parametrize("original_context", (None, "Review authentication only."))
def test_context_snapshot_survives_owner_join_and_explicit_resume(
    tmp_path: Path, original_context: str | None
) -> None:
    state_dir, codex_home = tmp_path / "state", tmp_path / "codex-home"
    target, scan_root = tmp_path / "target", tmp_path / "scans"
    target.mkdir()
    first = begin_target_scan(
        state_dir, codex_home, target, scan_root, user_context=original_context
    )["deepScan"]
    scan_id = str(first["scanId"])
    run_workbench(
        state_dir,
        "update-scan-context",
        "--scan-id",
        scan_id,
        "--thread-id",
        "thread-deep-scan",
        "--user-context",
        "Use updated context in later phases.",
    )
    for requested in (
        begin_target_scan(state_dir, codex_home, target, scan_root, user_context="New request"),
        run_workbench(
            state_dir,
            "begin-deep-scan",
            "--scan-id",
            scan_id,
            "--thread-id",
            "thread-deep-scan",
            environment={"CODEX_HOME": str(codex_home)},
        ),
    ):
        assert requested["startDisposition"] == "joined"
        assert requested["deepScan"]["scanId"] == scan_id
        assert requested["deepScan"]["userContext"] == original_context


@pytest.mark.parametrize("resume_existing", (False, True))
def test_begin_and_resume_after_recorded_deep_scan_tables_are_repaired(
    tmp_path: Path, resume_existing: bool
) -> None:
    state_dir, codex_home = tmp_path / "state", tmp_path / "codex-home"
    target, scan_root = tmp_path / "target", tmp_path / "scans"
    target.mkdir()
    original_context = "Review authentication only."
    first = begin_target_scan(
        state_dir, codex_home, target, scan_root, user_context=original_context
    )["deepScan"]
    database = state_dir / "workbench.sqlite3"
    with sqlite3.connect(database) as connection:
        connection.execute("DROP TABLE deep_scan_dedup_inputs")
        connection.execute("DROP TABLE deep_scan_workers")
        connection.execute("DROP TABLE deep_scan_runs")
        assert connection.execute(
            "SELECT version FROM schema_migrations WHERE version IN (11, 43) ORDER BY version"
        ).fetchall() == [(11,), (43,)]

    thread_id = "thread-deep-scan" if resume_existing else "thread-new-request"
    expected_context = original_context if resume_existing else "Review SQL injection only."
    if resume_existing:
        started = run_workbench(
            state_dir,
            "begin-deep-scan",
            "--scan-id",
            str(first["scanId"]),
            "--thread-id",
            thread_id,
            environment={"CODEX_HOME": str(codex_home)},
        )
    else:
        started = begin_target_scan(
            state_dir,
            codex_home,
            target,
            scan_root,
            thread_id=thread_id,
            user_context=expected_context,
        )
    scan_id = str(started["deepScan"]["scanId"])
    assert started["startDisposition"] == "created"
    assert (scan_id == first["scanId"]) is resume_existing
    assert started["deepScan"]["userContext"] == expected_context
    resumed = run_workbench(
        state_dir,
        "begin-deep-scan",
        "--scan-id",
        scan_id,
        "--thread-id",
        thread_id,
        environment={"CODEX_HOME": str(codex_home)},
    )
    assert resumed["startDisposition"] == "joined"
    assert resumed["deepScan"]["userContext"] == expected_context
    with sqlite3.connect(database) as connection:
        assert connection.execute(
            "SELECT discovery_user_context_json FROM deep_scan_runs WHERE scan_id = ?",
            (scan_id,),
        ).fetchone() == (json.dumps(expected_context),)


@pytest.mark.parametrize("migration_recorded", (False, True))
@pytest.mark.parametrize("current_context", (None, "Review authentication only."))
def test_upgrade_keeps_unknown_discovery_context_resumable_but_not_reusable(
    tmp_path: Path, current_context: str | None, migration_recorded: bool
) -> None:
    state_dir, codex_home = tmp_path / "state", tmp_path / "codex-home"
    target, scan_root = tmp_path / "target", tmp_path / "scans"
    target.mkdir()
    first = begin_target_scan(
        state_dir, codex_home, target, scan_root, user_context=current_context
    )["deepScan"]
    scan_id = str(first["scanId"])
    mark_deep_coordinator_succeeded(state_dir, scan_id, Path(str(first["scanDir"])))
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.execute("ALTER TABLE deep_scan_runs DROP COLUMN discovery_user_context_json")
        if not migration_recorded:
            connection.execute("DELETE FROM schema_migrations WHERE version = 43")
    resumed = run_workbench(
        state_dir,
        "begin-deep-scan",
        "--scan-id",
        scan_id,
        "--thread-id",
        "thread-deep-scan",
        environment={"CODEX_HOME": str(codex_home)},
    )
    assert resumed["startDisposition"] == "joined"
    assert resumed["deepScan"]["userContext"] == current_context
    requested = begin_target_scan(
        state_dir,
        codex_home,
        target,
        scan_root,
        thread_id="thread-new-request",
        user_context=current_context,
    )
    assert requested["startDisposition"] == "created"
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        assert connection.execute(
            "SELECT discovery_user_context_json FROM deep_scan_runs WHERE scan_id = ?",
            (scan_id,),
        ).fetchone() == (None,)
