from __future__ import annotations

import argparse
import errno
import json
import os
import runpy
import sqlite3
import subprocess
import sys
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest import mock

import pytest
from workbench_test_support import (
    SCRIPT,
    SNAPSHOT_SCRIPT,
    configure_git_command,
    create_saved_git_workspace,
    create_saved_workspace,
    initialize_git_repository,
    run_workbench,
    write_completed_contract,
)


def test_sqlite_snapshot_includes_uncheckpointed_wal_rows(tmp_path: Path) -> None:
    source = tmp_path / "source.sqlite3"
    snapshot = tmp_path / "snapshot.sqlite3"
    with sqlite3.connect(source) as connection:
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("PRAGMA wal_autocheckpoint = 0")
        connection.execute("CREATE TABLE records (value TEXT NOT NULL)")
        connection.execute("INSERT INTO records VALUES ('sealed')")
        connection.commit()
        subprocess.run(
            [sys.executable, str(SNAPSHOT_SCRIPT), str(source), str(snapshot)],
            check=True,
        )
    with sqlite3.connect(snapshot) as connection:
        assert connection.execute("SELECT value FROM records").fetchone() == ("sealed",)


def test_windows_completion_lock_retries_and_unlocks(tmp_path: Path) -> None:
    namespace = runpy.run_path(str(SCRIPT), run_name="codex_security_workbench_db")
    completion_lock = namespace["scan_completion_lock"]
    lock_globals = completion_lock.__wrapped__.__globals__
    real_write = os.write
    seed_attempts = 0

    def seed_lock_file(descriptor: int, payload: bytes) -> int:
        nonlocal seed_attempts
        seed_attempts += 1
        if seed_attempts == 1:
            raise OSError(errno.EACCES, "another process is seeding the lock file")
        return real_write(descriptor, payload)

    class FakeWindowsFileLock:
        LK_NBLCK = 1
        LK_UNLCK = 2

        def __init__(self) -> None:
            self.calls: list[tuple[int, int, int]] = []
            self.lock_attempts = 0

        def locking(self, descriptor: int, mode: int, byte_count: int) -> None:
            self.calls.append((mode, byte_count, os.lseek(descriptor, 0, os.SEEK_CUR)))
            if mode == self.LK_NBLCK:
                self.lock_attempts += 1
                if self.lock_attempts == 1:
                    raise OSError(errno.EACCES, "lock is held")

    fake_windows_lock = FakeWindowsFileLock()
    scan_id = str(uuid.uuid4())
    with (
        mock.patch.dict(
            lock_globals,
            {"posix_file_lock": None, "windows_file_lock": fake_windows_lock},
        ),
        mock.patch.object(lock_globals["os"], "write", side_effect=seed_lock_file),
        mock.patch.object(lock_globals["time"], "sleep") as sleep,
        mock.patch.dict(os.environ, {"CODEX_SECURITY_STATE_DIR": str(tmp_path)}),
    ):
        try:
            with completion_lock(scan_id):
                raise RuntimeError("exercise unlock")
        except RuntimeError:
            pass

    assert fake_windows_lock.calls == [
        (fake_windows_lock.LK_NBLCK, 1, 0),
        (fake_windows_lock.LK_NBLCK, 1, 0),
        (fake_windows_lock.LK_UNLCK, 1, 0),
    ]
    assert sleep.call_args_list == [mock.call(0.05), mock.call(0.05)]
    lock_path = tmp_path / "completion-locks" / f"{scan_id}.lock"
    assert lock_path.stat().st_size == 1


def test_workbench_does_not_run_textconv_during_diff_setup(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    initialize_git_repository(target)
    marker = tmp_path / "textconv-ran"
    helper = tmp_path / "textconv.py"
    helper.write_text(
        "from pathlib import Path\n"
        "import sys\n"
        f"Path({str(marker)!r}).write_text('ran')\n"
        "sys.stdout.buffer.write(Path(sys.argv[-1]).read_bytes())\n"
    )
    configure_git_command(target, "diff.codex-security-test.textconv", helper)
    (target / ".gitattributes").write_text("README.md diff=codex-security-test\n")
    subprocess.run(["git", "add", ".gitattributes"], cwd=target, check=True)
    subprocess.run(["git", "commit", "-qm", "Add attributes"], cwd=target, check=True)
    (target / "README.md").write_text("changed fixture\n")

    subprocess.run(
        ["git", "diff", "--binary", "--full-index", "--no-ext-diff", "HEAD", "--"],
        cwd=target,
        check=True,
        capture_output=True,
    )
    assert marker.exists()
    marker.unlink()

    run_workbench(
        state_dir,
        "inspect-setup",
        "--target-path",
        str(target),
        "--scope",
        ".",
        "--mode",
        "diff",
        "--diff-target-kind",
        "working_tree",
    )
    assert not marker.exists()


def test_workbench_does_not_run_fsmonitor_during_scan_start(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    initialize_git_repository(target)
    marker = tmp_path / "fsmonitor-ran"
    helper = tmp_path / "fsmonitor.py"
    helper.write_text(
        f"from pathlib import Path\nPath({str(marker)!r}).write_text('ran')\nprint()\n"
    )
    configure_git_command(target, "core.fsmonitor", helper)

    subprocess.run(
        ["git", "ls-files", "--others", "--exclude-standard", "-z"],
        cwd=target,
        check=True,
        capture_output=True,
    )
    assert marker.exists()
    marker.unlink()

    saved = create_saved_git_workspace(state_dir, target)
    run_workbench(state_dir, "start-scan", "--workspace-id", str(saved["id"]))
    assert not marker.exists()


def test_workbench_counts_scope_before_taking_sqlite_writer_lock(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    (target / "source.py").write_text("print('fixture')\n")
    workspace = create_saved_workspace(state_dir, target)
    database = state_dir / "workbench.sqlite3"
    namespace = runpy.run_path(str(SCRIPT), run_name="codex_security_workbench_db")
    start_scan = namespace["start_scan"]
    count_files = start_scan.__globals__["directory_snapshot_regular_file_count"]

    with sqlite3.connect(database) as connection:
        connection.row_factory = sqlite3.Row

        def count_without_writer_lock(scope: Path) -> int:
            assert not connection.in_transaction
            with sqlite3.connect(database, timeout=0) as writer:
                writer.execute("BEGIN IMMEDIATE")
            return count_files(scope)

        with mock.patch.dict(
            start_scan.__globals__,
            {"directory_snapshot_regular_file_count": count_without_writer_lock},
        ):
            started = start_scan(
                connection,
                argparse.Namespace(
                    model=None,
                    reasoning_effort=None,
                    workspace_id=str(workspace["id"]),
                    scan_root=str(tmp_path / "scans"),
                ),
            )

    assert started["results"]["progress"]["coverage"]["filesTotal"] == 1


def test_scan_start_rejects_dirty_initialized_submodule(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    dependency = tmp_path / "dependency"
    initialize_git_repository(dependency)
    target = tmp_path / "target"
    initialize_git_repository(target)
    subprocess.run(
        [
            "git",
            "-c",
            "protocol.file.allow=always",
            "submodule",
            "add",
            "-q",
            str(dependency),
            "vendor/dependency",
        ],
        cwd=target,
        check=True,
    )
    subprocess.run(["git", "commit", "-qam", "Add dependency"], cwd=target, check=True)
    saved = create_saved_git_workspace(state_dir, target)
    (target / "vendor/dependency/README.md").write_text("dirty dependency\n")

    failed = run_workbench(
        state_dir,
        "start-scan",
        "--workspace-id",
        str(saved["id"]),
        check=False,
    )

    assert failed["returncode"] != 0
    assert "Dirty Git submodules are not supported" in str(failed["stderr"])


def test_scan_start_allows_uninitialized_submodule(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    dependency = tmp_path / "dependency"
    initialize_git_repository(dependency)
    target = tmp_path / "target"
    initialize_git_repository(target)
    subprocess.run(
        [
            "git",
            "-c",
            "protocol.file.allow=always",
            "submodule",
            "add",
            "-q",
            str(dependency),
            "vendor/dependency",
        ],
        cwd=target,
        check=True,
    )
    subprocess.run(["git", "commit", "-qam", "Add dependency"], cwd=target, check=True)
    subprocess.run(
        ["git", "submodule", "deinit", "-f", "-q", "--", "vendor/dependency"],
        cwd=target,
        check=True,
    )
    assert not (target / "vendor/dependency/.git").exists()
    saved = create_saved_git_workspace(state_dir, target)

    started = run_workbench(
        state_dir,
        "start-scan",
        "--workspace-id",
        str(saved["id"]),
    )

    assert started["results"]["progress"]["status"] == "running"


def test_scan_start_rejects_submodule_at_unrecorded_revision(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    dependency = tmp_path / "dependency"
    revision_a = initialize_git_repository(dependency)
    (dependency / "README.md").write_text("second revision\n")
    subprocess.run(["git", "commit", "-qam", "Second revision"], cwd=dependency, check=True)
    target = tmp_path / "target"
    initialize_git_repository(target)
    subprocess.run(
        [
            "git",
            "-c",
            "protocol.file.allow=always",
            "submodule",
            "add",
            "-q",
            str(dependency),
            "vendor/dependency",
        ],
        cwd=target,
        check=True,
    )
    subprocess.run(["git", "commit", "-qam", "Add dependency"], cwd=target, check=True)
    submodule = target / "vendor/dependency"
    subprocess.run(["git", "checkout", "-q", revision_a], cwd=submodule, check=True)
    subprocess.run(
        ["git", "config", "submodule.vendor/dependency.ignore", "all"],
        cwd=target,
        check=True,
    )
    saved = create_saved_git_workspace(state_dir, target)

    failed = run_workbench(
        state_dir,
        "start-scan",
        "--workspace-id",
        str(saved["id"]),
        check=False,
    )

    assert failed["returncode"] != 0
    assert "revision recorded by the parent repository" in str(failed["stderr"])


def test_nested_target_name_is_a_literal_git_pathspec(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    repository = tmp_path / "repository"
    initialize_git_repository(repository)
    target = repository / ":(top,glob)**"
    target.mkdir()
    (target / "source.py").write_text("selected = True\n")
    (repository / "outside.py").write_text("outside = 1\n")
    subprocess.run(["git", "add", "."], cwd=repository, check=True)
    subprocess.run(["git", "commit", "-qm", "Add selected target"], cwd=repository, check=True)
    revision = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=repository, text=True
    ).strip()
    workspace_id = str(uuid.uuid4())
    run_workbench(
        state_dir,
        "create-workspace",
        "--workspace-id",
        workspace_id,
        "--target-path",
        str(target),
    )
    run_workbench(
        state_dir,
        "save-workspace",
        "--workspace-id",
        workspace_id,
        "--target-path",
        str(target),
        "--scope",
        ".",
        "--mode",
        "standard",
    )
    started = run_workbench(
        state_dir,
        "start-scan",
        "--workspace-id",
        workspace_id,
        "--scan-root",
        str(tmp_path / "scans"),
    )
    scan_id = str(started["results"]["scanId"])
    scan_dir = Path(str(started["results"]["scanDir"]))
    (repository / "outside.py").write_text("outside = 2\n")
    write_completed_contract(
        scan_dir,
        scan_id,
        target,
        relative_path="source.py",
        target_kind="git_revision",
        target_revision=revision,
    )

    completed = run_workbench(state_dir, "complete-scan", "--scan-id", scan_id)
    assert completed["scan"]["progress"]["status"] == "complete"


def test_workbench_defaults_to_persistent_codex_home_state(tmp_path: Path) -> None:
    codex_home = tmp_path / "codex-home"
    completed = subprocess.run(
        [sys.executable, str(SCRIPT), "database-info"],
        check=True,
        capture_output=True,
        env={**os.environ, "CODEX_HOME": str(codex_home), "CODEX_SECURITY_STATE_DIR": ""},
        text=True,
    )
    assert json.loads(completed.stdout) == {
        "databasePath": str(
            codex_home / "state" / "plugins" / "codex-security" / "workbench.sqlite3"
        )
    }


def test_workbench_serializes_concurrent_first_run_migrations(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _: run_workbench(state_dir, "database-info"), range(2)))
    assert results == [
        {"databasePath": str(state_dir / "workbench.sqlite3")},
        {"databasePath": str(state_dir / "workbench.sqlite3")},
    ]
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        assert connection.execute("SELECT COUNT(*) FROM schema_migrations").fetchone() == (32,)


def test_workbench_backfills_repository_targets_only_during_migration() -> None:
    namespace = runpy.run_path(str(SCRIPT), run_name="codex_security_workbench_db")
    apply_migrations = namespace["apply_migrations"]
    backfill = mock.Mock(wraps=namespace["backfill_security_targets"])
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row

    with mock.patch.dict(apply_migrations.__globals__, {"backfill_security_targets": backfill}):
        apply_migrations(connection)
        apply_migrations(connection)

    backfill.assert_called_once_with(connection)


def test_scan_model_migration_preserves_existing_scans() -> None:
    namespace = runpy.run_path(str(SCRIPT), run_name="codex_security_workbench_db")
    apply_migrations = namespace["apply_migrations"]
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    historical_migrations = tuple(
        migration for migration in namespace["MIGRATIONS"] if migration[0] < 25
    )
    with mock.patch.dict(apply_migrations.__globals__, {"MIGRATIONS": historical_migrations}):
        apply_migrations(connection)
    timestamp = "2026-07-01T00:00:00Z"
    connection.execute(
        "INSERT INTO workspaces (id, created_at, updated_at) VALUES (?, ?, ?)",
        ("legacy-workspace", timestamp, timestamp),
    )
    connection.execute(
        """
        INSERT INTO scans (
            id, workspace_id, target_path, target_revision, scope, mode, scan_dir,
            status, phase, started_at, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "legacy-scan",
            "legacy-workspace",
            "/legacy/target",
            "legacy-revision",
            ".",
            "standard",
            "/legacy/scan",
            "running",
            "discovery",
            timestamp,
            timestamp,
            timestamp,
        ),
    )
    connection.commit()

    apply_migrations(connection)

    scan = connection.execute(
        "SELECT status, model, reasoning_effort, completion_warnings_json FROM scans WHERE id = ?",
        ("legacy-scan",),
    ).fetchone()
    assert scan["status"] == "running"
    assert scan["model"] is None
    assert scan["reasoning_effort"] is None
    assert scan["completion_warnings_json"] == "[]"


def test_deep_discovery_error_migration_backfills_each_existing_threshold() -> None:
    namespace = runpy.run_path(str(SCRIPT), run_name="codex_security_workbench_db")
    apply_migrations = namespace["apply_migrations"]
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    historical_migrations = tuple(
        migration for migration in namespace["MIGRATIONS"] if migration[0] < 27
    )
    with mock.patch.dict(apply_migrations.__globals__, {"MIGRATIONS": historical_migrations}):
        apply_migrations(connection)

    timestamp = "2026-07-01T00:00:00Z"
    for index, stop_after_no_new in enumerate((2, 7), start=1):
        workspace_id = f"legacy-deep-workspace-{index}"
        scan_id = f"legacy-deep-scan-{index}"
        connection.execute(
            "INSERT INTO workspaces (id, created_at, updated_at) VALUES (?, ?, ?)",
            (workspace_id, timestamp, timestamp),
        )
        connection.execute(
            """
            INSERT INTO scans (
                id, workspace_id, target_path, target_revision, scope, mode,
                scan_dir, status, phase, started_at, created_at, updated_at
            ) VALUES (?, ?, ?, ?, '.', 'deep', ?, 'running', 'discovery', ?, ?, ?)
            """,
            (
                scan_id,
                workspace_id,
                f"/legacy/target-{index}",
                "legacy-revision",
                f"/legacy/scan-{index}",
                timestamp,
                timestamp,
                timestamp,
            ),
        )
        connection.execute(
            """
            INSERT INTO deep_scan_runs (
                scan_id, schema_version, workflow_version, status, phase,
                workers, subagents, stop_after_no_new, max_discovery_runs,
                created_at, updated_at
            ) VALUES (?, 1, 'deep-scan-mcp/v1', 'running', 'discovery',
                2, 0, ?, 10, ?, ?)
            """,
            (scan_id, stop_after_no_new, timestamp, timestamp),
        )
    connection.commit()

    apply_migrations(connection)

    rows = connection.execute(
        """
        SELECT stop_after_no_new, stop_after_consecutive_errors, consecutive_errors
        FROM deep_scan_runs
        ORDER BY scan_id
        """
    ).fetchall()
    assert [tuple(row) for row in rows] == [(2, 2, 0), (7, 7, 0)]


@pytest.mark.parametrize(
    ("legacy_name", "has_owner_columns"),
    (
        ("durable deep scan coordinator ownership", True),
        ("repair deep scan orchestration state", False),
    ),
)
def test_workbench_repairs_recorded_deep_scan_failure_counter_migration(
    legacy_name: str, has_owner_columns: bool
) -> None:
    namespace = runpy.run_path(str(SCRIPT), run_name="codex_security_workbench_db")
    apply_migrations = namespace["apply_migrations"]
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    historical_migrations = tuple(
        migration for migration in namespace["MIGRATIONS"] if migration[0] < 27
    )
    with mock.patch.dict(apply_migrations.__globals__, {"MIGRATIONS": historical_migrations}):
        apply_migrations(connection)
    timestamp = "2026-07-01T00:00:00Z"
    for scan_id, stop_after_no_new in (("legacy-scan-a", 2), ("legacy-scan-b", 7)):
        workspace_id = f"workspace-{scan_id}"
        connection.execute(
            "INSERT INTO workspaces (id, created_at, updated_at) VALUES (?, ?, ?)",
            (workspace_id, timestamp, timestamp),
        )
        connection.execute(
            """
            INSERT INTO scans (
                id, workspace_id, target_path, target_revision, scope, mode, scan_dir,
                status, phase, started_at, created_at, updated_at
            ) VALUES (?, ?, ?, 'legacy-revision', '.', 'deep', ?,
                'running', 'discovery', ?, ?, ?)
            """,
            (
                scan_id,
                workspace_id,
                f"/legacy/{scan_id}",
                f"/legacy/scans/{scan_id}",
                timestamp,
                timestamp,
                timestamp,
            ),
        )
        connection.execute(
            """
            INSERT INTO deep_scan_runs (
                scan_id, schema_version, workflow_version, status, phase, workers,
                subagents, stop_after_no_new, max_discovery_runs, created_at, updated_at
            ) VALUES (?, 1, 'legacy-workflow', 'running', 'discovery', 1, 0, ?, 10, ?, ?)
            """,
            (scan_id, stop_after_no_new, timestamp, timestamp),
        )
    if has_owner_columns:
        connection.execute("ALTER TABLE deep_scan_runs ADD COLUMN coordinator_owner_id TEXT")
        connection.execute("ALTER TABLE deep_scan_runs ADD COLUMN coordinator_heartbeat_at TEXT")
    connection.execute(
        "INSERT INTO schema_migrations (version, name, applied_at) VALUES (27, ?, ?)",
        (legacy_name, timestamp),
    )
    connection.commit()
    apply_migrations(connection)
    assert [
        tuple(row)
        for row in connection.execute(
            "SELECT stop_after_consecutive_errors, stop_after_no_new, consecutive_errors "
            "FROM deep_scan_runs ORDER BY scan_id"
        )
    ] == [(2, 2, 0), (7, 7, 0)]
    connection.execute(
        "UPDATE deep_scan_runs SET stop_after_consecutive_errors = 9, consecutive_errors = 3"
    )
    connection.commit()
    apply_migrations(connection)

    assert [
        tuple(row)
        for row in connection.execute(
            "SELECT stop_after_consecutive_errors, consecutive_errors "
            "FROM deep_scan_runs ORDER BY scan_id"
        )
    ] == [(9, 3), (9, 3)]
    assert (
        connection.execute("SELECT name FROM schema_migrations WHERE version = 27").fetchone()[
            "name"
        ]
        == legacy_name
    )
    if has_owner_columns:
        assert {"coordinator_owner_id", "coordinator_heartbeat_at"} <= {
            row[1] for row in connection.execute("PRAGMA table_info(deep_scan_runs)")
        }


@pytest.mark.parametrize("migration_recorded", (False, True))
def test_deep_scan_time_limit_migration_backfills_and_repairs_existing_runs(
    migration_recorded: bool,
) -> None:
    namespace = runpy.run_path(str(SCRIPT), run_name="codex_security_workbench_db")
    apply_migrations = namespace["apply_migrations"]
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    historical_migrations = tuple(
        migration for migration in namespace["MIGRATIONS"] if migration[0] < 28
    )
    with mock.patch.dict(apply_migrations.__globals__, {"MIGRATIONS": historical_migrations}):
        apply_migrations(connection)

    timestamp = "2026-07-01T00:00:00Z"
    connection.execute(
        "INSERT INTO workspaces (id, created_at, updated_at) VALUES (?, ?, ?)",
        ("legacy-workspace", timestamp, timestamp),
    )
    connection.execute(
        """
        INSERT INTO scans (
            id, workspace_id, target_path, target_revision, scope, mode, scan_dir,
            status, phase, started_at, created_at, updated_at
        ) VALUES (?, ?, '/legacy/target', 'legacy-revision', '.', 'deep',
            '/legacy/scan', 'running', 'discovery', ?, ?, ?)
        """,
        ("legacy-scan", "legacy-workspace", timestamp, timestamp, timestamp),
    )
    connection.execute(
        """
        INSERT INTO deep_scan_runs (
            scan_id, schema_version, workflow_version, status, phase, workers,
            subagents, stop_after_no_new, max_discovery_runs, created_at, updated_at
        ) VALUES (?, 1, 'legacy-workflow', 'running', 'discovery', 1, 0, 3, 10, ?, ?)
        """,
        ("legacy-scan", timestamp, timestamp),
    )
    if migration_recorded:
        connection.execute(
            "INSERT INTO schema_migrations (version, name, applied_at) VALUES (28, ?, ?)",
            ("persist deep scan discovery time limit", timestamp),
        )
    connection.commit()

    apply_migrations(connection)

    assert connection.execute("SELECT max_time_hours FROM deep_scan_runs").fetchone()[0] == 96.0
    connection.execute("UPDATE deep_scan_runs SET max_time_hours = 2.5")
    connection.commit()

    apply_migrations(connection)

    assert connection.execute("SELECT max_time_hours FROM deep_scan_runs").fetchone()[0] == 2.5
    assert (
        connection.execute("SELECT name FROM schema_migrations WHERE version = 28").fetchone()[0]
        == "persist deep scan discovery time limit"
    )


def test_workbench_reconciles_monorepo_migration_lineage() -> None:
    namespace = runpy.run_path(str(SCRIPT), run_name="codex_security_workbench_db")
    apply_migrations = namespace["apply_migrations"]
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    historical_migrations = tuple(
        migration for migration in namespace["MIGRATIONS"] if migration[0] < 29
    )
    with mock.patch.dict(apply_migrations.__globals__, {"MIGRATIONS": historical_migrations}):
        apply_migrations(connection)

    retained_digest_applied_at = "2026-08-20T10:00:00Z"
    publication_error_applied_at = "2026-08-21T11:00:00Z"
    connection.execute("ALTER TABLE scans ADD COLUMN retained_source_digests_json TEXT")
    connection.execute("ALTER TABLE deep_scan_runs ADD COLUMN publication_error_message TEXT")
    connection.executemany(
        "INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)",
        (
            (29, "freeze stopped scan source digests", retained_digest_applied_at),
            (30, "separate deep scan publication failures", publication_error_applied_at),
        ),
    )
    connection.commit()

    apply_migrations(connection)
    apply_migrations(connection)

    assert [
        tuple(row)
        for row in connection.execute(
            "SELECT version, name, applied_at FROM schema_migrations "
            "WHERE version BETWEEN 29 AND 32 ORDER BY version"
        )
    ] == [
        (29, "persist finding publication associations", mock.ANY),
        (30, "preserve team-only finding publication associations", mock.ANY),
        (31, "freeze stopped scan source digests", retained_digest_applied_at),
        (32, "separate deep scan publication failures", publication_error_applied_at),
    ]
    assert connection.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'finding_publications'"
    ).fetchone() is not None
    assert {
        row[0]
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'index' "
            "AND tbl_name = 'finding_publications'"
        )
    } >= {
        "finding_publications_by_scan",
        "finding_publications_by_finding",
        "finding_publications_team_only_occurrence",
        "finding_publications_team_only_external_issue",
    }
    assert [
        row["name"]
        for row in connection.execute("PRAGMA table_info(scans)")
        if row["name"] == "retained_source_digests_json"
    ] == ["retained_source_digests_json"]
    assert [
        row["name"]
        for row in connection.execute("PRAGMA table_info(deep_scan_runs)")
        if row["name"] == "publication_error_message"
    ] == ["publication_error_message"]


def test_workbench_creates_single_final_schema(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    run_workbench(state_dir, "database-info")

    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        assert connection.execute("SELECT version, name FROM schema_migrations").fetchall() == [
            (1, "initial workbench schema"),
            (2, "persist capability preflight summaries"),
            (3, "finding management schema"),
            (4, "scan handoff delivery claims"),
            (5, "finding remediation action claims"),
            (6, "thread-scoped workspaces"),
            (7, "remediation host delivery state"),
            (8, "sealed manifest digests"),
            (9, "scan target filesystem identity"),
            (10, "scan cancellation state"),
            (11, "deep scan orchestration state"),
            (12, "scan continuation threads"),
            (13, "scan scope file counts"),
            (14, "imported triage results"),
            (15, "append-only finding decisions"),
            (16, "stable repository targets"),
            (17, "scan target summaries"),
            (18, "clear legacy delivered handoff claims"),
            (19, "persist setup workspace preference"),
            (20, "phase-specific scan progress"),
            (21, "current scan preflight state"),
            (22, "replayable scan launch recipes"),
            (23, "semantic scan comparison matches"),
            (24, "persist scan cost estimates"),
            (25, "persist scan model settings"),
            (26, "persist scan completion warnings"),
            (27, "persist deep scan consecutive discovery failures"),
            (28, "persist deep scan discovery time limit"),
            (29, "persist finding publication associations"),
            (30, "preserve team-only finding publication associations"),
            (31, "freeze stopped scan source digests"),
            (32, "separate deep scan publication failures"),
        ]
        assert {row[1] for row in connection.execute("PRAGMA table_info(workspaces)")} >= {
            "diff_target_kind",
            "diff_base_revision",
            "diff_head_revision",
            "diff_content_digest",
            "diff_resolution_id",
            "capability_preflight_json",
            "thread_id",
        }

        assert {row[1] for row in connection.execute("PRAGMA table_info(scans)")} >= {
            "diff_target_kind",
            "diff_base_revision",
            "diff_head_revision",
            "diff_content_digest",
            "handoff_claimed_at",
            "handoff_claim_token",
            "handoff_status",
            "target_snapshot_digest",
            "seal_manifest_digest",
            "target_device",
            "target_inode",
            "canceled_at",
            "deep_scan_owner_thread_id",
            "continuation_thread_id",
            "target_summary",
            "recipe_json",
            "parent_scan_id",
            "cost_json",
            "completion_warnings_json",
            "model",
            "reasoning_effort",
        }
        assert {row[1] for row in connection.execute("PRAGMA table_info(scan_progress)")} >= {
            "deep_review_pass",
            "scope_file_count",
            "phase_items_completed",
            "phase_items_total",
            "phase_progress_unit",
            "preflight_checks_completed",
            "preflight_checks_total",
            "preflight_issues_json",
        }
        assert {row[1] for row in connection.execute("PRAGMA table_info(deep_scan_runs)")} >= {
            "canonical_inventory_path",
            "canonical_finding_report_path",
            "canonical_candidates_path",
            "dedupe_report_path",
            "seed_research_path",
            "work_ledger_path",
            "raw_candidates_path",
            "coverage_ledger_path",
            "findings_dir",
            "stop_after_consecutive_errors",
            "consecutive_errors",
            "max_time_hours",
        }
        assert {
            row[1] for row in connection.execute("PRAGMA table_info(finding_remediation_attempts)")
        } >= {
            "applied_content_digest",
            "base_content_digest",
            "pending_action",
            "pending_action_claimed_at",
            "pending_action_claim_token",
            "pending_action_delivered_at",
        }
        assert {row[1] for row in connection.execute("PRAGMA table_info(setup_preferences)")} == {
            "singleton",
            "skip_setup_ui",
            "updated_at",
        }
        assert connection.execute(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'app_settings'"
        ).fetchone() == (0,)
        assert connection.execute(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = 'scans_one_running_per_workspace'"
        ).fetchone() == (1,)
        assert connection.execute(
            "SELECT COUNT(*) FROM sqlite_master "
            "WHERE type = 'index' AND name = 'scans_one_running_deep_per_owner_target'"
        ).fetchone() == (1,)


def test_workbench_upgrades_preexisting_database(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    run_workbench(state_dir, "database-info")
    database = state_dir / "workbench.sqlite3"
    with sqlite3.connect(database) as connection:
        connection.execute("DELETE FROM schema_migrations WHERE version = 5")
        connection.execute(
            "ALTER TABLE finding_remediation_attempts DROP COLUMN pending_action_claimed_at"
        )
        connection.execute(
            "ALTER TABLE finding_remediation_attempts DROP COLUMN pending_action_claim_token"
        )
        connection.execute("DELETE FROM schema_migrations WHERE version = 4")
        connection.execute("ALTER TABLE scans DROP COLUMN handoff_claimed_at")
        connection.execute("ALTER TABLE scans DROP COLUMN handoff_claim_token")
    run_workbench(state_dir, "database-info")
    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone() == (32,)
        assert {row[1] for row in connection.execute("PRAGMA table_info(scans)")} >= {
            "handoff_claimed_at",
            "handoff_claim_token",
            "target_snapshot_digest",
            "seal_manifest_digest",
            "target_device",
            "target_inode",
            "continuation_thread_id",
        }
        assert {
            row[1] for row in connection.execute("PRAGMA table_info(finding_remediation_attempts)")
        } >= {
            "pending_action_claimed_at",
            "pending_action_claim_token",
            "pending_action_delivered_at",
        }


@pytest.mark.parametrize(
    ("drop_owner_column", "drop_deep_scan_tables", "attach_continuation"),
    (
        (True, False, False),
        (True, True, False),
        (True, False, True),
        (False, True, True),
        (False, False, True),
    ),
)
def test_workbench_repairs_recorded_deep_scan_migration(
    tmp_path: Path,
    drop_owner_column: bool,
    drop_deep_scan_tables: bool,
    attach_continuation: bool,
) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    workspace = create_saved_workspace(state_dir, target, thread_id="thread-deep-scan", mode="deep")
    started = run_workbench(
        state_dir,
        "start-scan",
        "--workspace-id",
        str(workspace["id"]),
        "--scan-root",
        str(tmp_path / "scans"),
    )
    scan_id = str(started["results"]["scanId"])
    database = state_dir / "workbench.sqlite3"

    with sqlite3.connect(database) as connection:
        if attach_continuation:
            connection.execute(
                "UPDATE scans SET continuation_thread_id = ?, deep_scan_owner_thread_id = ? "
                "WHERE id = ?",
                ("thread-continuation", "thread-continuation", scan_id),
            )
        if drop_owner_column:
            connection.execute("DROP INDEX scans_one_running_deep_per_owner_target")
            connection.execute("ALTER TABLE scans DROP COLUMN deep_scan_owner_thread_id")
        if drop_deep_scan_tables:
            connection.execute("DROP TABLE deep_scan_dedup_inputs")
            connection.execute("DROP TABLE deep_scan_workers")
            connection.execute("DROP TABLE deep_scan_runs")
        elif not drop_owner_column:
            connection.execute("DROP INDEX deep_scan_workers_by_scan_status")

    run_workbench(state_dir, "database-info")

    with sqlite3.connect(database) as connection:
        expected_owner = "thread-continuation" if attach_continuation else "thread-deep-scan"
        assert connection.execute(
            "SELECT deep_scan_owner_thread_id, status FROM scans WHERE id = ?", (scan_id,)
        ).fetchone() == (expected_owner, "running")
        assert connection.execute(
            "SELECT name FROM schema_migrations WHERE version = 11"
        ).fetchone() == ("deep scan orchestration state",)
        assert connection.execute(
            "SELECT name FROM schema_migrations WHERE version = 27"
        ).fetchone() == ("persist deep scan consecutive discovery failures",)
        assert connection.execute(
            "SELECT name FROM schema_migrations WHERE version = 28"
        ).fetchone() == ("persist deep scan discovery time limit",)
        assert "max_time_hours" in {
            row[1] for row in connection.execute("PRAGMA table_info(deep_scan_runs)")
        }
        assert {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE name LIKE 'deep_scan_%' "
                "OR name = 'scans_one_running_deep_per_owner_target'"
            )
        } >= {
            "deep_scan_runs",
            "deep_scan_workers",
            "deep_scan_dedup_inputs",
            "deep_scan_workers_completion_sequence",
            "deep_scan_workers_by_scan_status",
            "scans_one_running_deep_per_owner_target",
        }


def test_workbench_repairs_pre_release_scan_continuation_migration(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    database = state_dir / "workbench.sqlite3"
    database.parent.mkdir(parents=True)
    target = tmp_path / "target"
    target.mkdir()
    workspace_id = str(uuid.uuid4())
    scan_id = str(uuid.uuid4())
    automation_id = str(uuid.uuid4())
    thread_id = "thread-deep-scan"
    timestamp = "2026-06-24T18:57:06Z"
    namespace = runpy.run_path(str(SCRIPT), run_name="codex_security_workbench_schema")
    migrations = namespace["MIGRATIONS"]
    legacy_migrations = (
        (
            11,
            "background Codex scan workers",
            """
            CREATE TABLE scan_workers (
                scan_id TEXT PRIMARY KEY REFERENCES scans(id) ON DELETE CASCADE,
                claim_token TEXT NOT NULL,
                status TEXT NOT NULL CHECK (
                    status IN ('starting', 'running', 'paused', 'complete', 'failed', 'canceled')
                ),
                supervisor_pid INTEGER CHECK (supervisor_pid IS NULL OR supervisor_pid >= 1),
                codex_pid INTEGER CHECK (codex_pid IS NULL OR codex_pid >= 1),
                codex_thread_id TEXT,
                log_path TEXT NOT NULL,
                exit_code INTEGER,
                error_message TEXT,
                started_at TEXT NOT NULL,
                completed_at TEXT,
                updated_at TEXT NOT NULL
            );
            """,
        ),
        (
            12,
            "managed repositories and local automations",
            """
            CREATE TABLE managed_repositories (
                path TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                added_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE local_automations (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                repository_path TEXT NOT NULL,
                mode TEXT NOT NULL CHECK (mode IN ('diff', 'standard', 'deep')),
                scope TEXT NOT NULL DEFAULT '.',
                trigger_kind TEXT NOT NULL CHECK (trigger_kind IN ('daily', 'weekly', 'commit')),
                schedule TEXT,
                missed_policy TEXT NOT NULL DEFAULT 'run_latest'
                    CHECK (missed_policy IN ('run_latest', 'skip')),
                enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
                next_run_at TEXT,
                last_run_at TEXT,
                last_scan_id TEXT REFERENCES scans(id) ON DELETE SET NULL,
                last_observed_revision TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE INDEX local_automations_by_repository
            ON local_automations(repository_path, updated_at DESC);

            ALTER TABLE scans ADD COLUMN trigger_kind TEXT NOT NULL DEFAULT 'manual'
                CHECK (trigger_kind IN ('manual', 'automation'));

            ALTER TABLE scans ADD COLUMN automation_id TEXT
                REFERENCES local_automations(id) ON DELETE SET NULL;
            """,
        ),
    )

    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute(
            """
            CREATE TABLE schema_migrations (
                version INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                applied_at TEXT NOT NULL
            )
            """
        )
        for version, name, sql in (*migrations[:10], *legacy_migrations):
            for statement in namespace["sql_statements"](sql):
                connection.execute(statement)
            connection.execute(
                "INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)",
                (version, name, timestamp),
            )
        connection.execute(
            """
            INSERT INTO workspaces (
                id, target_path, target_title, default_mode, submitted, thread_id,
                created_at, updated_at
            ) VALUES (?, ?, ?, 'deep', 1, ?, ?, ?)
            """,
            (workspace_id, str(target), "Legacy target", thread_id, timestamp, timestamp),
        )
        connection.execute(
            """
            INSERT INTO scans (
                id, workspace_id, target_path, target_revision, scope, mode, scan_dir,
                status, phase, started_at, created_at, updated_at
            ) VALUES (?, ?, ?, 'unversioned', '.', 'deep', ?, 'running', 'preflight', ?, ?, ?)
            """,
            (
                scan_id,
                workspace_id,
                str(target),
                str(tmp_path / "scans"),
                timestamp,
                timestamp,
                timestamp,
            ),
        )
        connection.execute(
            "INSERT INTO scan_progress (scan_id, updated_at) VALUES (?, ?)",
            (scan_id, timestamp),
        )
        connection.execute(
            "INSERT INTO managed_repositories (path, name, added_at, updated_at) "
            "VALUES (?, 'Legacy target', ?, ?)",
            (str(target), timestamp, timestamp),
        )
        connection.execute(
            """
            INSERT INTO local_automations (
                id, name, repository_path, mode, trigger_kind, schedule, last_scan_id,
                last_observed_revision, created_at, updated_at
            ) VALUES (?, 'Legacy daily scan', ?, 'deep', 'daily', '09:00', ?,
                'legacy-revision', ?, ?)
            """,
            (automation_id, str(target), scan_id, timestamp, timestamp),
        )
        connection.execute(
            "UPDATE scans SET trigger_kind = 'automation', automation_id = ? WHERE id = ?",
            (automation_id, scan_id),
        )
        connection.execute(
            "UPDATE workspaces SET active_scan_id = ? WHERE id = ?",
            (scan_id, workspace_id),
        )
        connection.execute(
            """
            INSERT INTO scan_workers (
                scan_id, claim_token, status, supervisor_pid, codex_pid, codex_thread_id,
                log_path, started_at, updated_at
            ) VALUES (?, 'legacy-claim', 'running', 101, 202, 'legacy-codex-thread',
                'legacy.log', ?, ?)
            """,
            (scan_id, timestamp, timestamp),
        )

    first = run_workbench(state_dir, "get-workspace", "--workspace-id", workspace_id)
    second = run_workbench(state_dir, "get-workspace", "--workspace-id", workspace_id)

    assert first == second
    assert first["results"]["continuationThreadId"] is None
    with sqlite3.connect(database) as connection:
        assert connection.execute(
            "SELECT version, name FROM schema_migrations WHERE version IN (11, 12) ORDER BY version"
        ).fetchall() == [
            (11, "background Codex scan workers"),
            (12, "managed repositories and local automations"),
        ]
        assert connection.execute(
            "SELECT deep_scan_owner_thread_id, continuation_thread_id, trigger_kind, automation_id "
            "FROM scans WHERE id = ?",
            (scan_id,),
        ).fetchone() == (thread_id, None, "automation", automation_id)
        assert connection.execute(
            "SELECT claim_token, supervisor_pid, codex_pid, codex_thread_id, log_path "
            "FROM scan_workers WHERE scan_id = ?",
            (scan_id,),
        ).fetchone() == (
            "legacy-claim",
            101,
            202,
            "legacy-codex-thread",
            "legacy.log",
        )
        assert connection.execute(
            "SELECT name FROM managed_repositories WHERE path = ?", (str(target),)
        ).fetchone() == ("Legacy target",)
        assert connection.execute(
            "SELECT name, schedule, last_scan_id, last_observed_revision "
            "FROM local_automations WHERE id = ?",
            (automation_id,),
        ).fetchone() == (
            "Legacy daily scan",
            "09:00",
            scan_id,
            "legacy-revision",
        )
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []


def test_workbench_repairs_recorded_scan_scope_file_count_migration(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    workspace = create_saved_workspace(state_dir, target)
    started = run_workbench(state_dir, "start-scan", "--workspace-id", str(workspace["id"]))
    scan_id = str(started["results"]["scanId"])
    database = state_dir / "workbench.sqlite3"

    with sqlite3.connect(database) as connection:
        connection.execute("ALTER TABLE scan_progress DROP COLUMN scope_file_count")
        connection.execute(
            "UPDATE schema_migrations SET name = ? WHERE version = 13",
            ("linear scan phase enforcement",),
        )

    first = run_workbench(state_dir, "get-workspace", "--workspace-id", str(workspace["id"]))
    second = run_workbench(state_dir, "get-workspace", "--workspace-id", str(workspace["id"]))

    assert first == second
    assert first["results"]["progress"]["coverage"]["filesTotal"] is None
    with sqlite3.connect(database) as connection:
        assert connection.execute(
            "SELECT name FROM schema_migrations WHERE version = 13"
        ).fetchone() == ("linear scan phase enforcement",)
        assert connection.execute(
            "SELECT scope_file_count FROM scan_progress WHERE scan_id = ?", (scan_id,)
        ).fetchone() == (None,)
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []


@pytest.mark.parametrize(
    ("legacy_name", "owns_thread_schema"),
    (
        ("thread-scoped workspaces", True),
        ("add MCP-managed staging directories", False),
        ("scoped scan artifact persistence", False),
    ),
)
def test_workbench_repairs_shadowed_capability_preflight_migration(
    tmp_path: Path, legacy_name: str, owns_thread_schema: bool
) -> None:
    state_dir = tmp_path / "state"
    run_workbench(state_dir, "database-info")
    database = state_dir / "workbench.sqlite3"

    with sqlite3.connect(database) as connection:
        connection.execute("ALTER TABLE workspaces DROP COLUMN capability_preflight_json")
        connection.execute(
            "UPDATE schema_migrations SET name = ? WHERE version = 2", (legacy_name,)
        )
        if owns_thread_schema:
            connection.execute("DELETE FROM schema_migrations WHERE version = 6")

    run_workbench(state_dir, "database-info")
    run_workbench(state_dir, "database-info")

    with sqlite3.connect(database) as connection:
        assert "capability_preflight_json" in {
            row[1] for row in connection.execute("PRAGMA table_info(workspaces)")
        }
        assert connection.execute(
            "SELECT version, name FROM schema_migrations WHERE version IN (2, 6) ORDER BY version"
        ).fetchall() == [
            (2, legacy_name),
            (6, "thread-scoped workspaces"),
        ]
        assert connection.execute(
            "SELECT COUNT(*) FROM sqlite_master "
            "WHERE type = 'index' AND name = 'workspaces_by_thread_and_updated_at'"
        ).fetchone() == (1,)


def test_workbench_upgrades_stable_scan_target_identity_migration(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    database = state_dir / "workbench.sqlite3"
    database.parent.mkdir(parents=True)
    target = tmp_path / "target"
    target.mkdir()
    workspace_id = str(uuid.uuid4())
    scan_id = str(uuid.uuid4())
    legacy_target_id = "target_legacy_remote_identity"
    timestamp = "2026-06-30T00:00:00Z"
    namespace = runpy.run_path(str(SCRIPT), run_name="codex_security_workbench_schema")
    migrations = namespace["MIGRATIONS"]
    legacy_migration = (
        11,
        "stable scan target identities",
        "ALTER TABLE scans ADD COLUMN target_id TEXT;",
    )

    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute(
            """
            CREATE TABLE schema_migrations (
                version INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                applied_at TEXT NOT NULL
            )
            """
        )
        for version, name, sql in (*migrations[:10], legacy_migration, *migrations[11:15]):
            for statement in namespace["sql_statements"](sql):
                connection.execute(statement)
            connection.execute(
                "INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)",
                (version, name, timestamp),
            )
        connection.execute(
            """
            INSERT INTO workspaces (
                id, target_path, target_title, default_mode, submitted, created_at, updated_at
            ) VALUES (?, ?, 'Legacy target', 'standard', 1, ?, ?)
            """,
            (workspace_id, str(target), timestamp, timestamp),
        )
        connection.execute(
            """
            INSERT INTO scans (
                id, workspace_id, target_id, target_path, target_revision, scope, mode,
                scan_dir, status, phase, started_at, created_at, updated_at
            ) VALUES (?, ?, ?, ?, 'legacy-revision', '.', 'standard', ?, 'running',
                'discovery', ?, ?, ?)
            """,
            (
                scan_id,
                workspace_id,
                legacy_target_id,
                str(target),
                str(tmp_path / "scans"),
                timestamp,
                timestamp,
                timestamp,
            ),
        )
        connection.execute(
            "INSERT INTO scan_progress (scan_id, updated_at) VALUES (?, ?)",
            (scan_id, timestamp),
        )
        connection.execute(
            "UPDATE workspaces SET active_scan_id = ? WHERE id = ?", (scan_id, workspace_id)
        )

    first = run_workbench(state_dir, "get-workspace", "--workspace-id", workspace_id)
    second = run_workbench(state_dir, "get-workspace", "--workspace-id", workspace_id)
    repositories = run_workbench(state_dir, "list-repositories")["repositories"]

    assert first == second
    assert len(repositories) == 1
    assert repositories[0]["targetPath"] == str(target)
    assert repositories[0]["scanCount"] == 1
    with sqlite3.connect(database) as connection:
        assert connection.execute(
            "SELECT version, name FROM schema_migrations WHERE version IN (11, 16) ORDER BY version"
        ).fetchall() == [
            (11, "stable scan target identities"),
            (16, "stable repository targets"),
        ]
        workspace_target_id = connection.execute(
            "SELECT target_id FROM workspaces WHERE id = ?", (workspace_id,)
        ).fetchone()[0]
        assert workspace_target_id != legacy_target_id
        assert connection.execute(
            "SELECT target_id FROM scans WHERE id = ?", (scan_id,)
        ).fetchone() == (workspace_target_id,)
        assert repositories[0]["targetId"] == workspace_target_id
        assert connection.execute(
            "SELECT id, current_path FROM security_targets WHERE id = ?", (workspace_target_id,)
        ).fetchone() == (workspace_target_id, str(target))
        assert [row[2] for row in connection.execute("PRAGMA index_info(scans_by_target)")] == [
            "target_id",
            "started_at",
            "id",
        ]
        assert [row[1] for row in connection.execute("PRAGMA table_info(scans)")].count(
            "target_id"
        ) == 1
        assert [row[1] for row in connection.execute("PRAGMA table_info(workspaces)")].count(
            "target_id"
        ) == 1
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []


def test_workbench_applies_shadowed_delivered_claim_cleanup_once(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    workspace = create_saved_workspace(state_dir, target)
    started = run_workbench(state_dir, "start-scan", "--workspace-id", str(workspace["id"]))
    scan_id = str(started["results"]["scanId"])
    database = state_dir / "workbench.sqlite3"

    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE scans SET handoff_status = 'delivered', handoff_claimed_at = ?, "
            "handoff_claim_token = ? WHERE id = ?",
            ("2026-06-30T00:00:00Z", "stale-claim", scan_id),
        )
        connection.execute(
            "UPDATE schema_migrations SET name = ? WHERE version = 18",
            ("scan target summaries",),
        )

    run_workbench(state_dir, "database-info")

    with sqlite3.connect(database) as connection:
        assert connection.execute(
            "SELECT handoff_claimed_at, handoff_claim_token FROM scans WHERE id = ?", (scan_id,)
        ).fetchone() == (None, None)
        assert connection.execute(
            "SELECT name FROM schema_migrations WHERE version = 18"
        ).fetchone() == ("clear legacy delivered handoff claims",)
        connection.execute(
            "UPDATE scans SET handoff_claimed_at = ?, handoff_claim_token = ? WHERE id = ?",
            ("2026-07-01T00:00:00Z", "current-claim", scan_id),
        )

    run_workbench(state_dir, "database-info")

    with sqlite3.connect(database) as connection:
        assert connection.execute(
            "SELECT handoff_claimed_at, handoff_claim_token FROM scans WHERE id = ?", (scan_id,)
        ).fetchone() == ("2026-07-01T00:00:00Z", "current-claim")


@pytest.mark.parametrize(
    "legacy_name",
    ("structured scan guidance context", "idempotent scan lifecycle requests"),
)
def test_workbench_repairs_shadowed_setup_preferences_migration(
    tmp_path: Path, legacy_name: str
) -> None:
    state_dir = tmp_path / "state"
    run_workbench(state_dir, "database-info")
    database = state_dir / "workbench.sqlite3"

    with sqlite3.connect(database) as connection:
        connection.execute("DROP TABLE setup_preferences")
        connection.execute(
            "UPDATE schema_migrations SET name = ? WHERE version = 19",
            (legacy_name,),
        )

    run_workbench(state_dir, "database-info")
    with sqlite3.connect(database) as connection:
        assert [row[1] for row in connection.execute("PRAGMA table_info(setup_preferences)")] == [
            "singleton",
            "skip_setup_ui",
            "updated_at",
        ]
        assert connection.execute(
            "SELECT name FROM schema_migrations WHERE version = 19"
        ).fetchone() == ("persist setup workspace preference",)


@pytest.mark.parametrize(
    "legacy_name",
    ("retain superseded scan lifecycle requests", "threat model publication receipts"),
)
def test_workbench_repairs_shadowed_phase_progress_migration(
    tmp_path: Path, legacy_name: str
) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    workspace = create_saved_workspace(state_dir, target)
    started = run_workbench(state_dir, "start-scan", "--workspace-id", str(workspace["id"]))
    scan_id = str(started["results"]["scanId"])
    database = state_dir / "workbench.sqlite3"

    with sqlite3.connect(database) as connection:
        connection.execute("ALTER TABLE scan_progress DROP COLUMN phase_items_completed")
        connection.execute("ALTER TABLE scan_progress DROP COLUMN phase_items_total")
        connection.execute("ALTER TABLE scan_progress DROP COLUMN phase_progress_unit")
        connection.execute(
            "UPDATE schema_migrations SET name = ? WHERE version = 20",
            (legacy_name,),
        )

    first = run_workbench(state_dir, "get-workspace", "--workspace-id", str(workspace["id"]))
    second = run_workbench(state_dir, "get-workspace", "--workspace-id", str(workspace["id"]))

    assert first == second
    with sqlite3.connect(database) as connection:
        assert connection.execute(
            "SELECT phase_items_total, phase_items_completed, phase_progress_unit "
            "FROM scan_progress WHERE scan_id = ?",
            (scan_id,),
        ).fetchone() == (0, 0, None)
        assert connection.execute(
            "SELECT name FROM schema_migrations WHERE version = 20"
        ).fetchone() == ("phase-specific scan progress",)


@pytest.mark.parametrize(
    "legacy_name",
    ("scan progress projection and activity", "deep coordinator manifest receipts"),
)
def test_workbench_repairs_shadowed_preflight_progress_migration(
    tmp_path: Path, legacy_name: str
) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    saved = create_saved_workspace(state_dir, target)
    started = run_workbench(state_dir, "start-scan", "--workspace-id", str(saved["id"]))
    scan_id = str(started["results"]["scanId"])
    database = state_dir / "workbench.sqlite3"
    with sqlite3.connect(database) as connection:
        connection.execute(
            """
            UPDATE scan_progress
            SET phase_items_total = 1, phase_items_completed = 1,
                phase_progress_unit = 'checks'
            WHERE scan_id = ?
            """,
            (scan_id,),
        )
        connection.execute(
            "UPDATE schema_migrations SET name = ? WHERE version = 21", (legacy_name,)
        )
        connection.execute("ALTER TABLE scan_progress DROP COLUMN preflight_checks_completed")
        connection.execute("ALTER TABLE scan_progress DROP COLUMN preflight_checks_total")
        connection.execute("ALTER TABLE scan_progress DROP COLUMN preflight_issues_json")

    run_workbench(state_dir, "database-info")

    with sqlite3.connect(database) as connection:
        assert connection.execute(
            """
            SELECT preflight_checks_completed, preflight_checks_total, preflight_issues_json
            FROM scan_progress
            WHERE scan_id = ?
            """,
            (scan_id,),
        ).fetchone() == (0, 0, "[]")
        assert connection.execute(
            "SELECT name FROM schema_migrations WHERE version = 21"
        ).fetchone() == ("current scan preflight state",)


def test_workbench_repairs_shadowed_scan_recipe_migration(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    workspace = create_saved_workspace(state_dir, target)
    started = run_workbench(state_dir, "start-scan", "--workspace-id", str(workspace["id"]))
    scan_id = str(started["results"]["scanId"])
    database = state_dir / "workbench.sqlite3"

    with sqlite3.connect(database) as connection:
        connection.execute("ALTER TABLE scans DROP COLUMN parent_scan_id")
        connection.execute("ALTER TABLE scans DROP COLUMN recipe_json")
        connection.execute(
            "UPDATE schema_migrations SET name = ? WHERE version = 22",
            ("dynamic scan execution profiles",),
        )

    first = run_workbench(state_dir, "get-workspace", "--workspace-id", str(workspace["id"]))
    second = run_workbench(state_dir, "get-workspace", "--workspace-id", str(workspace["id"]))

    assert first == second
    with sqlite3.connect(database) as connection:
        assert connection.execute(
            "SELECT recipe_json, parent_scan_id FROM scans WHERE id = ?",
            (scan_id,),
        ).fetchone() == (None, None)
        assert connection.execute(
            "SELECT name FROM schema_migrations WHERE version = 22"
        ).fetchone() == ("replayable scan launch recipes",)
        assert any(
            row[3] == "parent_scan_id" and row[2] == "scans" and row[6] == "SET NULL"
            for row in connection.execute("PRAGMA foreign_key_list(scans)")
        )
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []


def test_workbench_reconciles_released_completion_warning_version(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    workspace = create_saved_workspace(state_dir, target)
    started = run_workbench(state_dir, "start-scan", "--workspace-id", str(workspace["id"]))
    scan_id = str(started["results"]["scanId"])
    database = state_dir / "workbench.sqlite3"

    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE scans SET completion_warnings_json = ? WHERE id = ?",
            ('["existing warning"]', scan_id),
        )
        connection.execute("DELETE FROM schema_migrations WHERE version = 26")
        connection.execute("ALTER TABLE scans DROP COLUMN reasoning_effort")
        connection.execute("ALTER TABLE scans DROP COLUMN model")
        connection.execute(
            "UPDATE schema_migrations SET name = ? WHERE version = 25",
            ("persist scan completion warnings",),
        )

    first = run_workbench(state_dir, "get-workspace", "--workspace-id", str(workspace["id"]))
    second = run_workbench(state_dir, "get-workspace", "--workspace-id", str(workspace["id"]))

    assert first == second
    with sqlite3.connect(database) as connection:
        assert connection.execute(
            "SELECT model, reasoning_effort, completion_warnings_json FROM scans WHERE id = ?",
            (scan_id,),
        ).fetchone() == (None, None, '["existing warning"]')
        assert connection.execute(
            "SELECT version, name FROM schema_migrations WHERE version IN (25, 26) ORDER BY version"
        ).fetchall() == [
            (25, "persist scan model settings"),
            (26, "persist scan completion warnings"),
        ]


def test_workbench_repairs_recorded_completion_warnings_migration(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    workspace = create_saved_workspace(state_dir, target)
    started = run_workbench(state_dir, "start-scan", "--workspace-id", str(workspace["id"]))
    scan_id = str(started["results"]["scanId"])
    database = state_dir / "workbench.sqlite3"

    with sqlite3.connect(database) as connection:
        connection.execute("ALTER TABLE scans DROP COLUMN completion_warnings_json")
        connection.execute("ALTER TABLE scans ADD COLUMN attention_message TEXT")
        connection.execute(
            "UPDATE schema_migrations SET name = ? WHERE version = 26",
            ("recoverable scan attention",),
        )

    first = run_workbench(state_dir, "get-workspace", "--workspace-id", str(workspace["id"]))
    second = run_workbench(state_dir, "get-workspace", "--workspace-id", str(workspace["id"]))

    assert first == second
    with sqlite3.connect(database) as connection:
        assert connection.execute(
            "SELECT completion_warnings_json, attention_message FROM scans WHERE id = ?",
            (scan_id,),
        ).fetchone() == ("[]", None)
        assert connection.execute(
            "SELECT name FROM schema_migrations WHERE version = 26"
        ).fetchone() == ("recoverable scan attention",)
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []


@pytest.mark.parametrize(
    ("legacy_version", "legacy_name", "dynamic", "preexisting_model"),
    (
        (11, "scan execution profiles", False, False),
        (12, "scan execution profiles", False, False),
        (12, "dynamic scan execution profiles", True, False),
        (13, "dynamic scan execution profiles", True, True),
        (22, "dynamic scan execution profiles", True, False),
        (25, "dynamic scan execution profiles", True, False),
    ),
    ids=("v11-static", "v12-static", "v12-dynamic", "v13", "v22", "v25"),
)
def test_workbench_reconciles_legacy_execution_profile_migrations(
    tmp_path: Path,
    legacy_version: int,
    legacy_name: str,
    dynamic: bool,
    preexisting_model: bool,
) -> None:
    state_dir = tmp_path / "state"
    database = state_dir / "workbench.sqlite3"
    database.parent.mkdir(parents=True)
    target = tmp_path / "target"
    target.mkdir()
    workspace_id = str(uuid.uuid4())
    scan_id = str(uuid.uuid4())
    timestamp = "2026-07-01T00:00:00Z"
    namespace = runpy.run_path(str(SCRIPT), run_name="codex_security_workbench_schema")
    migrations = namespace["MIGRATIONS"]
    if dynamic:
        legacy_model = "codex-next/security-pro"
        legacy_effort = "adaptive_depth"
        model_definition = """
            TEXT CHECK (
                execution_model IS NULL
                OR (
                    execution_model = trim(execution_model)
                    AND length(execution_model) BETWEEN 1 AND 128
                )
            )
        """
        effort_definition = """
            TEXT CHECK (
                (reasoning_effort IS NULL
                 OR (
                    reasoning_effort = trim(reasoning_effort)
                    AND length(reasoning_effort) BETWEEN 1 AND 64
                 ))
                AND ((execution_model IS NULL) = (reasoning_effort IS NULL))
            )
        """
    else:
        legacy_model = "gpt-5.5"
        legacy_effort = "high"
        model_definition = """
            TEXT CHECK (
                execution_model IS NULL
                OR execution_model IN ('gpt-5.4-mini', 'gpt-5.4', 'gpt-5.5')
            )
        """
        effort_definition = """
            TEXT CHECK (
                (reasoning_effort IS NULL
                 OR reasoning_effort IN ('low', 'medium', 'high', 'xhigh'))
                AND ((execution_model IS NULL) = (reasoning_effort IS NULL))
            )
        """

    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute(
            """
            CREATE TABLE schema_migrations (
                version INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                applied_at TEXT NOT NULL
            )
            """
        )
        current_migrations = (*migrations[: legacy_version - 1], *migrations[legacy_version:24])
        for version, name, sql in current_migrations:
            for statement in namespace["sql_statements"](sql):
                connection.execute(statement)
            connection.execute(
                "INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)",
                (version, name, timestamp),
            )
        for table in ("workspaces", "scans"):
            connection.execute(f"ALTER TABLE {table} ADD COLUMN execution_model {model_definition}")
            connection.execute(
                f"ALTER TABLE {table} ADD COLUMN reasoning_effort {effort_definition}"
            )
        connection.execute(
            "INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)",
            (legacy_version, legacy_name, timestamp),
        )
        if preexisting_model:
            connection.execute("ALTER TABLE scans ADD COLUMN model TEXT")
        connection.execute(
            """
            INSERT INTO workspaces (
                id, target_path, default_mode, execution_model, reasoning_effort,
                created_at, updated_at
            ) VALUES (?, ?, 'standard', ?, ?, ?, ?)
            """,
            (
                workspace_id,
                str(target),
                legacy_model,
                legacy_effort,
                timestamp,
                timestamp,
            ),
        )
        connection.execute(
            """
            INSERT INTO scans (
                id, workspace_id, target_path, target_revision, scope, mode, scan_dir,
                status, phase, started_at, created_at, updated_at,
                execution_model, reasoning_effort
            ) VALUES (?, ?, ?, 'legacy-revision', '.', 'standard', ?, 'running',
                'discovery', ?, ?, ?, ?, ?)
            """,
            (
                scan_id,
                workspace_id,
                str(target),
                str(tmp_path / "legacy-scan"),
                timestamp,
                timestamp,
                timestamp,
                legacy_model,
                legacy_effort,
            ),
        )
        if preexisting_model:
            connection.execute("UPDATE scans SET model = 'current-model' WHERE id = ?", (scan_id,))

    run_workbench(state_dir, "database-info")
    run_workbench(state_dir, "database-info")

    expected_migration_name = {
        11: "deep scan orchestration state",
        12: "scan continuation threads",
        22: "replayable scan launch recipes",
        25: "persist scan model settings",
    }.get(legacy_version, legacy_name)
    with sqlite3.connect(database) as connection:
        assert connection.execute(
            "SELECT name FROM schema_migrations WHERE version = ?", (legacy_version,)
        ).fetchone() == (expected_migration_name,)
        assert connection.execute(
            """
            SELECT legacy_execution_model, legacy_reasoning_effort, model, reasoning_effort
            FROM scans WHERE id = ?
            """,
            (scan_id,),
        ).fetchone() == (
            legacy_model,
            legacy_effort,
            "current-model" if preexisting_model else legacy_model,
            legacy_effort,
        )
        assert connection.execute(
            "SELECT legacy_execution_model, legacy_reasoning_effort FROM workspaces WHERE id = ?",
            (workspace_id,),
        ).fetchone() == (legacy_model, legacy_effort)
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []

    current_workspace = create_saved_workspace(state_dir, target)
    current_scan = run_workbench(
        state_dir,
        "start-scan",
        "--workspace-id",
        str(current_workspace["id"]),
        "--scan-root",
        str(tmp_path / "current-scans"),
        "--model",
        "gpt-5.6-sol",
    )
    current_scan_id = str(current_scan["results"]["scanId"])
    run_workbench(
        state_dir,
        "update-progress",
        "--scan-id",
        current_scan_id,
        "--reasoning-effort",
        "high",
    )
    with sqlite3.connect(database) as connection:
        assert connection.execute(
            """
            SELECT legacy_execution_model, legacy_reasoning_effort, model, reasoning_effort
            FROM scans WHERE id = ?
            """,
            (current_scan_id,),
        ).fetchone() == (None, None, "gpt-5.6-sol", "high")


def test_workbench_upgrades_released_database_schema(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    database = state_dir / "workbench.sqlite3"
    database.parent.mkdir(parents=True)
    namespace = runpy.run_path(str(SCRIPT), run_name="codex_security_workbench_schema")
    migrations = namespace["MIGRATIONS"]
    assert [(version, name) for version, name, _ in migrations[:2]] == [
        (1, "initial workbench schema"),
        (2, "persist capability preflight summaries"),
    ]
    with sqlite3.connect(database) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute(
            """
            CREATE TABLE schema_migrations (
                version INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                applied_at TEXT NOT NULL
            )
            """
        )
        for version, name, sql in migrations[:2]:
            for statement in namespace["sql_statements"](sql):
                connection.execute(statement)
            connection.execute(
                "INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)",
                (version, name, "2026-06-01T00:00:00Z"),
            )

    run_workbench(state_dir, "database-info")

    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT version, name FROM schema_migrations").fetchall() == [
            (1, "initial workbench schema"),
            (2, "persist capability preflight summaries"),
            (3, "finding management schema"),
            (4, "scan handoff delivery claims"),
            (5, "finding remediation action claims"),
            (6, "thread-scoped workspaces"),
            (7, "remediation host delivery state"),
            (8, "sealed manifest digests"),
            (9, "scan target filesystem identity"),
            (10, "scan cancellation state"),
            (11, "deep scan orchestration state"),
            (12, "scan continuation threads"),
            (13, "scan scope file counts"),
            (14, "imported triage results"),
            (15, "append-only finding decisions"),
            (16, "stable repository targets"),
            (17, "scan target summaries"),
            (18, "clear legacy delivered handoff claims"),
            (19, "persist setup workspace preference"),
            (20, "phase-specific scan progress"),
            (21, "current scan preflight state"),
            (22, "replayable scan launch recipes"),
            (23, "semantic scan comparison matches"),
            (24, "persist scan cost estimates"),
            (25, "persist scan model settings"),
            (26, "persist scan completion warnings"),
            (27, "persist deep scan consecutive discovery failures"),
            (28, "persist deep scan discovery time limit"),
            (29, "persist finding publication associations"),
            (30, "preserve team-only finding publication associations"),
            (31, "freeze stopped scan source digests"),
            (32, "separate deep scan publication failures"),
        ]
        assert "capability_preflight_json" in {
            row[1] for row in connection.execute("PRAGMA table_info(workspaces)")
        }
        assert "seal_manifest_digest" in {
            row[1] for row in connection.execute("PRAGMA table_info(scans)")
        }
        assert "canceled_at" in {row[1] for row in connection.execute("PRAGMA table_info(scans)")}
        assert "continuation_thread_id" in {
            row[1] for row in connection.execute("PRAGMA table_info(scans)")
        }


def test_workbench_upgrades_pre_release_phase_progress_migration(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    database = state_dir / "workbench.sqlite3"
    database.parent.mkdir(parents=True)
    namespace = runpy.run_path(str(SCRIPT), run_name="codex_security_workbench_schema")
    migrations = namespace["MIGRATIONS"]
    phase_migration = next(
        migration for migration in migrations if migration[1] == "phase-specific scan progress"
    )

    with sqlite3.connect(database) as connection:
        connection.execute(
            """
            CREATE TABLE schema_migrations (
                version INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                applied_at TEXT NOT NULL
            )
            """
        )
        for version, name, sql in migrations[:11]:
            for statement in namespace["sql_statements"](sql):
                connection.execute(statement)
            connection.execute(
                "INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)",
                (version, name, "2026-07-01T00:00:00Z"),
            )
        for statement in namespace["sql_statements"](phase_migration[2]):
            connection.execute(statement)
        connection.execute(
            "INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)",
            (12, phase_migration[1], "2026-07-01T00:00:00Z"),
        )

    run_workbench(state_dir, "database-info")

    with sqlite3.connect(database) as connection:
        assert connection.execute(
            "SELECT version, name FROM schema_migrations WHERE version >= 12 ORDER BY version"
        ).fetchall() == [
            (12, "scan continuation threads"),
            (13, "scan scope file counts"),
            (14, "imported triage results"),
            (15, "append-only finding decisions"),
            (16, "stable repository targets"),
            (17, "scan target summaries"),
            (18, "clear legacy delivered handoff claims"),
            (19, "persist setup workspace preference"),
            (20, "phase-specific scan progress"),
            (21, "current scan preflight state"),
            (22, "replayable scan launch recipes"),
            (23, "semantic scan comparison matches"),
            (24, "persist scan cost estimates"),
            (25, "persist scan model settings"),
            (26, "persist scan completion warnings"),
            (27, "persist deep scan consecutive discovery failures"),
            (28, "persist deep scan discovery time limit"),
            (29, "persist finding publication associations"),
            (30, "preserve team-only finding publication associations"),
            (31, "freeze stopped scan source digests"),
            (32, "separate deep scan publication failures"),
        ]
        assert "continuation_thread_id" in {
            row[1] for row in connection.execute("PRAGMA table_info(scans)")
        }
        assert {row[1] for row in connection.execute("PRAGMA table_info(scan_progress)")} >= {
            "scope_file_count",
            "phase_items_completed",
            "phase_items_total",
            "phase_progress_unit",
        }


def test_workbench_upgrades_pre_release_preflight_progress_migration(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    database = state_dir / "workbench.sqlite3"
    database.parent.mkdir(parents=True)
    namespace = runpy.run_path(str(SCRIPT), run_name="codex_security_workbench_schema")
    migrations = namespace["MIGRATIONS"]
    phase_migration = next(
        migration for migration in migrations if migration[1] == "phase-specific scan progress"
    )
    preflight_migration = next(
        migration for migration in migrations if migration[1] == "current scan preflight state"
    )

    with sqlite3.connect(database) as connection:
        connection.execute(
            """
            CREATE TABLE schema_migrations (
                version INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                applied_at TEXT NOT NULL
            )
            """
        )
        for version, name, sql in migrations[:11]:
            for statement in namespace["sql_statements"](sql):
                connection.execute(statement)
            connection.execute(
                "INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)",
                (version, name, "2026-07-01T00:00:00Z"),
            )
        for statement in namespace["sql_statements"](phase_migration[2]):
            connection.execute(statement)
        connection.execute(
            "INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)",
            (12, phase_migration[1], "2026-07-01T00:00:00Z"),
        )
        for statement in namespace["sql_statements"](preflight_migration[2]):
            connection.execute(statement)
        connection.execute(
            "INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)",
            (13, preflight_migration[1], "2026-07-01T00:00:00Z"),
        )

    run_workbench(state_dir, "database-info")

    with sqlite3.connect(database) as connection:
        assert connection.execute(
            "SELECT version, name FROM schema_migrations WHERE version >= 12 ORDER BY version"
        ).fetchall() == [
            (12, "scan continuation threads"),
            (13, "scan scope file counts"),
            (14, "imported triage results"),
            (15, "append-only finding decisions"),
            (16, "stable repository targets"),
            (17, "scan target summaries"),
            (18, "clear legacy delivered handoff claims"),
            (19, "persist setup workspace preference"),
            (20, "phase-specific scan progress"),
            (21, "current scan preflight state"),
            (22, "replayable scan launch recipes"),
            (23, "semantic scan comparison matches"),
            (24, "persist scan cost estimates"),
            (25, "persist scan model settings"),
            (26, "persist scan completion warnings"),
            (27, "persist deep scan consecutive discovery failures"),
            (28, "persist deep scan discovery time limit"),
            (29, "persist finding publication associations"),
            (30, "preserve team-only finding publication associations"),
            (31, "freeze stopped scan source digests"),
            (32, "separate deep scan publication failures"),
        ]
        assert "continuation_thread_id" in {
            row[1] for row in connection.execute("PRAGMA table_info(scans)")
        }
        assert {row[1] for row in connection.execute("PRAGMA table_info(scan_progress)")} >= {
            "scope_file_count",
            "phase_items_completed",
            "phase_items_total",
            "phase_progress_unit",
            "preflight_checks_completed",
            "preflight_checks_total",
            "preflight_issues_json",
        }


def test_workbench_normalizes_pre_release_migration_numbers(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    run_workbench(state_dir, "database-info")
    database = state_dir / "workbench.sqlite3"
    with sqlite3.connect(database) as connection:
        connection.execute("DELETE FROM schema_migrations WHERE version = 2")
        connection.execute(
            "UPDATE schema_migrations SET version = -version WHERE version BETWEEN 3 AND 5"
        )
        connection.execute("UPDATE schema_migrations SET version = 2 WHERE version = -3")
        connection.execute("UPDATE schema_migrations SET version = 3 WHERE version = -4")
        connection.execute("UPDATE schema_migrations SET version = 4 WHERE version = -5")
        connection.execute(
            "INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)",
            (5, "scan target snapshot digests", "2026-06-01T00:00:00Z"),
        )
        connection.execute("ALTER TABLE workspaces DROP COLUMN capability_preflight_json")

    run_workbench(state_dir, "database-info")

    with sqlite3.connect(database) as connection:
        assert connection.execute(
            "SELECT version, name FROM schema_migrations WHERE version BETWEEN 2 AND 5"
        ).fetchall() == [
            (2, "persist capability preflight summaries"),
            (3, "finding management schema"),
            (4, "scan handoff delivery claims"),
            (5, "finding remediation action claims"),
        ]
        assert "capability_preflight_json" in {
            row[1] for row in connection.execute("PRAGMA table_info(workspaces)")
        }


def test_workbench_preserves_diff_target_summary_on_scan(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    revision = initialize_git_repository(target)
    workspace_id = str(uuid.uuid4())
    run_workbench(state_dir, "create-workspace", "--workspace-id", workspace_id)
    run_workbench(
        state_dir,
        "save-workspace",
        "--workspace-id",
        workspace_id,
        "--target-path",
        str(target),
        "--scope",
        ".",
        "--mode",
        "diff",
        "--target-summary",
        "Authentication callback changes",
        "--diff-target-kind",
        "commit",
        "--diff-head-revision",
        revision,
    )

    started = run_workbench(
        state_dir,
        "start-scan",
        "--workspace-id",
        workspace_id,
        "--scan-root",
        str(tmp_path / "scans"),
    )
    scan_id = started["results"]["scanId"]

    assert started["results"]["targetSummary"] == "Authentication callback changes"
    assert (
        run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]["targetSummary"]
        == "Authentication callback changes"
    )


def test_workbench_upgrades_public_cli_completion_warning_migration() -> None:
    namespace = runpy.run_path(str(SCRIPT), run_name="codex_security_workbench_db")
    apply_migrations = namespace["apply_migrations"]
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    public_migrations = (
        *(migration for migration in namespace["MIGRATIONS"] if migration[0] < 25),
        (
            25,
            "persist scan completion warnings",
            ("ALTER TABLE scans ADD COLUMN completion_warnings_json TEXT NOT NULL DEFAULT '[]';"),
        ),
    )
    with mock.patch.dict(apply_migrations.__globals__, {"MIGRATIONS": public_migrations}):
        apply_migrations(connection)

    timestamp = "2026-07-01T00:00:00Z"
    connection.execute(
        "INSERT INTO workspaces (id, created_at, updated_at) VALUES (?, ?, ?)",
        ("legacy-workspace", timestamp, timestamp),
    )
    connection.execute(
        """
        INSERT INTO scans (
            id, workspace_id, target_path, target_revision, scope, mode, scan_dir,
            status, phase, started_at, created_at, updated_at, completion_warnings_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "legacy-scan",
            "legacy-workspace",
            "/legacy/target",
            "legacy-revision",
            ".",
            "standard",
            "/legacy/scan",
            "complete",
            "reporting",
            timestamp,
            timestamp,
            timestamp,
            '["existing warning"]',
        ),
    )
    connection.commit()

    apply_migrations(connection)
    apply_migrations(connection)

    assert [
        tuple(row)
        for row in connection.execute(
            "SELECT version, name FROM schema_migrations WHERE version IN (25, 26)"
        )
    ] == [
        (25, "persist scan model settings"),
        (26, "persist scan completion warnings"),
    ]
    scan = connection.execute(
        "SELECT model, reasoning_effort, completion_warnings_json FROM scans WHERE id = ?",
        ("legacy-scan",),
    ).fetchone()
    assert scan["model"] is None
    assert scan["reasoning_effort"] is None
    assert scan["completion_warnings_json"] == '["existing warning"]'


@pytest.mark.parametrize(
    ("has_dynamic_profile_migration", "migration_history"),
    (
        (False, "plugin"),
        (True, "plugin"),
        (False, "released-continuation"),
        (False, "phase-progress"),
        (True, "mixed-public"),
        (True, "canonical-metadata"),
    ),
    ids=(
        "v11",
        "v11-v12",
        "v11-released-v12",
        "v11-phase-progress-v12",
        "mixed-public",
        "canonical-metadata",
    ),
)
def test_workbench_upgrades_legacy_execution_profile_migrations(
    tmp_path: Path, has_dynamic_profile_migration: bool, migration_history: str
) -> None:
    state_dir = tmp_path / "state"
    database = state_dir / "workbench.sqlite3"
    database.parent.mkdir(parents=True)
    target = tmp_path / "target"
    target.mkdir()
    namespace = runpy.run_path(str(SCRIPT), run_name="codex_security_workbench_schema")
    migrations = namespace["MIGRATIONS"]
    timestamp = "2026-07-01T00:00:00Z"
    workspace_id = str(uuid.uuid4())
    scan_id = str(uuid.uuid4())
    if has_dynamic_profile_migration:
        model = "codex-next/security-pro"
        reasoning_effort = "adaptive_depth"
        model_definition = """
            TEXT CHECK (
                execution_model IS NULL
                OR (
                    execution_model = trim(execution_model)
                    AND length(execution_model) BETWEEN 1 AND 128
                )
            )
        """
        reasoning_effort_definition = """
            TEXT CHECK (
                (reasoning_effort IS NULL
                 OR (
                    reasoning_effort = trim(reasoning_effort)
                    AND length(reasoning_effort) BETWEEN 1 AND 64
                 ))
                AND ((execution_model IS NULL) = (reasoning_effort IS NULL))
            )
        """
    else:
        model = "gpt-5.5"
        reasoning_effort = "high"
        model_definition = """
            TEXT CHECK (
                execution_model IS NULL
                OR execution_model IN ('gpt-5.4-mini', 'gpt-5.4', 'gpt-5.5')
            )
        """
        reasoning_effort_definition = """
            TEXT CHECK (
                (reasoning_effort IS NULL
                 OR reasoning_effort IN ('low', 'medium', 'high', 'xhigh'))
                AND ((execution_model IS NULL) = (reasoning_effort IS NULL))
            )
        """

    with sqlite3.connect(database) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute(
            """
            CREATE TABLE schema_migrations (
                version INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                applied_at TEXT NOT NULL
            )
            """
        )
        for version, name, sql in migrations[:10]:
            for statement in namespace["sql_statements"](sql):
                connection.execute(statement)
            connection.execute(
                "INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)",
                (version, name, timestamp),
            )
        for table in ("workspaces", "scans"):
            connection.execute(
                f"""
                ALTER TABLE {table}
                ADD COLUMN execution_model {model_definition}
                """
            )
            connection.execute(
                f"""
                ALTER TABLE {table}
                ADD COLUMN reasoning_effort {reasoning_effort_definition}
                """
            )
        if migration_history == "canonical-metadata":
            for version, name, sql in migrations[10:24]:
                for statement in namespace["sql_statements"](sql):
                    connection.execute(statement)
                connection.execute(
                    "INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)",
                    (version, name, timestamp),
                )
            connection.execute("ALTER TABLE scans ADD COLUMN model TEXT")
            connection.execute(
                "INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)",
                (25, "persist scan model settings", timestamp),
            )
        else:
            legacy_migrations = [(11, "scan execution profiles", timestamp)]
            if has_dynamic_profile_migration:
                legacy_migrations.append((12, "dynamic scan execution profiles", timestamp))
            elif migration_history in ("released-continuation", "phase-progress"):
                migration_name = (
                    "scan continuation threads"
                    if migration_history == "released-continuation"
                    else "phase-specific scan progress"
                )
                version, name, sql = next(
                    migration for migration in migrations if migration[1] == migration_name
                )
                assert version in (12, 20)
                for statement in namespace["sql_statements"](sql):
                    connection.execute(statement)
                legacy_migrations.append((12, migration_name, timestamp))
            connection.executemany(
                "INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)",
                legacy_migrations,
            )

        has_completion_warning = migration_history in ("mixed-public", "canonical-metadata")
        if has_completion_warning:
            connection.execute(
                "ALTER TABLE scans ADD COLUMN completion_warnings_json TEXT NOT NULL DEFAULT '[]'"
            )
            connection.execute(
                "INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)",
                (
                    26 if migration_history == "canonical-metadata" else 25,
                    "persist scan completion warnings",
                    timestamp,
                ),
            )
        connection.execute(
            """
            INSERT INTO workspaces (
                id, target_path, default_mode, execution_model, reasoning_effort,
                created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                workspace_id,
                str(target),
                "standard",
                model,
                reasoning_effort,
                timestamp,
                timestamp,
            ),
        )
        connection.execute(
            """
            INSERT INTO scans (
                id, workspace_id, target_path, target_revision, scope, mode, scan_dir,
                status, phase, started_at, created_at, updated_at,
                execution_model, reasoning_effort
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan_id,
                workspace_id,
                str(target),
                "legacy-revision",
                ".",
                "standard",
                str(tmp_path / "legacy-scan"),
                "running",
                "discovery",
                timestamp,
                timestamp,
                timestamp,
                model,
                reasoning_effort,
            ),
        )
        if has_completion_warning:
            connection.execute(
                "UPDATE scans SET completion_warnings_json = ? WHERE id = ?",
                ('["existing warning"]', scan_id),
            )
        if migration_history == "canonical-metadata":
            connection.execute("UPDATE scans SET model = ? WHERE id = ?", ("gpt-current", scan_id))

    run_workbench(state_dir, "database-info")
    run_workbench(state_dir, "database-info")

    with sqlite3.connect(database) as connection:
        assert connection.execute(
            "SELECT version, name FROM schema_migrations WHERE version IN (11, 12, 25, 26)"
        ).fetchall() == [
            (11, "deep scan orchestration state"),
            (12, "scan continuation threads"),
            (25, "persist scan model settings"),
            (26, "persist scan completion warnings"),
        ]
        assert connection.execute(
            """
            SELECT status, legacy_execution_model, legacy_reasoning_effort,
                model, reasoning_effort, completion_warnings_json
            FROM scans
            WHERE id = ?
            """,
            (scan_id,),
        ).fetchone() == (
            "running",
            model,
            reasoning_effort,
            "gpt-current" if migration_history == "canonical-metadata" else model,
            reasoning_effort,
            '["existing warning"]' if has_completion_warning else "[]",
        )
        assert connection.execute(
            """
            SELECT legacy_execution_model, legacy_reasoning_effort
            FROM workspaces
            WHERE id = ?
            """,
            (workspace_id,),
        ).fetchone() == (model, reasoning_effort)
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []

    current_workspace = create_saved_workspace(state_dir, target)
    current_scan = run_workbench(
        state_dir,
        "start-scan",
        "--workspace-id",
        str(current_workspace["id"]),
        "--scan-root",
        str(tmp_path / "current-scans"),
        "--model",
        "gpt-5.6-sol",
    )
    current_scan_id = str(current_scan["results"]["scanId"])
    assert current_scan["results"]["reasoningEffort"] is None
    run_workbench(
        state_dir,
        "update-progress",
        "--scan-id",
        current_scan_id,
        "--reasoning-effort",
        "high",
    )
    with sqlite3.connect(database) as connection:
        assert connection.execute(
            """
            SELECT legacy_execution_model, legacy_reasoning_effort, model,
                reasoning_effort
            FROM scans
            WHERE id = ?
            """,
            (current_scan_id,),
        ).fetchone() == (None, None, "gpt-5.6-sol", "high")


def test_workbench_rejects_unknown_execution_profile_migration_without_mutating_history() -> None:
    namespace = runpy.run_path(str(SCRIPT), run_name="codex_security_workbench_db")
    apply_migrations = namespace["apply_migrations"]
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    connection.execute(
        """
        CREATE TABLE schema_migrations (
            version INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            applied_at TEXT NOT NULL
        )
        """
    )
    timestamp = "2026-07-01T00:00:00Z"
    for version, name, sql in namespace["MIGRATIONS"][:10]:
        for statement in namespace["sql_statements"](sql):
            connection.execute(statement)
        connection.execute(
            "INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)",
            (version, name, timestamp),
        )
    for table in ("workspaces", "scans"):
        connection.execute(f"ALTER TABLE {table} ADD COLUMN execution_model TEXT")
        connection.execute(f"ALTER TABLE {table} ADD COLUMN reasoning_effort TEXT")
    continuation = next(migration for migration in namespace["MIGRATIONS"] if migration[0] == 12)
    for statement in namespace["sql_statements"](continuation[2]):
        connection.execute(statement)
    connection.executemany(
        "INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)",
        (
            (11, "unknown execution profile migration", timestamp),
            (12, continuation[1], timestamp),
        ),
    )
    connection.commit()

    with pytest.raises(SystemExit, match="unsupported execution-profile migration history"):
        apply_migrations(connection)

    assert [
        tuple(row)
        for row in connection.execute(
            "SELECT version, name FROM schema_migrations WHERE version IN (11, 12)"
        )
    ] == [
        (11, "unknown execution profile migration"),
        (12, "scan continuation threads"),
    ]
    assert (
        connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'deep_scan_runs'"
        ).fetchone()
        is None
    )
    scan_columns = {row["name"] for row in connection.execute("PRAGMA table_info(scans)")}
    assert {"execution_model", "reasoning_effort"}.issubset(scan_columns)
    assert "legacy_execution_model" not in scan_columns
