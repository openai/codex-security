"""Exercise upgrades from Deep Scan preview schema histories."""

import runpy
import sqlite3

import pytest
from test_workbench_setup_and_migrations import (
    EXPECTED_MIGRATIONS,
    SCHEMA,
    apply_historical_migrations,
    create_migration_history,
)
from workbench_test_support import SCRIPT


@pytest.mark.parametrize(
    "snapshot",
    [
        "early",
        "previous",
        "current",
        "before-refresh",
        "f57",
        "f58",
        "previous-head",
        "before-worker-usage",
        "before-log-boundaries",
        "before-repository-migrations",
    ],
)
def test_original_deep_scan_history_upgrades_without_skipping_local_embeddings(
    snapshot: str,
) -> None:
    apply_migrations = runpy.run_path(str(SCRIPT), run_name="codex_security_workbench_db")[
        "apply_migrations"
    ]
    original_versions = {
        "preserve original deep scan discovery context": 44,
        "retain deep scan attempts and exact merge inputs": 45,
        "persist selected deep scan finalization input": 46,
        "freeze stopped scan checkpoint selections": 47,
        "bind original deep scan parent usage turn": 48,
        "bind original deep scan execution settings": 51,
    }
    if snapshot in {"before-worker-usage", "before-log-boundaries", "before-repository-migrations"}:
        first_preview_version = 67 if snapshot == "before-repository-migrations" else 64
        original_versions = {
            name: first_preview_version + index
            for index, (_, name, _) in enumerate(SCHEMA.MIGRATIONS[72:77])
        }
        if snapshot == "before-worker-usage":
            original_versions["preserve original deep scan discovery context"] = 63
    elif snapshot != "early":
        original_versions = {
            name: version
            - {
                "previous": 7,
                "current": 6,
                "before-refresh": 4,
                "f57": 2,
                "f58": 1,
                "previous-head": 0,
            }[snapshot]
            for version, name in enumerate(original_versions, 54)
        }
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    create_migration_history(connection)
    timestamp = "2026-01-01T00:00:00Z"
    historical = [
        (original_versions.get(name, version), name, sql)
        for version, name, sql in SCHEMA.MIGRATIONS
        if version
        <= (
            {
                "before-worker-usage": 62,
                "before-log-boundaries": 63,
                "before-repository-migrations": 66,
                "early": 43,
                "previous": 46,
                "current": 47,
                "before-refresh": 49,
                "f57": 51,
                "f58": 52,
                "previous-head": 53,
            }[snapshot]
        )
        or name in original_versions
    ]
    apply_historical_migrations(connection, historical, timestamp)
    connection.execute(
        "INSERT INTO workspaces (id, created_at, updated_at) VALUES ('workspace', ?, ?)",
        (timestamp, timestamp),
    )
    connection.execute(
        """INSERT INTO scans (id, workspace_id, target_path, target_revision, scope,
            mode, scan_dir, status, phase, started_at, created_at, updated_at)
        VALUES ('scan', 'workspace', '/synthetic/repository', 'revision', '.',
            'deep', '/synthetic/scan', 'running', 'discovery', ?, ?, ?)""",
        (timestamp, timestamp, timestamp),
    )
    connection.execute(
        """INSERT INTO deep_scan_runs (scan_id, schema_version, workflow_version,
            status, phase, workers, subagents, stop_after_no_new, max_discovery_runs,
            discovery_user_context, finalization_input_json, usage_owner_json,
            execution_settings_json, created_at, updated_at)
        VALUES ('scan', 1, 'deep-scan-mcp/v1', 'running', 'discovery', 2, 0, 2, 10,
            'original context', '{"result":"original"}', '{"turn":"original"}',
            '{"model":"synthetic"}', ?, ?)""",
        (timestamp, timestamp),
    )
    connection.commit()
    original = dict(connection.execute("SELECT * FROM deep_scan_runs").fetchone())

    apply_migrations(connection)

    upgraded = dict(connection.execute("SELECT * FROM deep_scan_runs").fetchone())
    assert {key: upgraded[key] for key in original} == original
    assert upgraded["discovery_user_context_json"] is None
    assert connection.execute("SELECT * FROM local_finding_embeddings").fetchall() == []
    assert "cache_key" in {
        row["name"] for row in connection.execute("PRAGMA table_info(finding_embeddings)")
    }
    assert (
        connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'trigger' "
            "AND name = 'invalidate_local_finding_embedding'"
        ).fetchone()
        is not None
    )
    recorded = [
        tuple(row)
        for row in connection.execute(
            "SELECT version, name, applied_at FROM schema_migrations ORDER BY version"
        )
    ]
    assert [(version, name) for version, name, _ in recorded] == EXPECTED_MIGRATIONS
    assert all(
        applied_at == timestamp for _, name, applied_at in recorded if name in original_versions
    )
    apply_migrations(connection)
    assert [
        tuple(row)
        for row in connection.execute(
            "SELECT version, name, applied_at FROM schema_migrations ORDER BY version"
        )
    ] == recorded
    connection.close()
