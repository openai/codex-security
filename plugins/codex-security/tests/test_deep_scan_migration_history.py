"""Check released Deep Scan histories retain their saved work during upgrades."""

from contextlib import closing

import pytest
from test_workbench_setup_and_migrations import (
    EXPECTED_MIGRATIONS,
    SCHEMA,
    apply_historical_migrations,
    create_historical_database,
    insert_historical_row,
    insert_legacy_scan,
)


@pytest.mark.cross_platform
@pytest.mark.parametrize("preview_offset", [0, 3, 4])
def test_durable_recovery_preview_preserves_receipts_and_saved_input(preview_offset: int) -> None:
    preview = tuple(
        (version - 6 - preview_offset, name, sql)
        for version, name, sql in SCHEMA.MIGRATIONS
        if 73 <= version <= 76
    )
    db, migrate = create_historical_database(67 - preview_offset)
    with closing(db):
        timestamp = "2026-10-01T00:00:00Z"
        apply_historical_migrations(db, preview, timestamp)
        insert_historical_row(db, "workspaces", timestamp, id="legacy-workspace")
        insert_legacy_scan(db, timestamp, mode="deep")
        db.execute(
            """
            INSERT INTO deep_scan_runs (scan_id, schema_version, workflow_version, status, phase,
                workers, subagents, stop_after_no_new, max_discovery_runs, created_at, updated_at,
                finalization_input_json, usage_owner_json, execution_settings_json)
            VALUES ('legacy-scan', 1, 'legacy', 'running', 'discovery', 1, 0, 3, 10, ?, ?, ?, ?, ?)
            """,
            (timestamp, timestamp, '"selected input"', '"owner"', '"settings"'),
        )
        db.execute("UPDATE schema_migrations SET applied_at = ? WHERE version >= 63", (timestamp,))
        for _ in range(2):
            migrate(db)
            assert [
                tuple(row)
                for row in db.execute(
                    "SELECT version, name, applied_at FROM schema_migrations WHERE version >= 73 ORDER BY version"
                )
            ] == [(version + 6 + preview_offset, name, timestamp) for version, name, _ in preview]
            assert tuple(
                db.execute(
                    "SELECT finalization_input_json, usage_owner_json, execution_settings_json, worker_usage_gap "
                    "FROM deep_scan_runs WHERE scan_id = 'legacy-scan'"
                ).fetchone()
            ) == ('"selected input"', '"owner"', '"settings"', 0)


@pytest.mark.parametrize(
    "legacy_version", [48, 51, "published", "branch", "pre-merge", "previous-head"]
)
def test_local_cache_upgrade_preserves_deep_scan_migration_history(
    legacy_version: int | str,
) -> None:
    current = SCHEMA.MIGRATIONS
    published = isinstance(legacy_version, str)
    branch = legacy_version == "branch"
    pre_merge = legacy_version == "pre-merge"
    previous_head = legacy_version == "previous-head"
    historical = tuple(
        migration
        for migration in current
        if migration[0]
        <= (53 if previous_head else 52 if pre_merge else 47 if branch else 46 if published else 43)
    )

    def historical_version(version: int) -> int:
        if previous_head:
            return version
        if pre_merge:
            return version - 1
        return version - (6 if branch else 7 if published or version == 58 else 9)

    # The former branch numbered these five migrations 54 through 58.
    previous_migrations = (
        "retain deep scan attempts and exact merge inputs",
        "persist selected deep scan finalization input",
        "freeze stopped scan checkpoint selections",
        "bind original deep scan parent usage turn",
        "bind original deep scan execution settings",
    )
    sql_by_name = {name: sql for _, name, sql in current}
    historical += tuple(
        (historical_version(version), name, sql_by_name[name])
        for version, name in enumerate(previous_migrations, 54)
        if published or historical_version(version) <= legacy_version
    )
    connection, apply_migrations = create_historical_database(1, historical)
    connection.execute(
        "INSERT INTO findings (id, fingerprint, rule_id, identity_anchor, created_at, updated_at) "
        "VALUES ('finding', 'fingerprint', 'rule', 'anchor', 'created', 'updated')"
    )
    connection.execute(
        "INSERT INTO finding_embeddings (finding_id, model, vector_json) "
        "VALUES ('finding', 'service-model', '[1, 0]')"
    )
    recorded = {
        row["name"]: row["applied_at"]
        for row in connection.execute("SELECT name, applied_at FROM schema_migrations")
    }
    original_tables = {
        name: [tuple(column)[1:] for column in connection.execute(f"PRAGMA table_info({name})")]
        for (name,) in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        if name.startswith("deep_scan_")
    }
    connection.commit()
    for _ in range(2):
        apply_migrations(connection)
        assert [
            tuple(row) for row in connection.execute("SELECT version, name FROM schema_migrations")
        ] == EXPECTED_MIGRATIONS
        for row in connection.execute("SELECT name, applied_at FROM schema_migrations"):
            if row["name"] in recorded:
                assert row["applied_at"] == recorded[row["name"]]
        for name, columns in original_tables.items():
            upgraded_columns = [
                tuple(column)[1:] for column in connection.execute(f"PRAGMA table_info({name})")
            ]
            assert all(column in upgraded_columns for column in columns)
        assert any(
            row["name"] == "execution_settings_json" and row["type"] == "TEXT"
            for row in connection.execute("PRAGMA table_info(deep_scan_runs)")
        )
        assert dict(connection.execute("SELECT * FROM finding_embeddings").fetchone()) == {
            "finding_id": "finding",
            "model": "service-model",
            "vector_json": "[1, 0]",
            "cache_key": None,
        }
        assert (
            connection.execute("SELECT COUNT(*) FROM local_finding_embeddings").fetchone()[0] == 0
        )
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
