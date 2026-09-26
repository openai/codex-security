from __future__ import annotations

import json
import sqlite3
from contextlib import closing

import pytest


@pytest.mark.parametrize("upgrade", [False, True], ids=["fresh", "upgrade"])
def test_frozen_checkpoint_head_migration_preserves_scan_state(workbench_api, upgrade):
    migrations = workbench_api["MIGRATIONS"]
    timestamp = "2026-07-01T00:00:00Z"

    def migrate(connection, selected):
        workbench_api["apply_schema_migrations"](
            connection, selected, lambda: timestamp, workbench_api["backfill_security_targets"]
        )

    with closing(sqlite3.connect(":memory:")) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        migrate(
            connection,
            tuple(item for item in migrations if item[0] != 47) if upgrade else migrations,
        )
        connection.execute(
            "INSERT INTO workspaces (id, created_at, updated_at) VALUES (?, ?, ?)",
            ("workspace", timestamp, timestamp),
        )
        for status in ("running", "failed"):
            connection.execute(
                "INSERT INTO scans (id, workspace_id, target_path, target_revision, scope, "
                "mode, scan_dir, status, phase, started_at, created_at, updated_at, "
                "failure_message, retained_source_digests_json) "
                "VALUES (?, 'workspace', 'target', 'revision', '.', 'deep', ?, ?, "
                "'discovery', ?, ?, ?, ?, ?)",
                (
                    status,
                    f"scans/{status}",
                    status,
                    timestamp,
                    timestamp,
                    timestamp,
                    "Original stop reason." if status == "failed" else None,
                    json.dumps({"workers/review/result.json": "b" * 64})
                    if status == "failed"
                    else None,
                ),
            )
        before = [dict(row) for row in connection.execute("SELECT * FROM scans ORDER BY id")]
        migrate(connection, migrations)
        after = [dict(row) for row in connection.execute("SELECT * FROM scans ORDER BY id")]
        for original, updated in zip(before, after, strict=True):
            assert updated.pop("retained_checkpoint_heads_json") is None
            original.pop("retained_checkpoint_heads_json", None)
            assert updated == original

        heads = json.dumps({"workers/review": "workers/review/checkpoints/" + "a" * 64 + ".json"})
        connection.execute(
            "UPDATE scans SET retained_checkpoint_heads_json = ? WHERE id = 'failed'", (heads,)
        )
        migrate(connection, migrations)
        assert (
            connection.execute(
                "SELECT retained_checkpoint_heads_json FROM scans WHERE id = 'failed'"
            ).fetchone()[0]
            == heads
        )
        assert (
            connection.execute(
                "SELECT retained_checkpoint_heads_json FROM scans WHERE id = 'running'"
            ).fetchone()[0]
            is None
        )
        assert [
            tuple(row)
            for row in connection.execute(
                "SELECT version, name FROM schema_migrations WHERE version = 47"
            )
        ] == [(47, "freeze stopped scan checkpoint selections")]
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
