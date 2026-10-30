from __future__ import annotations

import json
import sqlite3
from contextlib import closing

import pytest


@pytest.mark.parametrize(
    "omitted_versions, legacy_checkpoint, main_reader",
    [
        ((), False, False),
        ((57,), False, False),
        ((), 47, False),
        ((), 47, True),
        ((), 48, False),
        ((), 50, False),
        ((), 52, False),
        ((), 53, False),
        ((), 54, False),
        ((43,), 47, False),
        ((44, 45, 46), 47, False),
    ],
    ids=[
        "fresh",
        "upgrade",
        "legacy-checkpoint",
        "legacy-main-reader",
        "prior-checkpoint-number",
        "previous-head-checkpoint-number",
        "refresh-checkpoint-number",
        "previous-main-checkpoint-number",
        "checkpoint-before-headless-recovery",
        "legacy-severity-gap",
        "legacy-dedupe-gap",
    ],
)
def test_frozen_checkpoint_head_migration_preserves_scan_state(
    workbench_api, omitted_versions, legacy_checkpoint, main_reader
):
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
            tuple(
                (legacy_checkpoint, name, sql)
                if legacy_checkpoint and version == 57
                else (version, name, sql)
                for version, name, sql in migrations
                if version not in omitted_versions
                and not (legacy_checkpoint and version in (54, 55, 56))
                and not (legacy_checkpoint in (47, 48, 50, 52, 53) and version in (52, 53))
                and not (legacy_checkpoint in (47, 48, 50) and version in (50, 51))
                and not (legacy_checkpoint in (47, 48) and version in (48, 49))
                and not (legacy_checkpoint == 47 and version == 47)
            ),
        )
        if main_reader:
            connection.execute(next(sql for version, _, sql in migrations if version == 47))
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
        heads = json.dumps({"workers/review": "workers/review/checkpoints/" + "a" * 64 + ".json"})
        if 57 not in omitted_versions:
            connection.execute(
                "UPDATE scans SET retained_checkpoint_heads_json = ? WHERE id = 'failed'", (heads,)
            )
        original_checkpoint_migration = connection.execute(
            "SELECT * FROM schema_migrations WHERE version = ?",
            (legacy_checkpoint or 57,),
        ).fetchone()
        connection.execute(
            "INSERT INTO deep_scan_runs (scan_id, schema_version, workflow_version, status, phase, "
            "workers, subagents, stop_after_no_new, max_discovery_runs, created_at, updated_at) "
            "VALUES ('failed', 1, 'v1', 'failed', 'terminal', 1, 0, 7, 10, ?, ?)",
            (timestamp, timestamp),
        )
        context = json.dumps("Original discovery context")
        if legacy_checkpoint != 47 or main_reader:
            connection.execute(
                "UPDATE deep_scan_runs SET discovery_user_context_json = ?", (context,)
            )
        original_discovery_migration = connection.execute(
            "SELECT name, applied_at FROM schema_migrations WHERE version = 47"
        ).fetchone()
        before = [dict(row) for row in connection.execute("SELECT * FROM scans ORDER BY id")]
        migrate(connection, migrations)
        after = [dict(row) for row in connection.execute("SELECT * FROM scans ORDER BY id")]
        for original, updated in zip(before, after, strict=True):
            retained_heads = updated.pop("retained_checkpoint_heads_json")
            assert retained_heads == original.get("retained_checkpoint_heads_json")
            original.pop("retained_checkpoint_heads_json", None)
            if "source_scopes_json" not in original:
                source_scopes = updated.pop("source_scopes_json")
                assert source_scopes is None
            assert updated == original

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
                "SELECT version, name FROM schema_migrations WHERE version = 57"
            )
        ] == [(57, "freeze stopped scan checkpoint selections")]
        if original_checkpoint_migration is not None:
            assert (
                connection.execute(
                    "SELECT name, applied_at FROM schema_migrations WHERE version = 57"
                ).fetchone()[:]
                == original_checkpoint_migration[1:]
            )
        assert connection.execute(
            "SELECT COUNT(*), MAX(version) FROM schema_migrations"
        ).fetchone()[:] == (len(migrations), 58)
        for version in (43, 44, 45, 46, 47):
            assert (
                connection.execute(
                    "SELECT COUNT(*) FROM schema_migrations WHERE version = ?", (version,)
                ).fetchone()[0]
                == 1
            )
        assert connection.execute(
            "SELECT discovery_user_context_json FROM deep_scan_runs"
        ).fetchone()[0] == (context if legacy_checkpoint != 47 or main_reader else None)
        if legacy_checkpoint != 47:
            assert (
                connection.execute(
                    "SELECT name, applied_at FROM schema_migrations WHERE version = 47"
                ).fetchone()
                == original_discovery_migration
            )
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []


def test_current_checkpoint_schema_reader_does_not_wait_for_writer(workbench_api, tmp_path):
    database_path = tmp_path / "workbench.sqlite3"

    def migrate(connection):
        connection.row_factory = sqlite3.Row
        workbench_api["apply_schema_migrations"](
            connection,
            workbench_api["MIGRATIONS"],
            lambda: "2026-07-01T00:00:00Z",
            workbench_api["backfill_security_targets"],
        )

    with closing(sqlite3.connect(database_path)) as writer:
        writer.execute("PRAGMA journal_mode = WAL")
        migrate(writer)
        writer.execute("BEGIN IMMEDIATE")
        with closing(sqlite3.connect(database_path, timeout=0)) as reader:
            migrate(reader)
        writer.rollback()
