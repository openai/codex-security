from __future__ import annotations

import runpy
import sqlite3
from pathlib import Path

import pytest


@pytest.mark.parametrize(
    ("shared_version", "relocations"),
    [
        (41, ((42, 43), (43, 54), (44, 55))),
        (47, ((48, 54), (49, 55))),
        (51, ((52, 54), (53, 55))),
        (52, ((53, 54), (54, 55))),
    ],
)
def test_composition_preview_history_preserves_rows_and_migration_timestamps(
    shared_version, relocations
) -> None:
    schema = runpy.run_path(
        str(Path(__file__).resolve().parents[1] / "scripts" / "workbench_schema.py")
    )
    current = schema["MIGRATIONS"]
    by_version = {version: (name, sql) for version, name, sql in current}
    # Published composition histories must retain their original data and receipts.
    previous = tuple(row for row in current if row[0] <= shared_version) + tuple(
        (old, *by_version[new]) for old, new in relocations
    )
    original_time = "2026-01-01T00:00:00Z"
    upgrade_time = "2026-02-01T00:00:00Z"
    with sqlite3.connect(":memory:") as connection:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        schema["apply_migrations"](connection, previous, lambda: original_time, lambda _: None)
        connection.execute(
            "INSERT INTO workspaces (id, created_at, updated_at) VALUES ('workspace', ?, ?)",
            (original_time, original_time),
        )
        connection.execute(
            "INSERT INTO scans (id, workspace_id, target_path, target_revision, scope, mode, "
            "scan_dir, status, phase, started_at, created_at, updated_at, parent_scan_role) "
            "VALUES ('scan', 'workspace', '/synthetic/repository', 'unversioned', '.', 'standard', "
            "'/synthetic/scans/scan', 'failed', 'preflight', ?, ?, ?, 'deep_pass')",
            (original_time, original_time, original_time),
        )
        connection.execute(
            "INSERT INTO findings (id, fingerprint, rule_id, identity_anchor, created_at, updated_at) "
            "VALUES ('finding', 'fingerprint', 'synthetic.rule', 'synthetic-anchor', ?, ?)",
            (original_time, original_time),
        )
        connection.execute(
            "INSERT INTO scan_severity_classifications (scan_id, finding_ids_json, assessed_at) "
            "VALUES ('scan', '[\"finding\"]', ?)",
            (original_time,),
        )
        connection.execute(
            "INSERT INTO scan_severity_assessments "
            "(scan_id, finding_id, input_sha256, assessed_at, source, decision, level, rationale) "
            "VALUES ('scan', 'finding', 'synthetic-digest', ?, 'rubric', 'assessed', 'high', "
            "'Synthetic retained assessment')",
            (original_time,),
        )
        scan = dict(connection.execute("SELECT * FROM scans WHERE id = 'scan'").fetchone())
        assessment = dict(connection.execute("SELECT * FROM scan_severity_assessments").fetchone())
        schema["apply_migrations"](connection, current, lambda: upgrade_time, lambda _: None)
        upgraded = dict(connection.execute("SELECT * FROM scans WHERE id = 'scan'").fetchone())
        assert {name: upgraded[name] for name in scan} == scan
        upgraded_assessment = dict(
            connection.execute("SELECT * FROM scan_severity_assessments").fetchone()
        )
        assert {name: upgraded_assessment[name] for name in assessment} == assessment
        assert upgraded_assessment["classification_runs"] is None
        history = {
            row["version"]: (row["name"], row["applied_at"])
            for row in connection.execute("SELECT * FROM schema_migrations")
        }
        assert history[52] == (
            "record severity classification review counts",
            original_time if shared_version >= 52 else upgrade_time,
        )
        for old, new in relocations:
            assert history[new] == (previous[old - 1][1], original_time)
        assert history[42] == (
            by_version[42][0],
            original_time if shared_version >= 42 else upgrade_time,
        )
        assert [row["name"] for row in connection.execute("PRAGMA index_list(scans)")].count(
            "scans_by_composition_parent"
        ) == 1
        schema["apply_migrations"](connection, current, lambda: upgrade_time, lambda _: None)
        assert {
            row["version"]: (row["name"], row["applied_at"])
            for row in connection.execute("SELECT * FROM schema_migrations")
        } == history
