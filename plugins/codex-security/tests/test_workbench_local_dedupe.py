from __future__ import annotations

import sqlite3
from contextlib import closing

TIMESTAMP = "2026-01-01T00:00:00Z"


def test_embedding_cache_migration_preserves_existing_vectors(workbench_api, tmp_path):
    with closing(sqlite3.connect(tmp_path / "legacy.sqlite3")) as connection:
        connection.row_factory = sqlite3.Row
        workbench_api["apply_schema_migrations"](
            connection,
            tuple(m for m in workbench_api["MIGRATIONS"] if m[0] < 44),
            lambda: TIMESTAMP,
            workbench_api["backfill_security_targets"],
        )
        with connection:
            connection.execute(
                "INSERT INTO findings (id, fingerprint, rule_id, identity_anchor, created_at, updated_at) "
                "VALUES ('legacy', 'legacy', 'rule', 'anchor', ?, ?)",
                (TIMESTAMP, TIMESTAMP),
            )
            connection.execute(
                "INSERT INTO finding_embeddings VALUES ('legacy', 'synthetic', '[1, 0]')"
            )
        workbench_api["apply_migrations"](connection)
        row = connection.execute("SELECT * FROM finding_embeddings").fetchone()
        assert dict(row) == {
            "finding_id": "legacy",
            "model": "synthetic",
            "vector_json": "[1, 0]",
            "cache_key": None,
        }


def test_local_cache_migration_keeps_service_and_local_rows_separate(workbench_api, tmp_path):
    with closing(sqlite3.connect(tmp_path / "cached.sqlite3")) as connection:
        connection.row_factory = sqlite3.Row
        workbench_api["apply_schema_migrations"](
            connection,
            tuple(m for m in workbench_api["MIGRATIONS"] if m[0] < 45),
            lambda: TIMESTAMP,
            workbench_api["backfill_security_targets"],
        )
        with connection:
            for identity, key in [("service", None), ("local", "cached-input")]:
                connection.execute(
                    "INSERT INTO findings (id, fingerprint, rule_id, identity_anchor, created_at, updated_at) VALUES (?, ?, 'rule', 'anchor', ?, ?)",
                    (identity, identity, TIMESTAMP, TIMESTAMP),
                )
                connection.execute(
                    "INSERT INTO finding_embeddings VALUES (?, 'synthetic', '[1, 0]', ?)",
                    (identity, key),
                )
        workbench_api["apply_migrations"](connection)
        assert [
            row[0] for row in connection.execute("SELECT finding_id FROM finding_embeddings")
        ] == ["service"]
        assert [
            tuple(row)
            for row in connection.execute(
                "SELECT finding_id, cache_key FROM local_finding_embeddings"
            )
        ] == [("local", "cached-input")]
