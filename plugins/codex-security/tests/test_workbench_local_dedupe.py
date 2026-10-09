from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from pathlib import Path

import pytest

TIMESTAMP = "2026-01-01T00:00:00Z"


def finding(index: int) -> dict:
    source = Path(__file__).resolve().parents[1] / "examples/completed-scan/findings.json"
    result = json.loads(source.read_text())["findings"][0]
    result["findingId"] = f"finding-{index}"
    result["fingerprints"]["primary"] = f"fingerprint-{index}"
    return result


def request(api, connection, action, **values):
    return api["local_dedupe"](
        connection,
        {
            "action": action,
            "space": "synthetic-v1",
            "model": "synthetic",
            "dimensions": 2,
            **values,
        },
        TIMESTAMP,
    )


def prepare(api, connection, findings, **values):
    repository_path = str(Path(__file__).resolve().parent)
    with connection:
        target_id = api["ensure_security_target"](connection, repository_path)
    return request(
        api,
        connection,
        "prepare",
        findings=findings,
        anchorRepositoryId=target_id,
        repositoryId=target_id,
        repositoryPath=repository_path,
        **values,
    )


def entry(prepared, index=0, **values):
    finding_id = prepared["findingsToEmbed"][index]["findingId"]
    return {
        "findingId": finding_id,
        "cacheKey": prepared["cacheKeys"][finding_id],
        "embedding": {"model": "synthetic", "vector": [1, 0]},
        **values,
    }


def test_cache_reuse_survives_service_embedding_writes(workbench_api, workbench_db):
    first = prepare(workbench_api, workbench_db, [finding(1)])
    assert first["findingsToEmbed"] == [finding(1)]
    assert request(workbench_api, workbench_db, "embed", entries=[entry(first)]) == {}
    assert prepare(workbench_api, workbench_db, [finding(1)]) == {
        "cacheKeys": first["cacheKeys"],
        "findingsToEmbed": [],
    }
    assert prepare(workbench_api, workbench_db, [finding(1)], space="synthetic-v2")[
        "findingsToEmbed"
    ] == [finding(1)]
    with workbench_db:
        workbench_db.execute(
            "INSERT INTO finding_embeddings (finding_id, model, vector_json) VALUES (?, ?, ?)",
            ("finding-1", "synthetic", "[0, 1]"),
        )
    assert prepare(workbench_api, workbench_db, [finding(1)])["findingsToEmbed"] == []


def test_preparation_returns_all_cache_keys_but_only_uncached_bodies(workbench_api, workbench_db):
    first = prepare(workbench_api, workbench_db, [finding(1)])
    request(workbench_api, workbench_db, "embed", entries=[entry(first)])
    mixed = prepare(workbench_api, workbench_db, [finding(1), finding(2)])
    assert mixed["findingsToEmbed"] == [finding(2)]
    assert set(mixed["cacheKeys"]) == {"finding-1", "finding-2"}
    assert mixed["cacheKeys"]["finding-1"] == first["cacheKeys"]["finding-1"]
    assert prepare(workbench_api, workbench_db, []) == {"cacheKeys": {}, "findingsToEmbed": []}


@pytest.mark.parametrize("failure", ["stale", "dimensions", "zero", "nonfinite"])
def test_embedding_batch_rolls_back_on_invalid_or_stale_input(workbench_api, workbench_db, failure):
    prepared = prepare(workbench_api, workbench_db, [finding(1), finding(2)])
    second = entry(prepared, 1)
    if failure == "stale":
        second["cacheKey"] = "old-input"
    else:
        second["embedding"]["vector"] = {
            "dimensions": [1],
            "zero": [0, 0],
            "nonfinite": [float("nan"), 0],
        }[failure]
    result = request(workbench_api, workbench_db, "embed", entries=[entry(prepared), second])
    assert result == {"error": "finding_changed" if failure == "stale" else "embedding_failed"}
    assert workbench_db.execute("SELECT COUNT(*) FROM local_finding_embeddings").fetchone()[0] == 0


def test_preparation_conflict_rolls_back_new_findings(workbench_api, workbench_db):
    prepare(workbench_api, workbench_db, [finding(1)])
    conflicting = finding(1)
    conflicting["identity"]["anchor"] = "different-anchor"
    assert prepare(workbench_api, workbench_db, [finding(2), conflicting]) == {
        "error": "finding_conflict"
    }
    assert workbench_db.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 1


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


def test_finding_body_update_invalidates_local_search_and_pending_groups(
    workbench_api, workbench_db
):
    prepared = prepare(workbench_api, workbench_db, [finding(1)])
    request(workbench_api, workbench_db, "embed", entries=[entry(prepared)])
    changed = {**finding(1), "title": "Updated evidence from another scan"}
    with workbench_db:
        workbench_db.execute(
            "UPDATE findings SET details_json = ? WHERE id = ?",
            (json.dumps(changed, sort_keys=True), "finding-1"),
        )
    assert workbench_db.execute("SELECT COUNT(*) FROM local_finding_embeddings").fetchone()[0] == 0
    assert prepare(workbench_api, workbench_db, [finding(1)])["findingsToEmbed"] == [changed]
