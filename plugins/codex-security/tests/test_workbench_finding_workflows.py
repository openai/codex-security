from __future__ import annotations

import json
import sqlite3

import pytest

TIMESTAMP = "2026-08-01T00:00:00Z"


def workflow(api, connection, action, *, workflow_id="synthetic-workflow", **payload):
    return api["finding_workflow"](
        connection, {"id": workflow_id, "action": action, **payload}, TIMESTAMP
    )


@pytest.mark.parametrize("linked_state", [False, True])
@pytest.mark.parametrize("linked_home", [False, True])
def test_source_snapshot_excludes_generated_home_without_following_its_leaf_link(
    workbench_api, workbench_db, tmp_path, linked_state, linked_home
):
    repository = tmp_path / "repository"
    source = repository / "src"
    source.mkdir(parents=True)
    source_file = source / "index.ts"
    source_file.write_text("export const value = 1;\n")
    state = repository / "local-state"
    state.mkdir()
    credential_home = state / "codex-home"
    if linked_home:
        credential_home.symlink_to(source, target_is_directory=True)
    else:
        credential_home.mkdir()
    selected_state = state
    if linked_state:
        selected_state = tmp_path / "configured-state"
        selected_state.symlink_to(state, target_is_directory=True)

    def snapshot():
        return workflow(
            workbench_api,
            workbench_db,
            "source",
            repository=str(repository),
            credentialHome=str(selected_state / "codex-home"),
        )["source"]

    original = snapshot()
    if not linked_home:
        (credential_home / "history.jsonl").write_text('{"generated":true}\n')
        assert snapshot() == original
    source_file.write_text("export const value = 2;\n")
    changed = snapshot()
    assert changed["content"] != original["content"]
    (state / "ordinary-source.ts").write_text("export const local = 1;\n")
    assert snapshot()["content"] != changed["content"]


@pytest.mark.parametrize("database_name", ["workbench.sqlite3", "external.sqlite3"])
def test_source_snapshot_separates_linked_database_storage_from_managed_directories(
    workbench_api, tmp_path, database_name
):
    repository = tmp_path / "repository"
    state = repository / "local-state"
    state.mkdir(parents=True)
    storage = repository / "database-storage"
    storage.mkdir()
    database = storage / database_name
    selected_database = state / "workbench.sqlite3"
    selected_database.symlink_to(database)
    with sqlite3.connect(selected_database) as connection:
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("CREATE TABLE sample (value INTEGER)")

        def snapshot():
            return workflow(
                workbench_api,
                connection,
                "source",
                repository=str(repository),
                credentialHome=str(state / "codex-home"),
            )["source"]

        original = snapshot()
        with connection:
            connection.execute("INSERT INTO sample VALUES (1)")
        assert snapshot() == original
        for name in ("dedupe", "dedupe-locks"):
            directory = state / name
            directory.mkdir()
            (directory / "generated").write_text("managed output")
            assert snapshot() == original
        locks = storage / (
            "dedupe-locks"
            if database_name == "workbench.sqlite3"
            else f"{database_name}.dedupe-locks"
        )
        locks.mkdir()
        (locks / "operation.sqlite3").write_text("managed lock")
        assert snapshot() == original
        ordinary = storage / "dedupe"
        ordinary.mkdir()
        (ordinary / "source.ts").write_text("export const source = 1;\n")
        assert snapshot()["content"] != original["content"]


@pytest.mark.parametrize("suffix", ["-wal", "-shm", "-journal"])
def test_source_snapshot_uses_sqlite_reported_sidecar_paths(workbench_api, tmp_path, suffix):
    repository = tmp_path / "repository"
    state = repository / "local-state"
    state.mkdir(parents=True)
    database = repository / "physical.sqlite3"
    selected_database = state / "workbench.sqlite3"
    selected_database.symlink_to(database)
    with sqlite3.connect(database) as connection:
        connection.execute("CREATE TABLE sample (value INTEGER)")
        connection.commit()

        class ReportedPathConnection:
            def execute(self, statement):
                assert statement == "PRAGMA database_list"
                # The Windows VFS reports the opened pathname without resolving its leaf link.
                return connection.execute("SELECT 0, 'main', ?", (str(selected_database),))

        def snapshot():
            return workflow(
                workbench_api,
                ReportedPathConnection(),
                "source",
                repository=str(repository),
                credentialHome=str(state / "codex-home"),
            )["source"]

        original = snapshot()
        with connection:
            connection.execute("INSERT INTO sample VALUES (1)")
        assert snapshot() == original
        sidecar = state / f"workbench.sqlite3{suffix}"
        sidecar.write_bytes(b"SQLite sidecar before write")
        assert snapshot() == original
        sidecar.write_bytes(b"SQLite sidecar after write")
        assert snapshot() == original
        source = state / "ordinary.ts"
        source.write_text("export const source = 1;\n")
        assert snapshot()["content"] != original["content"]
        source.unlink()
        alias = tmp_path / "database-alias.sqlite3"
        alias.symlink_to(database)
        selected_database.unlink()
        selected_database.symlink_to(alias)
        assert snapshot()["content"] != original["content"]


@pytest.mark.parametrize("stage", ["scan", "publish", "dedupe"])
def test_failed_stages_resume_and_completed_results_are_immutable(
    workbench_api, workbench_db, stage
):
    assert workflow(workbench_api, workbench_db, "get") == {"workflow": None}
    bound = workflow(workbench_api, workbench_db, "bind", binding={})["workflow"]
    assert bound["stages"] == {
        name: {"status": "pending"} for name in ("scan", "publish", "dedupe")
    }
    assert (
        workflow(workbench_api, workbench_db, "begin", stage=stage)["workflow"]["stages"][stage][
            "status"
        ]
        == "running"
    )
    failed = workflow(workbench_api, workbench_db, "fail", stage=stage, error="Synthetic failure")
    assert failed["workflow"]["stages"][stage] == {"status": "failed", "error": "Synthetic failure"}
    assert (
        workflow(workbench_api, workbench_db, "begin", stage=stage)["workflow"]["stages"][stage][
            "status"
        ]
        == "running"
    )
    result = {"findingIds": [], "duplicateGroups": []}
    completed = workflow(workbench_api, workbench_db, "complete", stage=stage, result=result)
    assert completed["workflow"]["stages"][stage] == {"status": "completed", "result": result}
    for action, payload in [
        ("begin", {}),
        ("fail", {"error": "Late failure"}),
        ("complete", {"result": {"unexpected": True}}),
    ]:
        assert workflow(workbench_api, workbench_db, action, stage=stage, **payload) == completed


@pytest.mark.parametrize(
    ("binding", "changed"),
    [
        ({"scanId": "scan-a"}, {"scanId": "scan-b"}),
        ({"scanDir": "/synthetic/scan-a"}, {"scanDir": "/synthetic/scan-b"}),
        ({"destination": "https://synthetic.invalid/"}, {"destination": "https://other.invalid/"}),
        ({"scope": {"repositoryId": "repository-a"}}, {"scope": {"allRepositories": True}}),
        ({"scope": {"allRepositories": True}}, {"scope": {"repositoryId": "repository-a"}}),
    ],
)
def test_bindings_and_workflow_identities_remain_separate(
    workbench_api, workbench_db, binding, changed
):
    workflow(workbench_api, workbench_db, "bind", binding=binding)
    saved = workflow(
        workbench_api, workbench_db, "complete", stage="dedupe", result={"duplicateGroups": []}
    )
    with pytest.raises(SystemExit, match="already bound to a different"):
        workflow(workbench_api, workbench_db, "bind", binding=changed)
    assert not workbench_db.in_transaction
    assert workflow(workbench_api, workbench_db, "get") == saved
    separate = workflow(
        workbench_api, workbench_db, "bind", workflow_id="separate", binding=changed
    )
    assert separate["workflow"]["id"] == "separate"
    assert separate["workflow"]["stages"]["dedupe"] == {"status": "pending"}
    for key, value in changed.items():
        assert separate["workflow"][key] == value
    assert workflow(workbench_api, workbench_db, "get") == saved


@pytest.mark.parametrize("result", [{"duplicateGroups": []}, {"duplicateGroups": [["a", "b"]]}])
def test_pending_publication_payload_survives_failure_until_completion(
    workbench_api, workbench_db, result
):
    assert not workflow(workbench_api, workbench_db, "dedupe-progress")["progress"]["pendingWrite"]
    workflow(workbench_api, workbench_db, "bind", binding={})
    workflow(workbench_api, workbench_db, "begin", stage="dedupe")
    assert not workflow(workbench_api, workbench_db, "dedupe-progress")["progress"]["pendingWrite"]
    pending = {"groups": result["duplicateGroups"]}
    prepared = workflow(
        workbench_api,
        workbench_db,
        "prepare-dedupe",
        stage="dedupe",
        result=result,
        pendingWrite=pending,
    )
    assert prepared["workflow"]["stages"]["dedupe"] == {
        "status": "running",
        "result": result,
        "pendingWrite": pending,
    }
    workflow(workbench_api, workbench_db, "fail", stage="dedupe", error="Lost acknowledgement")
    assert workflow(workbench_api, workbench_db, "dedupe-progress")["progress"]["pendingWrite"]
    resumed = workflow(workbench_api, workbench_db, "begin", stage="dedupe")["workflow"]["stages"][
        "dedupe"
    ]
    assert resumed["result"] == result
    assert resumed["pendingWrite"] == pending
    completed = workflow(workbench_api, workbench_db, "complete", stage="dedupe", result=result)
    assert completed["workflow"]["stages"]["dedupe"] == {"status": "completed", "result": result}
    assert not workflow(workbench_api, workbench_db, "dedupe-progress")["progress"]["pendingWrite"]


def test_review_checkpoints_keep_the_first_valid_result_and_enforce_workflow_ownership(
    workbench_api, workbench_db
):
    binding = {
        "version": 1,
        "codexVersion": "synthetic-version",
        "source": {
            "repository": "/synthetic/repository",
            "revision": "synthetic-revision",
            "refsDigest": "synthetic-refs",
            "content": "synthetic-content",
        },
        "scope": {"repositoryId": "synthetic-repository"},
        "model": "synthetic-model",
        "effort": "high",
        "settingsDigest": "synthetic-settings",
        "promptDigest": "synthetic-prompt",
        "contractDigest": "synthetic-contract",
    }
    result = {"decision": "DISTINCT", "rationale": "Independent corrections"}
    with pytest.raises(sqlite3.IntegrityError):
        workflow(
            workbench_api,
            workbench_db,
            "save-review",
            key="review-1",
            binding=binding,
            result=result,
        )
    workflow(workbench_api, workbench_db, "bind", binding={})
    assert workflow(workbench_api, workbench_db, "get-review", key="review-1") == {"review": None}
    workflow(
        workbench_api, workbench_db, "save-review", key="review-1", binding=binding, result=result
    )
    workflow(
        workbench_api,
        workbench_db,
        "save-review",
        key="review-1",
        binding=binding,
        result={"unexpected": True},
    )
    assert workflow(workbench_api, workbench_db, "get-review", key="review-1") == {"review": result}
    assert workflow(
        workbench_api, workbench_db, "get-review", workflow_id="another", key="review-1"
    ) == {"review": None}
    row = workbench_db.execute("SELECT * FROM finding_workflow_reviews").fetchone()
    assert row["source_repository_path"] == binding["source"]["repository"]
    assert row["settings_digest"] == binding["settingsDigest"]
    assert json.loads(row["result_json"]) == result


@pytest.mark.parametrize(
    "payload",
    [
        {"action": "bind", "binding": {"unknown": "value"}},
        {"action": "begin", "stage": "unknown"},
        {"action": "unknown", "stage": "scan"},
    ],
)
def test_rejected_workflow_mutations_roll_back_without_leaking_state(
    workbench_api, workbench_db, payload
):
    saved = workflow(workbench_api, workbench_db, "bind", binding={})
    with pytest.raises(SystemExit):
        workflow(workbench_api, workbench_db, **payload)
    assert not workbench_db.in_transaction
    assert workflow(workbench_api, workbench_db, "get") == saved


def test_workflow_column_migration_is_atomic_and_preserves_resume_state(workbench_api, tmp_path):
    database = tmp_path / "legacy.sqlite3"
    completed = {
        "id": "migrated-completed",
        "repositoryPath": str(tmp_path / "repository"),
        "scanRequestDigest": "synthetic-request-hash",
        "scanId": "synthetic-scan",
        "scanDir": str(tmp_path / "scan"),
        "artifactDigest": "synthetic-artifact-hash",
        "destination": "https://synthetic.invalid/",
        "scope": {"repositoryId": "synthetic-repository"},
        "stages": {
            "scan": {"status": "completed", "result": None},
            "publish": {"status": "completed", "result": {"findingIds": []}},
            "dedupe": {"status": "completed", "result": {"duplicateGroups": []}},
        },
    }
    unfinished = {
        "id": "migrated-unfinished",
        "scope": {"allRepositories": True},
        "stages": {
            "scan": {"status": "failed", "error": "Synthetic interruption"},
            "publish": {"status": "running", "error": "Synthetic earlier failure"},
            "dedupe": {
                "status": "failed",
                "error": "Synthetic lost acknowledgement",
                "result": {"duplicateGroups": [["a", "b"]]},
                "pendingWrite": {"groups": [["a", "b"]]},
            },
        },
    }
    pending = {
        "id": "migrated-pending",
        "stages": {stage: {"status": "pending"} for stage in ("scan", "publish", "dedupe")},
    }
    migrations = workbench_api["MIGRATIONS"]
    connection = sqlite3.connect(database)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")

    def migrate(history):
        workbench_api["apply_schema_migrations"](
            connection, history, lambda: TIMESTAMP, workbench_api["backfill_security_targets"]
        )

    try:
        migrate(tuple(m for m in migrations if m[0] <= 36))
        with connection:
            for state in (completed, unfinished, pending):
                connection.execute(
                    "INSERT INTO finding_workflows VALUES (?, ?, ?, ?)",
                    (state["id"], json.dumps(state), TIMESTAMP, "2026-08-02T00:00:00Z"),
                )
            connection.execute(
                "CREATE TABLE synthetic_workflow_references "
                "(workflow_id TEXT REFERENCES finding_workflows(id) ON DELETE CASCADE)"
            )
            connection.execute(
                "INSERT INTO synthetic_workflow_references VALUES (?)", (completed["id"],)
            )
        before = list(connection.iterdump())
        with pytest.raises(sqlite3.OperationalError):
            migrate(
                (
                    *migrations,
                    (999, "synthetic failure", "INSERT INTO synthetic_missing_table VALUES (1);"),
                )
            )
        assert not connection.in_transaction
        assert list(connection.iterdump()) == before
        migrate(migrations)
        after = list(connection.iterdump())
        migrate(migrations)
        assert list(connection.iterdump()) == after
        assert "state_json" not in {
            row["name"] for row in connection.execute("PRAGMA table_info(finding_workflows)")
        }
        assert (
            connection.execute("SELECT count(*) FROM synthetic_workflow_references").fetchone()[0]
            == 1
        )
        assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert list(connection.execute("PRAGMA foreign_key_check")) == []
        row = connection.execute(
            "SELECT * FROM finding_workflows WHERE id = ?", (completed["id"],)
        ).fetchone()
        assert row["repository_path"] == completed["repositoryPath"]
        assert row["scan_request_digest"] == completed["scanRequestDigest"]
        assert row["artifact_digest"] == completed["artifactDigest"]
        assert row["scope_all_repositories"] is None
        assert row["created_at"] == TIMESTAMP
        assert row["updated_at"] == "2026-08-02T00:00:00Z"
    finally:
        connection.close()

    # Reopen the actual file so this remains a persistence and migration test.
    connection = sqlite3.connect(database)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    try:
        for state in (completed, unfinished, pending):
            assert workflow(workbench_api, connection, "get", workflow_id=state["id"]) == {
                "workflow": state
            }
        for stage in ("scan", "publish", "dedupe"):
            state = workflow(
                workbench_api, connection, "begin", workflow_id=completed["id"], stage=stage
            )
            assert state == {"workflow": completed}
        workflow(workbench_api, connection, "begin", workflow_id=unfinished["id"], stage="scan")
        resumed = workflow(
            workbench_api,
            connection,
            "complete",
            workflow_id=unfinished["id"],
            stage="scan",
            result={"scanId": "resumed-scan"},
        )
        assert resumed["workflow"]["stages"]["scan"] == {
            "status": "completed",
            "result": {"scanId": "resumed-scan"},
        }
    finally:
        connection.close()
