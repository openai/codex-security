from __future__ import annotations

import json
import os
import sqlite3
from contextlib import closing
from functools import partial
from pathlib import Path

import pytest

TIMESTAMP = "2026-08-01T00:00:00Z"


def run_workflow(api, connection, action, *, workflow_id="synthetic-workflow", **payload):
    return api["finding_workflow"](
        connection, {"id": workflow_id, "action": action, **payload}, TIMESTAMP
    )


@pytest.fixture
def workflow(workbench_api, workbench_db):
    return partial(run_workflow, workbench_api, workbench_db)


@pytest.mark.parametrize("optional", [False, True])
def test_source_snapshot_excludes_private_storage_without_hiding_source(
    workflow, tmp_path, monkeypatch, optional
):
    repository = tmp_path / "repository"
    repository.mkdir()
    source = repository / "source.py"
    source.write_text("original source")
    private = repository / "native-state"
    private.mkdir()
    database = private / "state.sqlite"
    database.write_text("synthetic state")
    original_scandir = os.scandir

    def inspect(path):
        assert Path(path) != private, "private storage must not be traversed"
        return original_scandir(path)

    monkeypatch.setattr(os, "scandir", inspect)

    def snapshot():
        return workflow(
            "source",
            repository=str(repository),
            privateStatePaths=[str(private)],
            optional=optional,
        )["source"]

    before = snapshot()
    database.write_text("later native state")
    assert snapshot() == before
    assert before["privateStatePaths"] == [str(private)]
    source.write_text("changed source")
    assert snapshot()["content"] != before["content"]
    with pytest.raises(SystemExit, match="repository root"):
        workflow("source", repository=str(repository), privateStatePaths=[str(repository)])
    with pytest.raises(SystemExit, match="absolute paths"):
        workflow("source", repository=str(repository), privateStatePaths=["relative-state"])


@pytest.mark.parametrize("location", ["root", "descendant"])
def test_source_snapshot_preserves_unreadable_directory_errors(
    workflow, tmp_path, monkeypatch, location
):
    repository = tmp_path / "repository"
    repository.mkdir()
    unreadable = repository if location == "root" else repository / "unreadable"
    unreadable.mkdir(exist_ok=True)
    (unreadable / "contents.txt").write_text("source content")
    private = repository / "native-state"
    private.mkdir()
    original_scandir = os.scandir
    failure = PermissionError("synthetic inaccessible source directory")

    def inspect(path):
        assert Path(path) != private, "private storage must not be traversed"
        if Path(path) == unreadable:
            raise failure
        return original_scandir(path)

    monkeypatch.setattr(os, "scandir", inspect)

    def snapshot(excluded):
        return workflow(
            "source",
            repository=str(repository),
            gitDisabled=True,
            privateStatePaths=[str(path) for path in excluded],
        )["source"]

    with pytest.raises(PermissionError) as raised:
        snapshot([private])
    assert raised.value is failure
    if location == "descendant":
        assert snapshot([private, unreadable])["privateStatePaths"] == sorted(
            [str(private), str(unreadable)]
        )


@pytest.mark.parametrize("stage", ["scan", "publish", "dedupe"])
def test_failed_stages_resume_and_completed_results_are_immutable(workflow, stage):
    assert workflow("get") == {"workflow": None}
    bound = workflow("bind", binding={})["workflow"]
    assert bound["stages"] == {
        name: {"status": "pending"} for name in ("scan", "publish", "dedupe")
    }
    assert workflow("begin", stage=stage)["workflow"]["stages"][stage]["status"] == "running"
    failed = workflow("fail", stage=stage, error="Synthetic failure")
    assert failed["workflow"]["stages"][stage] == {"status": "failed", "error": "Synthetic failure"}
    assert workflow("begin", stage=stage)["workflow"]["stages"][stage]["status"] == "running"
    result = {"findingIds": [], "duplicateGroups": []}
    completed = workflow("complete", stage=stage, result=result)
    assert completed["workflow"]["stages"][stage] == {"status": "completed", "result": result}
    for action, payload in [
        ("begin", {}),
        ("fail", {"error": "Late failure", "result": {"unexpected": True}}),
        ("complete", {"result": {"unexpected": True}}),
    ]:
        assert workflow(action, stage=stage, **payload) == completed


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
def test_bindings_and_workflow_identities_remain_separate(workflow, workbench_db, binding, changed):
    workflow("bind", binding=binding)
    saved = workflow("complete", stage="dedupe", result={"duplicateGroups": []})
    with pytest.raises(SystemExit, match="already bound to a different"):
        workflow("bind", binding=changed)
    assert not workbench_db.in_transaction
    assert workflow("get") == saved
    separate = workflow("bind", workflow_id="separate", binding=changed)
    assert separate["workflow"]["id"] == "separate"
    assert separate["workflow"]["stages"]["dedupe"] == {"status": "pending"}
    for key, value in changed.items():
        assert separate["workflow"][key] == value
    assert workflow("get") == saved


@pytest.mark.parametrize("result", [{"duplicateGroups": []}, {"duplicateGroups": [["a", "b"]]}])
def test_pending_publication_payload_survives_failure_until_completion(workflow, result):
    workflow("bind", binding={})
    workflow("begin", stage="dedupe")
    pending = {"groups": result["duplicateGroups"]}
    prepared = workflow("prepare-dedupe", stage="dedupe", result=result, pendingWrite=pending)
    assert prepared["workflow"]["stages"]["dedupe"] == {
        "status": "running",
        "result": result,
        "pendingWrite": pending,
    }
    workflow("fail", stage="dedupe", error="Lost acknowledgement")
    resumed = workflow("begin", stage="dedupe")["workflow"]["stages"]["dedupe"]
    assert resumed["result"] == result
    assert resumed["pendingWrite"] == pending
    completed = workflow("complete", stage="dedupe", result=result)
    assert completed["workflow"]["stages"]["dedupe"] == {"status": "completed", "result": result}


def test_review_checkpoints_keep_the_first_valid_result_and_enforce_workflow_ownership(
    workflow, workbench_db
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
        workflow("save-review", key="review-1", binding=binding, result=result)
    workflow("bind", binding={})
    assert workflow("get-review", key="review-1") == {"review": None}
    workflow("save-review", key="review-1", binding=binding, result=result)
    workflow("save-review", key="review-1", binding=binding, result={"unexpected": True})
    assert workflow("get-review", key="review-1") == {"review": result}
    assert workflow("get-review", workflow_id="another", key="review-1") == {"review": None}
    row = workbench_db.execute("SELECT * FROM finding_workflow_reviews").fetchone()
    assert row["source_repository_path"] == binding["source"]["repository"]
    assert row["settings_digest"] == binding["settingsDigest"]
    assert json.loads(row["result_json"]) == result

    replacement = {"assessment": {"report": "Regenerated validation"}, "evidenceDigest": "new"}
    workflow("save-review", key="review-1", binding=binding, result=replacement, replace=True)
    assert workflow("get-review", key="review-1") == {"review": result}
    workflow(
        "save-review",
        key="review-1",
        binding={**binding, "stage": "scan-validation"},
        result=replacement,
        replace=True,
    )
    assert workflow("get-review", key="review-1") == {"review": replacement}


@pytest.mark.parametrize(
    "payload",
    [
        {"action": "bind", "binding": {"unknown": "value"}},
        {"action": "begin", "stage": "unknown"},
        {"action": "unknown", "stage": "scan"},
    ],
)
def test_rejected_workflow_mutations_roll_back_without_leaking_state(
    workflow, workbench_db, payload
):
    saved = workflow("bind", binding={})
    with pytest.raises(SystemExit):
        workflow(**payload)
    assert not workbench_db.in_transaction
    assert workflow("get") == saved


def test_workflow_column_migration_is_atomic_and_preserves_resume_state(workbench_api, tmp_path):
    database = tmp_path / "legacy.sqlite3"
    completed = {
        "id": "migrated-completed",
        "repositoryPath": str(tmp_path / "repository"),
        "scanRequestDigest": "synthetic-request-hash",
        "scanId": "synthetic-scan\0retained tail",
        "scanDir": str(tmp_path / "scan"),
        "artifactDigest": "synthetic-artifact-hash",
        "destination": "https://synthetic.invalid/",
        "scope": {"repositoryId": "synthetic-repository\0retained tail"},
        "stages": {
            "scan": {"status": "completed", "result": None},
            "publish": {
                "status": "completed",
                "result": {"findingIds": [], "legacyCounter": 2**60 + 1},
            },
            "dedupe": {"status": "completed", "result": {"duplicateGroups": []}},
        },
    }
    unfinished = {
        "id": "migrated-unfinished",
        "scope": {"allRepositories": True},
        "stages": {
            "scan": {"status": "failed", "error": "Synthetic interruption\0retained tail"},
            "publish": {"status": "running", "error": "Synthetic earlier failure\0retained tail"},
            "dedupe": {
                "status": "failed",
                "error": "Synthetic lost acknowledgement\0retained tail",
                "result": {"duplicateGroups": [["a", "b"]]},
                "pendingWrite": {"groups": [["a", "b"]]},
            },
        },
    }
    pending = {
        "id": "migrated-pending",
        "stages": {stage: {"status": "pending"} for stage in ("scan", "publish", "dedupe")},
    }
    review_binding = {
        "version": 1,
        "codexVersion": "synthetic-version",
        "source": {
            "repository": completed["repositoryPath"],
            "revision": "synthetic-revision",
            "refsDigest": "synthetic-refs",
            "content": "synthetic-content",
        },
        "scope": completed["scope"],
        "model": "synthetic-model",
        "effort": "high",
        "promptDigest": "synthetic-prompt",
        "contractDigest": "synthetic-contract",
    }
    review_result = {"decision": "DISTINCT", "rationale": "Synthetic reviewed result"}
    migrations = workbench_api["MIGRATIONS"]
    connection = sqlite3.connect(database)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")

    def migrate(history):
        workbench_api["apply_schema_migrations"](
            connection, history, lambda: TIMESTAMP, workbench_api["backfill_security_targets"]
        )

    with closing(connection):
        migrate(tuple(m for m in migrations if m[0] <= 37))
        with connection:
            for state in (completed, unfinished, pending):
                connection.execute(
                    "INSERT INTO finding_workflows VALUES (?, ?, ?, ?)",
                    (state["id"], json.dumps(state), TIMESTAMP, "2026-08-02T00:00:00Z"),
                )
            connection.execute(
                "INSERT INTO finding_workflow_reviews VALUES (?, ?, ?, ?, ?)",
                (
                    completed["id"],
                    "synthetic-review",
                    json.dumps(review_binding),
                    json.dumps(review_result),
                    TIMESTAMP,
                ),
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

    # Reopen the actual file so this remains a persistence and migration test.
    connection = sqlite3.connect(database)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    with closing(connection):
        migrated_workflow = partial(run_workflow, workbench_api, connection)
        for state in (completed, unfinished, pending):
            assert migrated_workflow("get", workflow_id=state["id"]) == {"workflow": state}
        assert migrated_workflow(
            "bind",
            workflow_id=completed["id"],
            binding={"scanId": completed["scanId"], "scope": completed["scope"]},
        ) == {"workflow": completed}
        review = connection.execute("SELECT * FROM finding_workflow_reviews").fetchone()
        assert review["scope_repository_id"] == completed["scope"]["repositoryId"]
        assert review["prompt_digest"] == review_binding["promptDigest"]
        assert migrated_workflow(
            "get-review", workflow_id=completed["id"], key="synthetic-review"
        ) == {"review": review_result}
        for stage in ("scan", "publish", "dedupe"):
            state = migrated_workflow("begin", workflow_id=completed["id"], stage=stage)
            assert state == {"workflow": completed}
        migrated_workflow("begin", workflow_id=unfinished["id"], stage="scan")
        resumed = migrated_workflow(
            "complete",
            workflow_id=unfinished["id"],
            stage="scan",
            result={"scanId": "resumed-scan"},
        )
        assert resumed["workflow"]["stages"]["scan"] == {
            "status": "completed",
            "result": {"scanId": "resumed-scan"},
        }


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFOs require a Unix filesystem")
def test_optional_review_snapshot_disables_cache_for_unsupported_file_types(workflow, tmp_path):
    target = tmp_path / "repository"
    target.mkdir()
    source = target / "source.ts"
    source.write_text("export const value = 1;\n", encoding="utf-8")
    first = workflow("source", repository=str(target))
    assert first["source"]["content"].startswith("codex-security-snapshot/v1:")
    pipe = target / "pipe"
    os.mkfifo(pipe)
    with pytest.raises(SystemExit, match="Unsupported local file type: pipe"):
        workflow("source", repository=str(target))
    assert workflow("source", repository=str(target), optional=True) == {"source": None}
    pipe.unlink()
    assert workflow("source", repository=str(target), optional=True) == first
    source.write_text("export const value = 2;\n", encoding="utf-8")
    assert (
        workflow("source", repository=str(target), optional=True)["source"]["content"]
        != first["source"]["content"]
    )
    with pytest.raises(FileNotFoundError):
        workflow("source", repository=str(target / "missing"), optional=True)


@pytest.mark.skipif(
    os.name == "nt" or getattr(os, "geteuid", lambda: 0)() == 0,
    reason="Mode permissions require a non-root Unix user",
)
@pytest.mark.parametrize("kind", ["file", "directory"])
def test_optional_review_snapshot_disables_cache_for_unreadable_entries(workflow, tmp_path, kind):
    target = tmp_path / "repository"
    target.mkdir()
    (target / "source.ts").write_text("export const value = 1;\n", encoding="utf-8")
    entry = target / "ignored-cache"
    if kind == "directory":
        entry.mkdir()
        (entry / "cache.txt").write_text("Synthetic cache data.", encoding="utf-8")
    else:
        entry.write_text("Synthetic cache data.", encoding="utf-8")
    first = workflow("source", repository=str(target), optional=True)
    mode = entry.stat().st_mode
    entry.chmod(0)
    try:
        with pytest.raises((PermissionError, SystemExit)):
            workflow("source", repository=str(target))
        assert workflow("source", repository=str(target), optional=True) == {"source": None}
    finally:
        entry.chmod(mode)
    assert workflow("source", repository=str(target), optional=True) == first
    with pytest.raises(FileNotFoundError):
        workflow("source", repository=str(target / "missing"), optional=True)


@pytest.mark.parametrize("metadata_name", [".git", ".svn"])
def test_optional_evidence_snapshot_includes_source_metadata(workflow, tmp_path, metadata_name):
    evidence = tmp_path / "evidence"
    metadata = evidence / metadata_name
    metadata.mkdir(parents=True)
    (evidence / "proof.txt").write_text("Original proof.\n")
    head = metadata / "HEAD"
    head.write_text("Synthetic metadata.\n")
    source = workflow("source", repository=str(evidence))
    before = workflow("source", repository=str(evidence), evidence=True, optional=True)
    head.write_text("Changed metadata.\n")
    assert workflow("source", repository=str(evidence)) == source
    assert workflow("source", repository=str(evidence), evidence=True, optional=True) != before
    if hasattr(os, "mkfifo"):
        pipe = metadata / "pipe"
        os.mkfifo(pipe)
        try:
            assert workflow("source", repository=str(evidence), evidence=True, optional=True) == {
                "source": None
            }
        finally:
            pipe.unlink()


def test_optional_evidence_snapshot_does_not_follow_directory_links(workflow, tmp_path):
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    source = outside / "proof.txt"
    source.write_text("Outside contents.\n")
    linked = evidence / "linked"
    try:
        linked.symlink_to(outside, target_is_directory=True)
    except OSError:
        if os.name == "nt":
            pytest.skip("Directory symlinks are unavailable on this Windows filesystem")
        raise
    before = workflow("source", repository=str(evidence), evidence=True, optional=True)
    source.write_text("Changed outside contents.\n")
    assert workflow("source", repository=str(evidence), evidence=True, optional=True) == before
    evidence.rename(tmp_path / "original")
    evidence.symlink_to(outside, target_is_directory=True)
    assert workflow("source", repository=str(evidence), evidence=True, optional=True) == {
        "source": None
    }


@pytest.mark.parametrize("kind", ["missing", "file", "unreadable"])
def test_optional_evidence_snapshot_unavailable_roots(workflow, tmp_path, kind):
    evidence = tmp_path / "evidence"
    if kind == "file":
        evidence.write_text("Not a directory.\n")
    if kind == "unreadable":
        if os.name == "nt" or getattr(os, "geteuid", lambda: 0)() == 0:
            pytest.skip("Mode permissions require a non-root Unix user")
        evidence.mkdir()
        evidence.chmod(0)
    try:
        assert workflow("source", repository=str(evidence), evidence=True, optional=True) == {
            "source": None
        }
        if kind == "missing":
            with pytest.raises(FileNotFoundError):
                workflow("source", repository=str(evidence), optional=True)
    finally:
        if kind == "unreadable":
            evidence.chmod(0o700)
