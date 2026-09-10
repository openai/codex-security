from __future__ import annotations

import argparse
import json
import sqlite3
import uuid
from dataclasses import fields
from pathlib import Path

import pytest
from test_workbench_scan_checkpoints import save, scan_fixture, semantic
from workbench_test_support import run_workbench, write_checkpoint


@pytest.fixture(autouse=True)
def configure_deep(workbench_api):
    deep = workbench_api["deep_scan"]
    deep.configure(
        deep.DeepScanDependencies(
            **{
                field.name: workbench_api[
                    "preserve_stopped_results_after_transition"
                    if field.name == "preserve_stopped_results"
                    else field.name
                ]
                for field in fields(deep.DeepScanDependencies)
            }
        )
    )


def completed_deep_fixture(tmp_path: Path):
    state, repository, parent_dir, parent_id = scan_fixture(tmp_path, "deep")
    save(state, parent_id, write_checkpoint(parent_dir / "checkpoints", semantic(parent_id, [])))
    recipe = run_workbench(state, "get-scan-recipe", "--scan-id", parent_id)["recipe"]
    child_dir = tmp_path / "child"
    child_dir.mkdir(mode=0o700)
    child_id = run_workbench(
        state,
        "register-cli-scan",
        "--repository",
        str(repository),
        "--scan-dir",
        str(child_dir),
        "--recipe-json",
        json.dumps(recipe),
        "--parent-scan-id",
        parent_id,
    )["scanId"]
    worker_ids = [str(uuid.uuid4()) for _ in range(5)]
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute(
            "INSERT INTO deep_scan_runs (scan_id, schema_version, workflow_version, status, phase, "
            "workers, subagents, stop_after_no_new, max_discovery_runs, discovery_runs_dispatched, "
            "completion_sequence, created_at, updated_at) "
            "VALUES (?, 1, 'deep-security-scan/v1', 'failed', 'terminal', 2, 0, 2, 5, 4, 3, ?, ?)",
            (parent_id, "2026-01-01T00:00:00Z", "2026-01-01T01:00:00Z"),
        )
        for index, worker_id in enumerate(worker_ids):
            reducer = index == 4
            name = "dedup-0001" if reducer else f"discovery-{index + 1:04d}"
            directory = (
                parent_dir
                / "artifacts"
                / "deep_discovery"
                / ("dedup" if reducer else "workers")
                / name
            )
            output = directory / "output"
            output.mkdir(parents=True)
            prompt = directory / "prompt.md"
            prompt.write_text(f"Paid prompt for {name}\n")
            result = semantic(parent_id, [])
            result["complete"] = True
            if reducer:
                result["findings"] = [
                    {
                        "summary": worker_ids[0],
                        "provenance": {
                            "sourceFindingIds": [f"{worker_ids[0]}:0"],
                            "sourceFindings": [
                                {"id": f"{worker_ids[0]}:0", "finding": {"provenance": {}}}
                            ],
                        },
                    }
                ]
            (output / "result.json").write_text(json.dumps(result))
            (output / "evidence.txt").write_text("Saved evidence\n")
            (output / "checkpoints").mkdir()
            (output / "checkpoints" / "old.json").write_text(json.dumps(result))
            (output / "checkpoint-head.json").write_text('{"checkpoint":"old.json"}')
            connection.execute(
                "INSERT INTO deep_scan_workers (id, scan_id, kind, status, merge_state, prompt_path, "
                "artifact_dir, result_manifest_path, attempt, sdk_thread_id, completion_sequence, "
                "created_at, updated_at, completed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?)",
                (
                    worker_id,
                    parent_id,
                    "dedup" if reducer else "discovery",
                    "failed" if index == 3 else "succeeded",
                    "none" if reducer or index == 3 else ("merged" if index < 2 else "merging"),
                    str(prompt),
                    str(output),
                    str(output / "result.json"),
                    f"thread-{index}",
                    None if reducer or index == 3 else index + 1,
                    "2026-01-01T00:00:00Z",
                    "2026-01-01T01:00:00Z",
                    "2026-01-01T01:00:00Z",
                ),
            )
        connection.executemany(
            "INSERT INTO deep_scan_dedup_inputs VALUES (?, ?, ?, ?)",
            [(parent_id, worker_ids[4], worker_ids[index], index) for index in range(2)],
        )
    return state, parent_dir, parent_id, child_dir, child_id, worker_ids


def test_deep_continuation_restores_paid_workers_and_reducer_inputs(tmp_path: Path, workbench_api):
    state, parent_dir, parent_id, child_dir, child_id, workers = completed_deep_fixture(tmp_path)
    original = {
        p.relative_to(parent_dir): p.read_bytes() for p in parent_dir.rglob("*") if p.is_file()
    }
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        parent = connection.execute("SELECT * FROM scans WHERE id = ?", (parent_id,)).fetchone()
        child = connection.execute("SELECT * FROM scans WHERE id = ?", (child_id,)).fetchone()
        deep = workbench_api["deep_scan"]
        mapping = deep.restore_checkpoint_workers(connection, parent, child, "2026-01-01T02:00:00Z")
        assert (
            deep.restore_checkpoint_workers(connection, parent, child, "2026-01-01T02:00:01Z")
            == mapping
        )
        run = connection.execute(
            "SELECT * FROM deep_scan_runs WHERE scan_id = ?", (child_id,)
        ).fetchone()
        assert run["discovery_runs_dispatched"] == 3
        assert run["completion_sequence"] == 3
        assert run["created_at"] == "2026-01-01T00:00:00Z"
        assert run["max_discovery_runs"] == 5
        assert not deep.coordinator_lease_is_live(connection, run, child, "2026-01-01T02:00:00Z")
        restored = connection.execute(
            "SELECT * FROM deep_scan_workers WHERE scan_id = ? ORDER BY kind, completion_sequence",
            (child_id,),
        ).fetchall()
        assert len(restored) == 4
        assert workers[3] not in mapping
        assert [row["merge_state"] for row in restored if row["kind"] == "discovery"] == [
            "merged",
            "merged",
            "buffered",
        ]
        inputs = connection.execute(
            "SELECT * FROM deep_scan_dedup_inputs WHERE scan_id = ? ORDER BY input_order",
            (child_id,),
        ).fetchall()
        assert [row["discovery_worker_id"] for row in inputs] == [
            mapping[workers[0]],
            mapping[workers[1]],
        ]
        for row in restored:
            result = json.loads(Path(row["result_manifest_path"]).read_text())
            assert result["scanId"] == child_id
            assert Path(row["prompt_path"]).read_text().startswith("Paid prompt")
            output = Path(row["artifact_dir"])
            assert (output / "evidence.txt").read_text() == "Saved evidence\n"
            assert not (output / "checkpoints").exists()
            assert not (output / "checkpoint-head.json").exists()
            if row["kind"] == "dedup":
                finding = result["findings"][0]
                assert finding["summary"] == workers[0]
                assert finding["provenance"]["sourceFindingIds"] == [f"{mapping[workers[0]]}:0"]
                assert (
                    finding["provenance"]["sourceFindings"][0]["id"] == f"{mapping[workers[0]]}:0"
                )
    assert original == {
        p.relative_to(parent_dir): p.read_bytes() for p in parent_dir.rglob("*") if p.is_file()
    }


def test_failed_deep_artifact_copy_does_not_record_completed_child_workers(
    tmp_path: Path, workbench_api
):
    state, parent_dir, parent_id, _, child_id, _ = completed_deep_fixture(tmp_path)
    # A worker artifact can contain links; it must not read outside the bound scan.
    artifact = parent_dir / "artifacts/deep_discovery/dedup/dedup-0001/output/evidence.txt"
    artifact.unlink()
    artifact.symlink_to(tmp_path / "outside.txt")
    (tmp_path / "outside.txt").write_text("Outside the scan\n")
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.row_factory = sqlite3.Row
        parent = connection.execute("SELECT * FROM scans WHERE id = ?", (parent_id,)).fetchone()
        child = connection.execute("SELECT * FROM scans WHERE id = ?", (child_id,)).fetchone()
        with pytest.raises((SystemExit, ValueError)):
            workbench_api["deep_scan"].restore_checkpoint_workers(
                connection, parent, child, "2026-01-01T02:00:00Z"
            )
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM deep_scan_runs WHERE scan_id = ?", (child_id,)
            ).fetchone()[0]
            == 0
        )
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM deep_scan_workers WHERE scan_id = ?", (child_id,)
            ).fetchone()[0]
            == 0
        )


def test_continue_command_restores_deep_units_before_starting_a_new_coordinator(tmp_path: Path):
    state, parent_dir, parent_id, _, child_id, _ = completed_deep_fixture(tmp_path)
    reducer = parent_dir / "artifacts/deep_discovery/dedup/dedup-0001/output/result.json"
    payload = json.loads(reducer.read_text())
    payload["findings"] = []
    reducer.write_text(json.dumps(payload))
    # Workers from before automatic checkpointing still have accepted result files.
    for head in parent_dir.glob("artifacts/deep_discovery/*/*/output/checkpoint-head.json"):
        head.unlink()
        (head.parent / "checkpoints" / "old.json").unlink()
    continued = run_workbench(
        state,
        "continue-scan-checkpoint",
        "--scan-id",
        child_id,
        "--parent-scan-id",
        parent_id,
        "--cost-json",
        json.dumps(
            {
                "model": "test-model",
                "inputTokens": 100,
                "outputTokens": 10,
                "cachedInputTokens": 0,
                "cacheWriteInputTokens": 0,
                "estimatedUsd": 2.5,
            }
        ),
    )
    assert continued["restoredWorkers"] == 4
    assert not continued["completionReady"]
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        assert connection.execute(
            "SELECT discovery_runs_dispatched FROM deep_scan_runs WHERE scan_id = ?", (child_id,)
        ).fetchone() == (3,)
        assert connection.execute(
            "SELECT COUNT(*) FROM deep_scan_dedup_inputs WHERE scan_id = ?", (child_id,)
        ).fetchone() == (2,)
        assert connection.execute(
            "SELECT status FROM scans WHERE id = ?", (parent_id,)
        ).fetchone() == ("failed",)


def test_deep_continuation_rejects_a_changed_frozen_worker_result(tmp_path: Path, workbench_api):
    state, parent_dir, parent_id, _, child_id, _ = completed_deep_fixture(tmp_path)
    relative = "artifacts/deep_discovery/workers/discovery-0001/output/result.json"
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.row_factory = sqlite3.Row
        connection.execute(
            "UPDATE scans SET retained_source_digests_json = ? WHERE id = ?",
            (json.dumps({relative: "0" * 64}), parent_id),
        )
        parent = connection.execute("SELECT * FROM scans WHERE id = ?", (parent_id,)).fetchone()
        child = connection.execute("SELECT * FROM scans WHERE id = ?", (child_id,)).fetchone()
        with pytest.raises(SystemExit, match="changed after the scan stopped"):
            workbench_api["deep_scan"].restore_checkpoint_workers(
                connection, parent, child, "2026-01-01T02:00:00Z"
            )
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM deep_scan_runs WHERE scan_id = ?", (child_id,)
            ).fetchone()[0]
            == 0
        )
    assert (parent_dir / relative).is_file()


def test_unfinished_worker_checkpoint_survives_first_and_repeated_coordinator_claim(
    tmp_path: Path, workbench_api, monkeypatch
):
    state, parent_dir, parent_id, child_dir, child_id, workers = completed_deep_fixture(tmp_path)
    reducer = parent_dir / "artifacts/deep_discovery/dedup/dedup-0001/output/result.json"
    document = json.loads(reducer.read_text())
    document["findings"] = []
    reducer.write_text(json.dumps(document))
    for head in parent_dir.glob("artifacts/deep_discovery/*/*/output/checkpoint-head.json"):
        head.unlink()
        (head.parent / "checkpoints" / "old.json").unlink()
    pending_root = parent_dir / "artifacts/deep_discovery/workers/discovery-0004/output"
    save(
        state,
        parent_id,
        write_checkpoint(pending_root / "checkpoints", semantic(parent_id, ["clean.ts"])),
    )
    continued = run_workbench(
        state, "continue-scan-checkpoint", "--scan-id", child_id, "--parent-scan-id", parent_id
    )
    assert continued["restoredWorkers"] == 5
    worker_id = str(uuid.uuid5(uuid.UUID(child_id), workers[3]))
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.row_factory = sqlite3.Row
        worker = connection.execute(
            "SELECT * FROM deep_scan_workers WHERE id = ?", (worker_id,)
        ).fetchone()
        assert worker["status"] == "queued"
        assert worker["started_at"] is None
        assert worker["sdk_thread_id"] is None
        assert worker["result_manifest_path"] is None
        assert worker["completion_sequence"] is None
        assert worker["attempt"] == 0
        head = json.loads((Path(worker["artifact_dir"]) / "checkpoint-head.json").read_text())
        snapshot = json.loads(
            (Path(worker["artifact_dir"]) / "checkpoints" / head["checkpoint"]).read_text()
        )
        assert snapshot["complete"] is False
        assert snapshot["coverage"]["reviewedFiles"] == ["clean.ts"]
        assert snapshot["coverage"]["deferred"][0]["provenance"]["workerId"] == worker_id
        assert not (Path(worker["artifact_dir"]) / "result.json").exists()
        connection.execute(
            "UPDATE scans SET deep_scan_owner_thread_id = ?, handoff_status = 'delivered' WHERE id = ?",
            ("fixture-owner", child_id),
        )
    claimed = run_workbench(
        state, "claim-deep-scan-coordinator", "--scan-id", child_id, "--thread-id", "fixture-owner"
    )
    assert claimed["coordinatorDisposition"] == "claimed"
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        assert connection.execute(
            "SELECT status FROM deep_scan_workers WHERE id = ?", (worker_id,)
        ).fetchone() == ("queued",)
        connection.execute(
            "UPDATE deep_scan_workers SET status = 'running', attempt = 2, started_at = '2026-01-01T02:00:00Z', sdk_thread_id = 'interrupted-worker-thread' WHERE id = ?",
            (worker_id,),
        )
        connection.execute(
            "UPDATE deep_scan_runs SET updated_at = '2026-01-01T02:00:00Z' WHERE scan_id = ?",
            (child_id,),
        )
    old_output = Path(worker["artifact_dir"])
    old_prompt = Path(worker["prompt_path"])
    prompt_attempt = old_prompt.parent / "prompts" / "attempt-02.md"
    prompt_attempt.parent.mkdir()
    prompt_attempt.write_text("Saved attempt instructions\n")
    archive = old_output.parent / "attempts" / "attempt-02" / "checkpoints"
    archive.mkdir(parents=True)
    original_checkpoint = old_output / "checkpoints" / head["checkpoint"]
    original_contents = original_checkpoint.read_bytes()
    original_checkpoint.rename(archive / original_checkpoint.name)
    (old_output / "result.json.lock").write_text("held by expired writer")
    (old_output / "checkpoint-head.json.lock").write_text("held by expired writer")
    writer_temporary = f".{uuid.uuid4()}.tmp"
    (old_output / writer_temporary).write_text("incomplete atomic write")
    (old_output / "example.lock").write_text("Saved lock-file evidence")
    (old_output / ".example.tmp").write_text("Saved temporary-file evidence")
    threat_model = Path("artifacts/01_context/threat_model.md")
    (old_output / threat_model).parent.mkdir(parents=True, exist_ok=True)
    (old_output / threat_model).write_text("Saved threat model")
    (old_output / threat_model.with_suffix(".md.lock")).write_text("held by expired writer")
    (old_output / "result.json").write_text(json.dumps(snapshot))
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        original_receipts = connection.execute(
            "SELECT * FROM scan_checkpoints WHERE scan_id = ? ORDER BY sequence", (child_id,)
        ).fetchall()
    deep = workbench_api["deep_scan"]
    original_isolate = deep.isolate_checkpoint_worker

    def interrupted_rotation(*args):
        original_isolate(*args)
        raise OSError("interrupted after copying the replacement")

    # A failed claim must leave both the coordinator generation and accepted
    # source ownership unchanged, even when destination files were already copied.
    with monkeypatch.context() as patch:
        patch.setattr(deep, "isolate_checkpoint_worker", interrupted_rotation)
        with sqlite3.connect(state / "workbench.sqlite3") as connection:
            connection.row_factory = sqlite3.Row
            with pytest.raises(OSError, match="interrupted after copying"):
                deep.claim_deep_scan_coordinator(
                    connection,
                    argparse.Namespace(
                        scan_id=child_id,
                        thread_id="fixture-owner",
                        claim_token=None,
                        coordinator_generation=None,
                    ),
                )
            assert connection.execute(
                "SELECT artifact_dir FROM deep_scan_workers WHERE id = ?", (worker_id,)
            ).fetchone()[0] == str(old_output)
            assert [
                tuple(row)
                for row in connection.execute(
                    "SELECT * FROM scan_checkpoints WHERE scan_id = ? ORDER BY sequence",
                    (child_id,),
                )
            ] == original_receipts
    reclaimed = run_workbench(
        state, "claim-deep-scan-coordinator", "--scan-id", child_id, "--thread-id", "fixture-owner"
    )
    assert reclaimed["coordinatorDisposition"] == "adopted"
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.row_factory = sqlite3.Row
        replacement = connection.execute(
            "SELECT * FROM deep_scan_workers WHERE id = ?", (worker_id,)
        ).fetchone()
        assert replacement["artifact_dir"] != str(old_output)
        assert Path(replacement["artifact_dir"]).name == "output"
        assert Path(replacement["prompt_path"]).parent == Path(replacement["artifact_dir"]).parent
        worker_receipts = connection.execute(
            "SELECT * FROM scan_checkpoints WHERE scan_id = ? ORDER BY sequence", (child_id,)
        ).fetchall()
        for before, after in zip(original_receipts, worker_receipts, strict=True):
            assert tuple(after)[:2] == before[:2]
            assert tuple(after)[4:] == before[4:]
        connection.row_factory = None
        assert connection.execute(
            "SELECT status, attempt, completion_sequence FROM deep_scan_workers WHERE id = ?",
            (worker_id,),
        ).fetchone() == ("queued", 2, None)
        assert connection.execute(
            "SELECT discovery_runs_dispatched, completion_sequence FROM deep_scan_runs WHERE scan_id = ?",
            (child_id,),
        ).fetchone() == (4, 3)
        assert connection.execute(
            "SELECT COUNT(*) FROM deep_scan_workers WHERE scan_id = ?", (child_id,)
        ).fetchone() == (5,)
    run_workbench(
        state,
        "upsert-deep-scan-worker",
        "--scan-id",
        child_id,
        "--worker-id",
        worker_id,
        "--kind",
        "discovery",
        "--status",
        "running",
        "--prompt-path",
        replacement["prompt_path"],
        "--artifact-dir",
        replacement["artifact_dir"],
        "--attempt",
        "3",
        "--coordinator-generation",
        str(reclaimed["deepScan"]["coordinatorGeneration"]),
    )
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        assert connection.execute(
            "SELECT status, attempt, prompt_path, artifact_dir FROM deep_scan_workers WHERE id = ?",
            (worker_id,),
        ).fetchone() == ("running", 3, replacement["prompt_path"], replacement["artifact_dir"])
        assert connection.execute(
            "SELECT discovery_runs_dispatched, completion_sequence FROM deep_scan_runs WHERE scan_id = ?",
            (child_id,),
        ).fetchone() == (4, 3)
    assert (
        child_dir / "artifacts/deep_discovery/workers/discovery-0004/output/checkpoint-head.json"
    ).is_file()
    output = Path(replacement["artifact_dir"])
    assert not (output / "result.json").exists()
    assert not (output / "result.json.lock").exists()
    assert not (output / "checkpoint-head.json.lock").exists()
    assert not (output / writer_temporary).exists()
    assert (output / "example.lock").read_text() == "Saved lock-file evidence"
    assert (output / ".example.tmp").read_text() == "Saved temporary-file evidence"
    assert (output / threat_model).read_text() == "Saved threat model"
    assert not (output / threat_model.with_suffix(".md.lock")).exists()
    assert (output.parent / "prompts" / "attempt-02.md").read_bytes() == prompt_attempt.read_bytes()
    assert json.loads((output / "checkpoint-head.json").read_text()) == head
    assert (output / "checkpoints" / head["checkpoint"]).read_bytes() == original_contents
    # Replaying the relocated head must not manufacture another acceptance.
    run_workbench(state, "get-cli-scan-resume", "--scan-id", child_id)
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM scan_checkpoints WHERE scan_id = ?", (child_id,)
        ).fetchone()[0] == len(original_receipts)

    current = json.loads(original_contents)
    current["coverage"]["deferred"] = []
    current["coverage"]["surfaces"] = [
        {
            "candidateId": "candidate-1",
            "disposition": "rejected",
            "reason": "Validated by the replacement worker.",
            "provenance": {"workerId": worker_id},
        }
    ]
    save(state, child_id, write_checkpoint(output / "checkpoints", current))
    (output / "result.json").write_text(json.dumps(current))
    replacement_head = (output / "checkpoint-head.json").read_bytes()
    expired = json.loads(original_contents)
    expired["coverage"]["deferred"][0]["candidateId"] = "expired-only"
    expired_path = write_checkpoint(old_output / "checkpoints", expired)
    (old_output / "result.json").write_text(json.dumps(expired))
    failed = save(state, child_id, expired_path, check=False)
    assert "registered scan worker" in failed["stderr"]
    assert (output / "checkpoint-head.json").read_bytes() == replacement_head
    assert json.loads((output / "result.json").read_text()) == current

    grandchild = tmp_path / "grandchild"
    grandchild.mkdir(mode=0o700)
    recipe = run_workbench(state, "get-scan-recipe", "--scan-id", child_id)["recipe"]
    grandchild_id = run_workbench(
        state,
        "register-cli-scan",
        "--repository",
        str(tmp_path / "repository"),
        "--scan-dir",
        str(grandchild),
        "--recipe-json",
        json.dumps(recipe),
        "--parent-scan-id",
        child_id,
    )["scanId"]
    run_workbench(
        state,
        "continue-scan-checkpoint",
        "--scan-id",
        grandchild_id,
        "--parent-scan-id",
        child_id,
    )
    assert "expired-only" not in (grandchild / "coverage.json").read_text()
    assert "Validated by the replacement worker." in (grandchild / "coverage.json").read_text()


@pytest.mark.parametrize(("indexed", "archived"), [(True, False), (True, True), (False, False)])
def test_coordinator_adoption_replays_a_head_written_before_its_receipt_committed(
    tmp_path: Path, workbench_api, monkeypatch, indexed: bool, archived: bool
):
    state, root, scan_id, _, _, workers = completed_deep_fixture(tmp_path)
    worker_id = workers[3]
    output = root / "artifacts/deep_discovery/workers/discovery-0004/output"
    for head in root.glob("artifacts/deep_discovery/*/*/output/checkpoint-head.json"):
        head.unlink()
        (head.parent / "checkpoints" / "old.json").unlink()
    if indexed:
        save(state, scan_id, write_checkpoint(output / "checkpoints", semantic(scan_id, [])))
    newest = semantic(scan_id, [])
    newest["coverage"]["deferred"][0]["candidateId"] = "newest-saved-candidate"
    checkpoint = write_checkpoint(output / "checkpoints", newest)
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.row_factory = sqlite3.Row
        scan = connection.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        accepted = workbench_api["scan_checkpoints"].record_checkpoint(
            connection, scan, checkpoint, "2026-01-01T02:00:00Z", commit=False
        )
        connection.rollback()
        connection.execute(
            "UPDATE scans SET deep_scan_owner_thread_id = 'fixture-owner', handoff_status = 'delivered' WHERE id = ?",
            (scan_id,),
        )
        connection.execute(
            "UPDATE deep_scan_runs SET status = 'running', phase = 'discovery', coordinator_generation = 2, updated_at = '2026-01-01T02:00:00Z' WHERE scan_id = ?",
            (scan_id,),
        )
        connection.execute(
            "UPDATE deep_scan_workers SET status = 'running', attempt = 2, completion_sequence = NULL, completed_at = NULL, error_message = NULL WHERE id = ?",
            (worker_id,),
        )
    original_head = json.loads((output / "checkpoint-head.json").read_text())
    assert original_head["acceptanceId"] == accepted["acceptanceId"]
    if archived:
        archive = output.parent / "attempts" / "attempt-02" / "checkpoints"
        archive.mkdir(parents=True)
        checkpoint.rename(archive / checkpoint.name)

    deep = workbench_api["deep_scan"]
    original_isolate = deep.isolate_checkpoint_worker

    def interrupted_rotation(*args):
        original_isolate(*args)
        raise OSError("interrupted after receipt replay")

    with monkeypatch.context() as patch:
        patch.setattr(deep, "isolate_checkpoint_worker", interrupted_rotation)
        with sqlite3.connect(state / "workbench.sqlite3") as connection:
            connection.row_factory = sqlite3.Row
            with pytest.raises(OSError, match="interrupted after receipt replay"):
                deep.claim_deep_scan_coordinator(
                    connection,
                    argparse.Namespace(
                        scan_id=scan_id,
                        thread_id="fixture-owner",
                        claim_token=None,
                        coordinator_generation=None,
                    ),
                )
            assert (
                connection.execute(
                    "SELECT COUNT(*) FROM scan_checkpoints WHERE acceptance_id = ?",
                    (accepted["acceptanceId"],),
                ).fetchone()[0]
                == 0
            )
            assert connection.execute(
                "SELECT artifact_dir FROM deep_scan_workers WHERE id = ?", (worker_id,)
            ).fetchone()[0] == str(output)

    for generation in (3, 4):
        result = run_workbench(
            state,
            "claim-deep-scan-coordinator",
            "--scan-id",
            scan_id,
            "--thread-id",
            "fixture-owner",
        )
        assert result["coordinatorDisposition"] == "adopted"
        assert result["deepScan"]["coordinatorGeneration"] == generation
        worker = next(row for row in result["deepScan"]["workers"] if row["id"] == worker_id)
        replacement = Path(worker["artifactDir"])
        assert replacement != output
        assert json.loads((replacement / "checkpoint-head.json").read_text()) == original_head
        assert json.loads((replacement / "checkpoints" / checkpoint.name).read_text()) == newest
        run_workbench(state, "get-cli-scan-resume", "--scan-id", scan_id)
        with sqlite3.connect(state / "workbench.sqlite3") as connection:
            receipt = connection.execute(
                "SELECT sequence, content_sha256, snapshot_json, recorded_at, acceptance_id "
                "FROM scan_checkpoints WHERE acceptance_id = ?",
                (accepted["acceptanceId"],),
            ).fetchall()
            assert len(receipt) == 1
            if generation == 3:
                original_receipt = receipt
            else:
                assert receipt == original_receipt
            connection.execute(
                "UPDATE deep_scan_runs SET updated_at = '2026-01-01T02:00:00Z' WHERE scan_id = ?",
                (scan_id,),
            )
        output = replacement


def test_checkpoint_rebind_preserves_nested_source_owners(workbench_api):
    document = {
        "scanId": "parent-scan",
        "findings": [
            {
                "provenance": {
                    "workerId": "claimed-worker",
                    "sourceFindingIds": ["original-worker:0"],
                    "sourceFindings": [
                        {
                            "id": "original-worker:0",
                            "finding": {
                                "provenance": {
                                    "workerId": "original-worker",
                                    "previousFindings": [
                                        {"provenance": {"workerId": "earlier-worker"}}
                                    ],
                                }
                            },
                        }
                    ],
                },
            }
        ],
        "coverage": {
            "deferred": [
                {
                    "candidateId": "candidate-1",
                    "provenance": {"workerId": "claimed-worker"},
                }
            ]
        },
    }
    result = workbench_api["deep_scan"].rebind_checkpoint_result(
        document,
        "child-scan",
        {
            "registered-worker": "new-worker",
            "original-worker": "new-original",
            "earlier-worker": "new-earlier",
        },
        source_worker_id="registered-worker",
    )
    provenance = result["findings"][0]["provenance"]
    assert provenance["workerId"] == "new-worker"
    assert result["coverage"]["deferred"][0]["provenance"]["workerId"] == "new-worker"
    original = provenance["sourceFindings"][0]
    assert original["id"] == "new-original:0"
    assert provenance["sourceFindingIds"] == [original["id"]]
    assert original["finding"]["provenance"]["workerId"] == "new-original"
    assert (
        original["finding"]["provenance"]["previousFindings"][0]["provenance"]["workerId"]
        == "new-earlier"
    )
    assert document["findings"][0]["provenance"]["workerId"] == "claimed-worker"


@pytest.mark.parametrize(
    "outcome",
    [
        "deadline",
        "reported",
        "rejected",
        "other_worker",
        "grandchild",
        "accepted_partial",
        "archived_partial",
        "rejected_partial",
        "unaccepted_partial",
        "completed_partial",
        "root_accepted_partial",
        "root_rejected_partial",
    ],
)
def test_deep_finalization_accounts_for_inherited_partial_worker_evidence(
    tmp_path: Path, outcome: str
):
    from workbench_test_support import write_completed_contract

    state, repository, parent_dir, parent_id = scan_fixture(tmp_path, "deep")
    contract = tmp_path / "contract"
    contract.mkdir()
    write_completed_contract(contract, parent_id, repository, relative_path="clean.ts")
    finding = json.loads((contract / "findings.json").read_text())["findings"][0]
    finding["extensions"] = {"candidateId": "saved-candidate"}
    partial = semantic(parent_id, ["clean.ts"])
    partial["findings"] = [finding]
    partial["coverage"]["deferred"] = [
        {"candidateId": "saved-candidate", "reason": "Finish saved validation"}
    ]
    worker_id = str(uuid.uuid4())
    output = parent_dir / "artifacts/deep_discovery/workers/discovery-0001/output"
    output.mkdir(parents=True)
    prompt = output.parent / "prompt.md"
    prompt.write_text("Saved independent review\n")
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.execute(
            "INSERT INTO deep_scan_runs (scan_id, schema_version, workflow_version, status, phase, "
            "workers, subagents, stop_after_no_new, max_discovery_runs, discovery_runs_dispatched, "
            "created_at, updated_at) VALUES (?, 1, 'deep-security-scan/v1', 'failed', 'terminal', "
            "1, 0, 2, 3, 1, '2026-01-01T00:00:00Z', '2026-01-01T01:00:00Z')",
            (parent_id,),
        )
        connection.execute(
            "INSERT INTO deep_scan_workers (id, scan_id, kind, status, prompt_path, artifact_dir, "
            "created_at, updated_at) VALUES (?, ?, 'discovery', 'failed', ?, ?, "
            "'2026-01-01T00:00:00Z', '2026-01-01T01:00:00Z')",
            (worker_id, parent_id, str(prompt), str(output)),
        )
    source = write_checkpoint(output / "checkpoints", partial)
    save(state, parent_id, source)
    original = source.read_bytes()
    other_worker_id = str(uuid.uuid4())
    if outcome in {"other_worker", "grandchild"}:
        other_output = output.parent.parent / "discovery-0002" / "output"
        other_output.mkdir(parents=True)
        other_prompt = other_output.parent / "prompt.md"
        other_prompt.write_text("A separate independent review\n")
        with sqlite3.connect(state / "workbench.sqlite3") as connection:
            connection.execute(
                "INSERT INTO deep_scan_workers (id, scan_id, kind, status, prompt_path, artifact_dir, "
                "created_at, updated_at) VALUES (?, ?, 'discovery', 'failed', ?, ?, "
                "'2026-01-01T00:00:00Z', '2026-01-01T01:00:00Z')",
                (other_worker_id, parent_id, str(other_prompt), str(other_output)),
            )
        other = semantic(parent_id, ["pending.ts"])
        other["coverage"]["deferred"] = [
            {
                "candidateId": "saved-candidate",
                "reason": "A different worker still needs to validate a different control",
                "provenance": {"workerId": worker_id},
            }
        ]
        save(state, parent_id, write_checkpoint(other_output / "checkpoints", other))
    recipe = run_workbench(state, "get-scan-recipe", "--scan-id", parent_id)["recipe"]
    child_dir = tmp_path / "child"
    child_dir.mkdir(mode=0o700)
    child_id = run_workbench(
        state,
        "register-cli-scan",
        "--repository",
        str(repository),
        "--scan-dir",
        str(child_dir),
        "--recipe-json",
        json.dumps(recipe),
        "--parent-scan-id",
        parent_id,
    )["scanId"]
    continued = run_workbench(
        state, "continue-scan-checkpoint", "--scan-id", child_id, "--parent-scan-id", parent_id
    )
    assert continued["restoredWorkers"] == (2 if outcome in {"other_worker", "grandchild"} else 1)
    worker_id = str(uuid.uuid5(uuid.UUID(child_id), worker_id))
    other_worker_id = str(uuid.uuid5(uuid.UUID(child_id), other_worker_id))
    finding = continued["checkpoint"]["sources"][0]["findings"][0]
    assert finding["provenance"]["workerId"] == worker_id
    if outcome in {"other_worker", "grandchild"}:
        assert {
            item["provenance"]["workerId"]
            for item in continued["checkpoint"]["sources"][0]["coverage"]["deferred"]
        } == {worker_id, other_worker_id}
    if outcome == "grandchild":
        grandchild_dir = tmp_path / "grandchild"
        grandchild_dir.mkdir(mode=0o700)
        grandchild_id = run_workbench(
            state,
            "register-cli-scan",
            "--repository",
            str(repository),
            "--scan-dir",
            str(grandchild_dir),
            "--recipe-json",
            json.dumps(recipe),
            "--parent-scan-id",
            child_id,
        )["scanId"]
        grandchild = run_workbench(
            state,
            "continue-scan-checkpoint",
            "--scan-id",
            grandchild_id,
            "--parent-scan-id",
            child_id,
        )
        assert grandchild["restoredWorkers"] == 2
        worker_id = str(uuid.uuid5(uuid.UUID(grandchild_id), worker_id))
        other_worker_id = str(uuid.uuid5(uuid.UUID(grandchild_id), other_worker_id))
        finding = grandchild["checkpoint"]["sources"][0]["findings"][0]
        assert {
            item["provenance"]["workerId"]
            for item in grandchild["checkpoint"]["sources"][0]["coverage"]["deferred"]
        } == {worker_id, other_worker_id}
        child_dir, child_id = grandchild_dir, grandchild_id
    extra = outcome.endswith("_partial")
    if extra:
        with sqlite3.connect(state / "workbench.sqlite3") as connection:
            output = Path(
                connection.execute(
                    "SELECT artifact_dir FROM deep_scan_workers WHERE id = ?", (worker_id,)
                ).fetchone()[0]
            )
            connection.execute(
                "UPDATE deep_scan_workers SET status = 'canceled' WHERE id = ?", (worker_id,)
            )
        new_finding = json.loads(json.dumps(finding))
        new_finding["title"] = "New finding after continuation"
        new_finding["identity"]["anchor"] = "new-after-continuation"
        new_finding["extensions"]["candidateId"] = "new-candidate"
        new_finding["provenance"]["candidateId"] = "new-candidate"
        new_finding["provenance"].pop("preservedIdentity", None)
        current = semantic(child_id, ["clean.ts"])
        current["findings"] = [finding, new_finding]
        current["coverage"]["deferred"] = [
            {"candidateId": "new-pending", "reason": "Validation still pending"}
        ]
        checkpoint_output = child_dir if outcome.startswith("root_") else output
        checkpoint_path = write_checkpoint(checkpoint_output / "checkpoints", current)
        if outcome != "unaccepted_partial":
            save(state, child_id, checkpoint_path)
        else:
            (output / "result.json").write_text(json.dumps(current))
        if outcome == "archived_partial":
            archived = output.parent / "attempts" / "attempt-01"
            archived.parent.mkdir()
            output.rename(archived)
            output.mkdir()
        if outcome in {"rejected_partial", "completed_partial", "root_rejected_partial"}:
            current["findings"] = [] if outcome == "root_rejected_partial" else [finding]
            current["coverage"]["deferred"] = []
            current["coverage"]["surfaces"] = [
                {
                    "id": "new-review",
                    "candidateId": "saved-candidate"
                    if outcome == "root_rejected_partial"
                    else "new-candidate",
                    "label": "New candidate review",
                    "disposition": "rejected",
                    "receiptRefs": [],
                    "reason": "Existing control prevents the candidate",
                    "provenance": {"workerId": worker_id},
                }
            ]
            if outcome == "rejected_partial":
                save(state, child_id, write_checkpoint(output / "checkpoints", current))
            elif outcome == "completed_partial":
                current["complete"] = True
                current["coverage"]["completeness"] = "complete"
                result_path = output / "result.json"
                result_path.write_text(json.dumps(current))
                with sqlite3.connect(state / "workbench.sqlite3") as connection:
                    connection.execute(
                        "UPDATE deep_scan_workers SET status = 'succeeded', result_manifest_path = ? WHERE id = ?",
                        (str(result_path), worker_id),
                    )
    # Publish what the coordinator actually completed. The expired case has no
    # discoveries; the other cases explicitly account for the inherited candidate.
    completed = semantic(child_id, ["clean.ts", "pending.ts"])
    completed["complete"] = True
    completed["findings"] = (
        [finding]
        if outcome in {"reported", "other_worker", "grandchild", "root_rejected_partial"}
        else []
    )
    completed["coverage"].update(
        completeness="partial" if outcome == "deadline" else "complete", deferred=[]
    )
    save(state, child_id, write_checkpoint(child_dir / "checkpoints", completed))
    context = run_workbench(state, "get-cli-scan-resume", "--scan-id", child_id)["checkpoint"]
    assert any(source["findings"] for source in context["sources"]), (
        "a later empty publication must not hide inherited state"
    )
    write_completed_contract(child_dir, child_id, repository, relative_path="clean.ts")
    findings = json.loads((child_dir / "findings.json").read_text())
    findings["findings"] = completed["findings"]
    (child_dir / "findings.json").write_text(json.dumps(findings))
    coverage = json.loads((child_dir / "coverage.json").read_text())
    coverage["completeness"] = completed["coverage"]["completeness"]
    if outcome == "rejected":
        coverage["surfaces"] = [
            {
                "id": "saved-review",
                "candidateId": "saved-candidate",
                "label": "Saved candidate review",
                "disposition": "rejected",
                "receiptRefs": [],
                "reason": "Existing control prevents the candidate",
                "provenance": {"workerId": worker_id},
            }
        ]
    (child_dir / "coverage.json").write_text(json.dumps(coverage))
    if outcome.startswith("root_"):
        # An accepted root decision may be newer than its materialized report.
        save(state, child_id, write_checkpoint(child_dir / "checkpoints", current))
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE deep_scan_runs SET status = 'succeeded', phase = 'terminal', manifest_path = ? WHERE scan_id = ?",
            (str(child_dir / "scan-manifest.json"), child_id),
        )
    run_workbench(state, "prepare-scan-completion", "--scan-id", child_id)
    first_seal = (child_dir / "scan-manifest.json").read_bytes()
    run_workbench(state, "prepare-scan-completion", "--scan-id", child_id)
    assert (child_dir / "scan-manifest.json").read_bytes() == first_seal
    result = json.loads((child_dir / "findings.json").read_text())
    coverage = json.loads((child_dir / "coverage.json").read_text())
    assert len(result["findings"]) == (
        0
        if outcome in {"rejected", "root_rejected_partial"}
        else 2
        if outcome in {"accepted_partial", "archived_partial", "root_accepted_partial"}
        else 1
    )
    if extra:
        assert any(
            item["title"] == "New finding after continuation" for item in result["findings"]
        ) == (outcome in {"accepted_partial", "archived_partial", "root_accepted_partial"})
        if outcome == "root_rejected_partial":
            assert any(
                item.get("candidateId") == "saved-candidate" and item["disposition"] == "rejected"
                for item in coverage["surfaces"]
            )
        if outcome in {"rejected_partial", "completed_partial"}:
            assert any(
                item.get("candidateId") == "new-candidate" and item["disposition"] == "rejected"
                for item in coverage["surfaces"]
            )
    if extra:
        assert coverage["completeness"] == (
            "complete" if outcome == "completed_partial" else "partial"
        )
        if outcome in {"accepted_partial", "archived_partial", "root_accepted_partial"}:
            assert any(item.get("candidateId") == "new-pending" for item in coverage["deferred"])
        elif outcome == "unaccepted_partial":
            assert any(
                item.get("candidateId") == "saved-candidate" for item in coverage["deferred"]
            )
        else:
            assert not coverage["deferred"]
    elif outcome in {"deadline", "other_worker", "grandchild"}:
        assert coverage["completeness"] == "partial"
        assert any(item.get("candidateId") == "saved-candidate" for item in coverage["deferred"])
        if outcome in {"other_worker", "grandchild"}:
            assert {item["provenance"]["workerId"] for item in coverage["deferred"]} == {
                other_worker_id
            }
    else:
        assert coverage["completeness"] == "complete"
        assert not coverage["deferred"]
    assert source.read_bytes() == original
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM deep_scan_workers WHERE scan_id = ? AND status = 'succeeded'",
            (child_id,),
        ).fetchone() == (int(outcome == "completed_partial"),)


@pytest.mark.parametrize("registered", [False, True])
def test_native_inventory_hashing_allows_another_database_writer(
    tmp_path: Path, monkeypatch, workbench_api, registered: bool
) -> None:
    import sys

    import workbench_scan_checkpoints as checkpoints

    if registered:
        state, repository, _, scan_id = scan_fixture(tmp_path, "deep")
        target_args = ["--scan-id", scan_id]
        with sqlite3.connect(state / "workbench.sqlite3") as connection:
            connection.execute("DELETE FROM scan_review_files WHERE scan_id = ?", (scan_id,))
    else:
        state, repository = tmp_path / "state", tmp_path / "repository"
        repository.mkdir()
        (repository / "source.ts").write_text("export const value = 1;\n")
        target_args = ["--target-path", str(repository), "--scan-root", str(tmp_path / "scans")]
    monkeypatch.setenv("CODEX_SECURITY_STATE_DIR", str(state))
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "home"))
    monkeypatch.setattr(
        sys,
        "argv",
        ["workbench_db.py", "begin-deep-scan", "--thread-id", "inventory-owner", *target_args],
    )
    args = workbench_api["parse_args"]("Test inventory recovery")
    connection = workbench_api["connect"]()
    try:
        connection.execute("CREATE TABLE inventory_writer_probe (writes INTEGER)")
        connection.commit()
        digest = checkpoints.file_digest

        def hash_with_concurrent_write(path: Path) -> str:
            with sqlite3.connect(state / "workbench.sqlite3", timeout=0.05) as writer:
                writer.execute("INSERT INTO inventory_writer_probe VALUES (1)")
            return digest(path)

        monkeypatch.setattr(checkpoints, "file_digest", hash_with_concurrent_write)
        begun = workbench_api["deep_scan"].begin_deep_scan(connection, args)
        scan_id = begun["deepScan"]["scanId"]
        assert connection.execute("SELECT COUNT(*) FROM inventory_writer_probe").fetchone()[0] > 0
        inventory = connection.execute(
            "SELECT relative_path, content_sha256 FROM scan_review_files WHERE scan_id = ?",
            (scan_id,),
        ).fetchall()
        assert inventory
        assert all(content == digest(repository / name) for name, content in inventory)
    finally:
        connection.close()
