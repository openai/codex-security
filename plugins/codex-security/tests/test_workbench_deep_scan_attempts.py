from __future__ import annotations

import sqlite3
import uuid
from pathlib import Path

import pytest
from test_workbench_deep_scan import (
    begin_target_scan,
    claim_deep_scan_coordinator,
    deep_environment,
    dispatch_discovery_worker,
    expire_deep_scan_coordinator,
    upsert_worker,
    worker_attempts,
    worker_paths,
    write_canonical_artifacts,
)
from workbench_test_support import run_workbench


@pytest.mark.parametrize("resume_thread", [False, True])
def test_worker_attempts_retain_errors_and_thread_associations_across_retries(
    tmp_path: Path, resume_thread: bool
) -> None:
    state_dir, codex_home, target = tmp_path / "state", tmp_path / "codex-home", tmp_path / "target"
    target.mkdir()
    begun = begin_target_scan(state_dir, codex_home, target, tmp_path / "scans")["deepScan"]
    scan_id, worker_id = str(begun["scanId"]), str(uuid.uuid4())
    prompt, artifact_dir, result = worker_paths(Path(str(begun["scanDir"])), "retry-worker")
    update = {
        "scan_id": scan_id,
        "worker_id": worker_id,
        "kind": "discovery",
        "prompt_path": prompt,
        "artifact_dir": artifact_dir,
    }
    upsert_worker(
        state_dir, codex_home, **update, status="running", attempt=1, thread_id="thread-first"
    )
    upsert_worker(
        state_dir, codex_home, **update, status="running", attempt=1, error="first attempt failed"
    )
    first_attempt = worker_attempts(state_dir, worker_id)[0]

    resumed_thread = "thread-first" if resume_thread else None
    retry = upsert_worker(
        state_dir, codex_home, **update, status="running", attempt=2, thread_id=resumed_thread
    )["deepScan"]["workers"][0]
    assert retry["sdkThreadId"] == resumed_thread
    assert retry["error"] is None
    second_thread = resumed_thread or "thread-second"
    upsert_worker(
        state_dir, codex_home, **update, status="running", attempt=2, thread_id=second_thread
    )
    result.write_text("{}\n")
    upsert_worker(
        state_dir, codex_home, **update, status="succeeded", attempt=2, result_path=result
    )
    retained = worker_attempts(state_dir, worker_id)
    assert retained[0] == first_attempt
    assert first_attempt["sdk_thread_id"] == "thread-first"
    assert first_attempt["error_message"] == "first attempt failed"
    assert [attempt["attempt"] for attempt in retained] == [1, 2]
    assert retained[1]["sdk_thread_id"] == second_thread
    assert retained[1]["status"] == "succeeded"
    assert retained[1]["error_message"] is None
    assert retained[1]["started_at"] > retained[0]["started_at"]
    assert retained[1]["completed_at"] is not None

    # Every workbench call starts a new process; reopening and replaying a
    # terminal update must leave the retained attempt history unchanged.
    upsert_worker(
        state_dir, codex_home, **update, status="succeeded", attempt=2, result_path=result
    )
    assert worker_attempts(state_dir, worker_id) == retained


def test_retry_failure_before_thread_creation_does_not_inherit_previous_thread(
    tmp_path: Path,
) -> None:
    state_dir, codex_home, target = tmp_path / "state", tmp_path / "codex-home", tmp_path / "target"
    target.mkdir()
    begun = begin_target_scan(state_dir, codex_home, target, tmp_path / "scans")["deepScan"]
    worker_id = str(uuid.uuid4())
    prompt, artifact_dir, _ = worker_paths(Path(str(begun["scanDir"])), "pre-thread-failure")
    update = {
        "scan_id": str(begun["scanId"]),
        "worker_id": worker_id,
        "kind": "setup",
        "prompt_path": prompt,
        "artifact_dir": artifact_dir,
    }
    upsert_worker(
        state_dir, codex_home, **update, status="running", attempt=1, thread_id="thread-first"
    )
    upsert_worker(
        state_dir, codex_home, **update, status="running", attempt=1, error="first attempt failed"
    )
    upsert_worker(state_dir, codex_home, **update, status="running", attempt=2)
    failed = upsert_worker(
        state_dir,
        codex_home,
        **update,
        status="failed",
        attempt=2,
        error="executor failed before thread creation",
    )["deepScan"]["workers"][0]

    retained = worker_attempts(state_dir, worker_id)
    assert retained[0]["sdk_thread_id"] == "thread-first"
    assert retained[0]["error_message"] == "first attempt failed"
    assert retained[1]["sdk_thread_id"] is None
    assert retained[1]["error_message"] == "executor failed before thread creation"
    assert retained[1]["status"] == "failed"
    assert retained[1]["completed_at"] is not None
    assert failed["sdkThreadId"] is None


def test_dedup_commit_updates_current_attempt_and_retains_previous_retry(tmp_path: Path) -> None:
    state_dir, codex_home, target = tmp_path / "state", tmp_path / "codex-home", tmp_path / "target"
    target.mkdir()
    begun = begin_target_scan(state_dir, codex_home, target, tmp_path / "scans")["deepScan"]
    scan_id, scan_dir = str(begun["scanId"]), Path(str(begun["scanDir"]))
    input_ids = [
        dispatch_discovery_worker(
            state_dir, codex_home, scan_id=scan_id, scan_dir=scan_dir, name=f"discovery-{index}"
        )[0]
        for index in range(2)
    ]
    worker_id = str(uuid.uuid4())
    prompt, artifact_dir, result = worker_paths(scan_dir, "retry-reducer")
    run_workbench(
        state_dir,
        "claim-deep-scan-dedup",
        "--scan-id",
        scan_id,
        "--worker-id",
        worker_id,
        "--prompt-path",
        str(prompt),
        "--artifact-dir",
        str(artifact_dir),
        *(item for input_id in input_ids for item in ("--input-worker-id", input_id)),
        environment=deep_environment(codex_home),
    )
    update = {
        "scan_id": scan_id,
        "worker_id": worker_id,
        "kind": "dedup",
        "prompt_path": prompt,
        "artifact_dir": artifact_dir,
        "status": "running",
    }
    upsert_worker(
        state_dir,
        codex_home,
        **update,
        attempt=1,
        thread_id="thread-reducer-first",
        error="first reducer attempt failed",
    )
    first_attempt = worker_attempts(state_dir, worker_id)[0]
    upsert_worker(state_dir, codex_home, **update, attempt=2, thread_id="thread-reducer-second")
    write_canonical_artifacts(scan_dir)
    result.write_text("{}\n")
    run_workbench(
        state_dir,
        "commit-deep-scan-dedup",
        "--scan-id",
        scan_id,
        "--worker-id",
        worker_id,
        "--result-manifest-path",
        str(result),
        "--new-findings-count",
        "0",
        environment=deep_environment(codex_home),
    )
    retained = worker_attempts(state_dir, worker_id)
    assert retained[0] == first_attempt
    assert retained[1]["status"] == "succeeded"
    assert retained[1]["sdk_thread_id"] == "thread-reducer-second"
    assert retained[1]["error_message"] is None
    assert retained[1]["completed_at"] is not None


@pytest.mark.parametrize("coordinator_shutdown", [False, True])
def test_coordinator_recovery_preserves_recorded_execution_error(
    tmp_path: Path, coordinator_shutdown: bool
) -> None:
    state_dir, codex_home, target = tmp_path / "state", tmp_path / "codex-home", tmp_path / "target"
    target.mkdir()
    begun = begin_target_scan(state_dir, codex_home, target, tmp_path / "scans")["deepScan"]
    scan_id, worker_id = str(begun["scanId"]), str(uuid.uuid4())
    claim_deep_scan_coordinator(state_dir, codex_home, scan_id)
    prompt, artifact_dir, _ = worker_paths(Path(str(begun["scanDir"])), "interrupted-worker")
    upsert_worker(
        state_dir,
        codex_home,
        scan_id=scan_id,
        worker_id=worker_id,
        kind="discovery",
        status="running",
        prompt_path=prompt,
        artifact_dir=artifact_dir,
        attempt=1,
        thread_id="thread-interrupted-worker",
        error="worker execution error",
        coordinator_generation=2,
    )
    if coordinator_shutdown:
        upsert_worker(
            state_dir,
            codex_home,
            scan_id=scan_id,
            worker_id=worker_id,
            kind="discovery",
            status="canceled",
            prompt_path=prompt,
            artifact_dir=artifact_dir,
            attempt=1,
            thread_id="thread-interrupted-worker",
            error="coordinator_shutdown: mcp_transport_closed",
            coordinator_generation=2,
        )
        assert worker_attempts(state_dir, worker_id)[0]["error_message"] == "worker execution error"
    expire_deep_scan_coordinator(state_dir, scan_id)
    recovered = claim_deep_scan_coordinator(state_dir, codex_home, scan_id)["deepScan"]
    assert recovered["workers"][0]["status"] == "canceled"
    if coordinator_shutdown:
        assert recovered["workers"][0]["error"].startswith("coordinator_shutdown_recovered:")
    retained = worker_attempts(state_dir, worker_id)
    assert retained[0]["status"] == "canceled"
    assert retained[0]["sdk_thread_id"] == "thread-interrupted-worker"
    assert retained[0]["error_message"] == "worker execution error"
    assert retained[0]["completed_at"] == recovered["workers"][0]["completedAt"]


@pytest.mark.parametrize("legacy_attempt", [1, 3])
def test_worker_attempt_migration_only_backfills_unambiguous_first_attempt(
    tmp_path: Path, legacy_attempt: int
) -> None:
    state_dir, codex_home, target = tmp_path / "state", tmp_path / "codex-home", tmp_path / "target"
    target.mkdir()
    begun = begin_target_scan(state_dir, codex_home, target, tmp_path / "scans")["deepScan"]
    scan_id, worker_id = str(begun["scanId"]), str(uuid.uuid4())
    prompt, artifact_dir, _ = worker_paths(Path(str(begun["scanDir"])), "legacy-worker")
    update = {
        "scan_id": scan_id,
        "worker_id": worker_id,
        "kind": "setup",
        "prompt_path": prompt,
        "artifact_dir": artifact_dir,
    }
    upsert_worker(
        state_dir,
        codex_home,
        **update,
        status="running",
        attempt=1,
        thread_id="legacy-thread",
        error="legacy error",
    )
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.execute("DROP TABLE deep_scan_worker_attempts")
        connection.execute("DELETE FROM schema_migrations WHERE version = 42")
        connection.execute(
            "UPDATE deep_scan_workers SET attempt = ? WHERE id = ?", (legacy_attempt, worker_id)
        )

    restored = run_workbench(
        state_dir,
        "get-deep-scan",
        "--scan-id",
        scan_id,
        "--thread-id",
        "thread-deep-scan",
        environment=deep_environment(codex_home),
    )["deepScan"]["workers"][0]
    assert restored["attempt"] == legacy_attempt
    assert restored["sdkThreadId"] == "legacy-thread"
    assert restored["error"] == "legacy error"
    retained = worker_attempts(state_dir, worker_id)
    if legacy_attempt == 1:
        assert len(retained) == 1
        assert retained[0]["sdk_thread_id"] == "legacy-thread"
        assert retained[0]["error_message"] == "legacy error"
        assert retained[0]["started_at"] == restored["startedAt"]
    else:
        assert retained == []
        upsert_worker(state_dir, codex_home, **update, status="running", attempt=legacy_attempt)
        assert worker_attempts(state_dir, worker_id) == []
        upsert_worker(
            state_dir,
            codex_home,
            **update,
            status="running",
            attempt=legacy_attempt,
            thread_id="observed-current-thread",
        )
        assert worker_attempts(state_dir, worker_id) == []

    upsert_worker(state_dir, codex_home, **update, status="running", attempt=legacy_attempt + 1)
    latest = worker_attempts(state_dir, worker_id)[-1]
    assert latest["attempt"] == legacy_attempt + 1
    assert latest["sdk_thread_id"] is None
    assert latest["error_message"] is None
