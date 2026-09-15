from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
import uuid
from pathlib import Path

import pytest
from test_workbench_deep_scan import (
    begin_target_scan,
    dispatch_discovery_worker,
    upsert_worker,
    worker_paths,
)
from workbench_test_support import run_workbench


def test_state_snapshot_does_not_mix_concurrent_acceptance(
    tmp_path: Path, workbench_api, monkeypatch: pytest.MonkeyPatch
) -> None:
    state_dir, codex_home, target = tmp_path / "state", tmp_path / "codex", tmp_path / "target"
    target.mkdir()
    initial = begin_target_scan(state_dir, codex_home, target, tmp_path / "scans")["deepScan"]
    scan_id = initial["scanId"]
    worker_id, _, _, _ = dispatch_discovery_worker(
        state_dir,
        codex_home,
        scan_id=scan_id,
        scan_dir=Path(initial["scanDir"]),
        name="discovery-1",
        succeed=False,
    )
    database = state_dir / "workbench.sqlite3"
    deep_scan = sys.modules["deep_scan_workbench"]
    monkeypatch.setattr(deep_scan, "require_scan", workbench_api["require_scan"])
    original = deep_scan.require_deep_scan_run

    def accept_after_read(connection, requested_scan_id):
        run = original(connection, requested_scan_id)
        with sqlite3.connect(database) as writer:
            writer.execute(
                "UPDATE deep_scan_runs SET completion_sequence = 1 WHERE scan_id = ?", (scan_id,)
            )
            writer.execute(
                "UPDATE deep_scan_workers SET status = 'succeeded', completion_sequence = 1 "
                "WHERE id = ?",
                (worker_id,),
            )
        return run

    monkeypatch.setattr(deep_scan, "require_deep_scan_run", accept_after_read)
    with sqlite3.connect(database) as reader:
        reader.row_factory = sqlite3.Row
        snapshot = deep_scan.deep_scan_state(reader, scan_id)
        assert snapshot["completionSequence"] == 0
        assert snapshot["workers"][0]["status"] == "running"
        assert not reader.in_transaction


def test_state_snapshot_preserves_its_callers_transaction(
    tmp_path: Path, workbench_api, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "target"
    target.mkdir()
    initial = begin_target_scan(tmp_path / "state", tmp_path / "codex", target, tmp_path / "scans")
    scan_id = initial["deepScan"]["scanId"]
    deep_scan = sys.modules["deep_scan_workbench"]
    monkeypatch.setattr(deep_scan, "require_scan", workbench_api["require_scan"])
    with sqlite3.connect(tmp_path / "state" / "workbench.sqlite3") as connection:
        connection.row_factory = sqlite3.Row
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            "UPDATE deep_scan_runs SET consecutive_errors = 2 WHERE scan_id = ?", (scan_id,)
        )
        snapshot = deep_scan.deep_scan_state(connection, scan_id)
        assert snapshot["consecutiveErrors"] == 2
        assert connection.in_transaction
        connection.rollback()
        assert deep_scan.deep_scan_state(connection, scan_id)["consecutiveErrors"] == 0


def test_native_usage_keeps_replaced_failed_canceled_attempts_and_descendants(
    tmp_path: Path, workbench_api, monkeypatch: pytest.MonkeyPatch
) -> None:
    from datetime import datetime, timedelta

    from test_workbench_scan_usage import _counts, _event, _rollout, _state_graph, _token_event

    state, home, target = tmp_path / "state", tmp_path / "codex", tmp_path / "target"
    target.mkdir()
    run = begin_target_scan(state, home, target, tmp_path / "scans")["deepScan"]
    worker_id = str(uuid.uuid4())
    prompt, artifacts, _ = worker_paths(Path(run["scanDir"]), "discovery-1")
    mutation = dict(
        scan_id=run["scanId"],
        worker_id=worker_id,
        kind="discovery",
        prompt_path=prompt,
        artifact_dir=artifacts,
    )
    upsert_worker(state, home, **mutation, status="running", attempt=3, thread_id="replacement")
    upsert_worker(state, home, **mutation, status="canceled", attempt=3, thread_id="replacement")
    # The writer release recorded these prior attempts and observed sessions.
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        for attempt, status, thread in (
            (1, "replaced", "old"),
            (2, "failed", "old"),
            (3, "canceled", "replacement"),
        ):
            connection.execute(
                "INSERT INTO deep_scan_attempts "
                "(scan_id, worker_id, attempt, status, started_at) VALUES (?, ?, ?, ?, ?)",
                (run["scanId"], worker_id, attempt, status, run["createdAt"]),
            )
            connection.execute(
                "INSERT INTO deep_scan_attempt_sessions "
                "(scan_id, worker_id, attempt, sdk_thread_id, observed_at) VALUES (?, ?, ?, ?, ?)",
                (run["scanId"], worker_id, attempt, thread, run["createdAt"]),
            )
    terminal = run_workbench(
        state, "get-deep-scan", "--scan-id", run["scanId"], "--thread-id", "thread-deep-scan"
    )["deepScan"]
    assert [item["status"] for item in terminal["attempts"]] == ["replaced", "failed", "canceled"]
    environment = {
        "CODEX_HOME": str(home),
        "CODEX_SQLITE_HOME": str(tmp_path / "native"),
        "CODEX_STATE_DB": "",
    }
    for key, value in environment.items():
        monkeypatch.setenv(key, value)
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.row_factory = sqlite3.Row
        scan = connection.execute("SELECT * FROM scans WHERE id = ?", (run["scanId"],)).fetchone()
        timestamp = datetime.fromisoformat(scan["started_at"]) + timedelta(microseconds=1)
        context = _event(
            timestamp, "turn_context", {"turn_id": "fixture-turn", "model": "gpt-5.6-sol"}
        )
        old = _rollout(tmp_path, "old", [context])
        _state_graph(
            environment,
            {
                "thread-deep-scan": _rollout(tmp_path, "thread-deep-scan", []),
                "old": old,
                "replacement": _rollout(
                    tmp_path, "replacement", [context, _token_event(timestamp, 30, 0)]
                ),
                "child": _rollout(
                    tmp_path,
                    "child",
                    [context, _token_event(timestamp, 5, 0)],
                    parent_thread_id="old",
                ),
                "unrelated": _rollout(
                    tmp_path,
                    "unrelated",
                    [context, _token_event(timestamp, 900, 0)],
                    parent_thread_id="thread-deep-scan",
                ),
            },
            [("old", "child"), ("thread-deep-scan", "unrelated")],
        )
        reader = sys.modules["workbench_scan_usage"]
        pending = reader.collect_scan_usage(connection, scan)
        assert pending["inputTokens"] == 35
        assert pending["missingThreadCount"] == 2
        old.write_text(old.read_text() + json.dumps(_token_event(timestamp, 20, 0)) + "\n")
        measured = reader.collect_scan_usage(connection, scan)
        assert measured["inputTokens"] == 55
        assert measured["threadCount"] == 3
        assert measured["missingThreadCount"] == 1
        assert measured["coverage"] == "partial"  # Original shared parent turn was unavailable.
        assert measured["modelUsage"] == [{"model": "gpt-5.6-sol", **_counts(55, 0, 0)}]


def test_acceptance_rejects_mutable_result_behind_checkpoint_head(tmp_path: Path) -> None:
    import hashlib

    state, home, target = tmp_path / "state", tmp_path / "codex", tmp_path / "target"
    target.mkdir()
    run = begin_target_scan(state, home, target, tmp_path / "scans")["deepScan"]
    worker_id = str(uuid.uuid4())
    prompt, artifacts, result = worker_paths(Path(run["scanDir"]), "discovery")
    mutation = dict(
        scan_id=run["scanId"],
        worker_id=worker_id,
        kind="discovery",
        prompt_path=prompt,
        artifact_dir=artifacts,
        attempt=1,
    )
    upsert_worker(state, home, **mutation, status="running")
    draft = {"scanId": run["scanId"], "findings": [], "coverage": {"deferred": ["unresolved"]}}
    content = json.dumps(draft).encode()
    checkpoint = artifacts / "checkpoints" / f"{hashlib.sha256(content).hexdigest()}.json"
    checkpoint.parent.mkdir()
    checkpoint.write_bytes(content)
    (artifacts / "checkpoint-head.json").write_text(json.dumps({"checkpoint": checkpoint.name}))
    result.write_text(json.dumps({**draft, "coverage": {}}))
    with pytest.raises(subprocess.CalledProcessError) as failure:
        upsert_worker(state, home, **mutation, status="succeeded", result_path=result)
    assert "does not match its current checkpoint head" in failure.value.stderr
    assert checkpoint.read_bytes() == content


def test_claim_replay_preserves_original_inputs_after_concurrent_discovery(tmp_path: Path) -> None:
    state, home, target = tmp_path / "state", tmp_path / "codex", tmp_path / "target"
    target.mkdir()
    run = begin_target_scan(state, home, target, tmp_path / "scans")["deepScan"]
    scan_id, scan_dir = run["scanId"], Path(run["scanDir"])
    inputs = [
        dispatch_discovery_worker(
            state, home, scan_id=scan_id, scan_dir=scan_dir, name=f"discovery-{index}"
        )[0]
        for index in range(2)
    ]
    prompt, artifacts, _ = worker_paths(scan_dir, "reducer")
    args = [
        "claim-deep-scan-dedup",
        "--scan-id",
        scan_id,
        "--worker-id",
        str(uuid.uuid4()),
        "--prompt-path",
        str(prompt),
        "--artifact-dir",
        str(artifacts),
    ]
    for worker in inputs:
        args.extend(["--input-worker-id", worker])
    claimed = run_workbench(state, *args, environment={"CODEX_HOME": str(home)})
    dispatch_discovery_worker(
        state, home, scan_id=scan_id, scan_dir=scan_dir, name="concurrent-discovery"
    )
    replayed = run_workbench(state, *args, environment={"CODEX_HOME": str(home)})
    assert replayed["deepScan"]["mergeClaims"] == claimed["deepScan"]["mergeClaims"]
    assert replayed["deepScan"]["dedupInputs"] == claimed["deepScan"]["dedupInputs"]
    assert (
        replayed["deepScan"]["completionSequence"] == claimed["deepScan"]["completionSequence"] + 1
    )
