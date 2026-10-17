from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest
from test_workbench_deep_scan import (
    begin_target_scan,
    commit_reducer,
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
    monkeypatch.setattr(
        deep_scan,
        "_dependencies",
        SimpleNamespace(
            **workbench_api,
            preserve_stopped_results=workbench_api["preserve_stopped_results_after_transition"],
        ),
    )
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
    monkeypatch.setattr(
        deep_scan,
        "_dependencies",
        SimpleNamespace(
            **workbench_api,
            preserve_stopped_results=workbench_api["preserve_stopped_results_after_transition"],
        ),
    )
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


def test_replaced_attempts_retain_observed_sessions_and_accepted_result(tmp_path: Path) -> None:
    state, home, target = tmp_path / "state", tmp_path / "codex", tmp_path / "target"
    target.mkdir()
    run = begin_target_scan(state, home, target, tmp_path / "scans")["deepScan"]
    worker_id = str(uuid.uuid4())
    prompt, artifacts, result = worker_paths(Path(run["scanDir"]), "discovery-1")
    mutation = dict(
        scan_id=run["scanId"],
        worker_id=worker_id,
        kind="discovery",
        prompt_path=prompt,
        artifact_dir=artifacts,
    )
    upsert_worker(state, home, **mutation, status="running", attempt=1, thread_id="old-session")
    upsert_worker(
        state,
        home,
        **mutation,
        status="running",
        attempt=1,
        thread_id="old-session",
        error="Artifact validation failed",
    )
    upsert_worker(state, home, **mutation, status="running", attempt=2, thread_id="new-session")
    result.write_text('{"findings": []}\n')
    accepted = upsert_worker(
        state,
        home,
        **mutation,
        status="succeeded",
        attempt=2,
        thread_id="new-session",
        result_path=result,
    )["deepScan"]
    attempts = accepted["attempts"]
    assert [(item["attempt"], item["status"]) for item in attempts] == [
        (1, "failed"),
        (2, "succeeded"),
    ]
    assert [item["sdkThreadId"] for item in accepted["attemptSessions"]] == [
        "old-session",
        "new-session",
    ]
    assert attempts[0]["error"] == "Artifact validation failed"
    assert attempts[0]["completedAt"] is not None
    assert attempts[1]["acceptedResultSha256"]
    assert Path(attempts[1]["acceptedResultPath"]).read_text() == result.read_text()
    result.unlink()
    replayed = upsert_worker(
        state,
        home,
        **mutation,
        status="succeeded",
        attempt=2,
        thread_id="new-session",
        result_path=result,
    )["deepScan"]
    assert replayed == accepted


def test_merge_replay_returns_original_operation_after_later_work(tmp_path: Path) -> None:
    state, home, target = tmp_path / "state", tmp_path / "codex", tmp_path / "target"
    target.mkdir()
    run = begin_target_scan(state, home, target, tmp_path / "scans")["deepScan"]
    scan_id, scan_dir = run["scanId"], Path(run["scanDir"])
    inputs = [
        dispatch_discovery_worker(
            state,
            home,
            scan_id=scan_id,
            scan_dir=scan_dir,
            name=f"discovery-{index}",
        )[0]
        for index in range(2)
    ]
    committed = commit_reducer(
        state,
        home,
        scan_id=scan_id,
        scan_dir=scan_dir,
        name="dedup-1",
        input_worker_ids=inputs,
        new_findings_count=0,
    )
    reducer = next(worker for worker in committed["workers"] if worker["kind"] == "dedup")
    frozen = committed["committedMerge"]["resultManifestPath"]
    assert Path(frozen).is_file()
    Path(reducer["resultManifestPath"]).unlink()
    assert [item["discoveryWorkerId"] for item in committed["dedupInputs"]] == inputs
    assert all(item["attempt"] == 1 for item in committed["dedupInputs"])
    assert all("/checkpoints/" in item["resultManifestPath"] for item in committed["dedupInputs"])
    later = dispatch_discovery_worker(
        state,
        home,
        scan_id=scan_id,
        scan_dir=scan_dir,
        name="discovery-2",
    )[0]
    second_commit = commit_reducer(
        state,
        home,
        scan_id=scan_id,
        scan_dir=scan_dir,
        name="dedup-2",
        input_worker_ids=[later],
        new_findings_count=1,
    )
    second_claim = second_commit["mergeClaims"][-1]
    assert second_claim["previousWorkerId"] == reducer["id"]
    assert second_claim["previousResultPath"] == frozen
    assert (
        second_claim["previousResultSha256"] == committed["committedMerge"]["resultManifestSha256"]
    )
    replay = run_workbench(
        state,
        "commit-deep-scan-dedup",
        "--scan-id",
        scan_id,
        "--worker-id",
        reducer["id"],
        "--result-manifest-path",
        str(scan_dir / "different.json"),
        "--new-findings-count",
        "99",
        environment={"CODEX_HOME": str(home)},
    )["deepScan"]
    assert replay["committedMerge"] == committed["committedMerge"]
    assert replay["completionSequence"] == second_commit["completionSequence"]
    assert replay["noNewStreak"] == second_commit["noNewStreak"]
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        receipt = json.loads(
            connection.execute(
                "SELECT receipt_json FROM deep_scan_merge_claims WHERE worker_id = ?",
                (reducer["id"],),
            ).fetchone()[0]
        )
    assert receipt == committed["committedMerge"]


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
    upsert_worker(state, home, **mutation, status="running", attempt=1, thread_id="old")
    upsert_worker(state, home, **mutation, status="running", attempt=2, thread_id="old")
    upsert_worker(
        state,
        home,
        **mutation,
        status="running",
        attempt=2,
        thread_id="old",
        error="fixture failure",
    )
    upsert_worker(state, home, **mutation, status="running", attempt=3, thread_id="replacement")
    terminal = upsert_worker(
        state, home, **mutation, status="canceled", attempt=3, thread_id="replacement"
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
        timestamp = datetime.fromisoformat(scan["started_at"].replace("Z", "+00:00")) + timedelta(
            microseconds=1
        )
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


def test_acceptance_reuses_authoritative_checkpoint_without_rewriting(tmp_path: Path) -> None:
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
    draft = {"scanId": run["scanId"], "findings": [], "coverage": {}}
    content = json.dumps(draft, indent=2).encode() + b"\n"
    checkpoint = artifacts / "checkpoints" / f"{hashlib.sha256(content).hexdigest()}.json"
    checkpoint.parent.mkdir()
    checkpoint.write_bytes(content)
    (artifacts / "checkpoint-head.json").write_text(json.dumps({"checkpoint": checkpoint.name}))
    result.write_text(json.dumps({**draft, "handoffClaimToken": "synthetic-claim"}))
    accepted = upsert_worker(state, home, **mutation, status="succeeded", result_path=result)[
        "deepScan"
    ]
    assert accepted["attempts"][0]["acceptedResultPath"] == str(checkpoint)
    assert accepted["attempts"][0]["acceptedResultSha256"] == hashlib.sha256(content).hexdigest()
    result.unlink()
    upsert_worker(state, home, **mutation, status="succeeded", result_path=result)
    assert list(checkpoint.parent.iterdir()) == [checkpoint]
    assert checkpoint.read_bytes() == content
    assert not (artifacts / "accepted").exists()


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


@pytest.mark.parametrize("replacement", ["result", "checkpoint", "ordinary"])
def test_accepted_result_does_not_reopen_replaced_path(
    tmp_path, workbench_api, monkeypatch, replacement
):
    from finalize_scan_contract import ContractError

    state, home, target = tmp_path / "state", tmp_path / "codex", tmp_path / "target"
    target.mkdir()
    run = begin_target_scan(state, home, target, tmp_path / "scans")["deepScan"]
    scan_id, scan_dir = run["scanId"], Path(run["scanDir"])
    worker_id, prompt, artifacts, result = dispatch_discovery_worker(
        state, home, scan_id=scan_id, scan_dir=scan_dir, name="discovery-1", succeed=False
    )
    payload = {
        "scanId": scan_id,
        "complete": False,
        "findings": [],
        "coverage": {
            "completeness": "complete",
            "surfaces": [],
            "explicitExclusions": [],
            "deferred": [],
        },
    }
    original_bytes = json.dumps(payload).encode()
    result.write_bytes(original_bytes)
    checkpoint = artifacts / "checkpoints" / "accepted.json"
    if replacement == "checkpoint":
        checkpoint.parent.mkdir(parents=True)
        checkpoint.write_bytes(original_bytes)
    external = tmp_path / "outside-scan.json"
    external.write_text(json.dumps(payload, indent=2) + "\n")
    deep = sys.modules["deep_scan_workbench"]
    monkeypatch.setattr(
        deep,
        "_dependencies",
        SimpleNamespace(
            **workbench_api,
            preserve_stopped_results=workbench_api["preserve_stopped_results_after_transition"],
        ),
    )
    validate = deep.deep_scan_path
    swapped = []

    def validate_then_replace(scan, value, label, *, kind):
        checked = validate(scan, value, label, kind=kind)
        selected = (
            "Accepted worker result" if replacement == "result" else "Accepted worker checkpoint"
        )
        if replacement != "ordinary" and label == selected:
            path = Path(checked)
            path.unlink()
            path.symlink_to(external)
            swapped.append(label)
        return checked

    monkeypatch.setattr(deep, "deep_scan_path", validate_then_replace)
    args = SimpleNamespace(
        scan_id=scan_id,
        worker_id=worker_id,
        kind="discovery",
        status="succeeded",
        prompt_path=str(prompt),
        artifact_dir=str(artifacts),
        result_manifest_path=str(result),
        attempt=1,
        sdk_thread_id="synthetic-worker",
        error_message=None,
        replaceable_failure_kind=None,
        coordinator_generation=None,
    )
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.row_factory = sqlite3.Row
        if replacement == "ordinary":
            accepted = deep.upsert_deep_scan_worker(connection, args)["deepScan"]
            attempt = accepted["attempts"][-1]
            assert Path(attempt["acceptedResultPath"]).read_bytes() == original_bytes
            assert (
                attempt["acceptedResultSha256"]
                == __import__("hashlib").sha256(original_bytes).hexdigest()
            )
        else:
            with pytest.raises(ContractError, match="inside the scan directory"):
                deep.upsert_deep_scan_worker(connection, args)
            assert swapped
            assert (
                connection.execute(
                    "SELECT status FROM deep_scan_workers WHERE id = ?", (worker_id,)
                ).fetchone()[0]
                == "running"
            )
            assert (
                connection.execute(
                    "SELECT accepted_result_path FROM deep_scan_attempts WHERE worker_id = ?",
                    (worker_id,),
                ).fetchone()[0]
                is None
            )


@pytest.mark.parametrize("heartbeat", ["absent", "ordinary", "released", "other-generation"])
def test_artifact_release_does_not_override_current_persisted_lease(tmp_path, heartbeat):
    from test_workbench_deep_scan import claim_deep_scan_coordinator

    state, home, target = tmp_path / "state", tmp_path / "codex", tmp_path / "target"
    target.mkdir()
    initial = begin_target_scan(state, home, target, tmp_path / "scans")["deepScan"]
    claimed = claim_deep_scan_coordinator(state, home, initial["scanId"])["deepScan"]
    assert claimed["coordinatorGeneration"] == 2
    if heartbeat != "absent":
        record = {
            "coordinatorGeneration": 3 if heartbeat == "other-generation" else 2,
            "updatedAt": claimed["updatedAt"],
        }
        if heartbeat in {"released", "other-generation"}:
            record["released"] = True
        path = (
            Path(claimed["scanDir"])
            / "artifacts"
            / "deep_discovery"
            / "coordinator-heartbeat-2.json"
        )
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(record))
    rejoined = claim_deep_scan_coordinator(state, home, initial["scanId"])
    assert rejoined["coordinatorDisposition"] == "observing"
    assert rejoined["deepScan"]["coordinatorGeneration"] == 2


@pytest.mark.parametrize("release", ["normal", "repeat", "wrong-owner", "stale-generation"])
def test_host_release_preserves_lease_owner_and_generation(tmp_path, release):
    import os

    from test_workbench_deep_scan import claim_deep_scan_coordinator
    from workbench_test_support import SCRIPT

    state, home, target = tmp_path / "state", tmp_path / "codex", tmp_path / "target"
    target.mkdir()
    initial = begin_target_scan(state, home, target, tmp_path / "scans")["deepScan"]
    scan_id = initial["scanId"]
    claimed = claim_deep_scan_coordinator(state, home, scan_id)["deepScan"]
    assert claimed["coordinatorGeneration"] == 2

    def host_release(thread="thread-deep-scan", generation=2):
        return subprocess.run(
            [
                sys.executable,
                "-c",
                "import runpy,sys; script=sys.argv.pop(1); runpy.run_path(script)['main'](release_coordinator=True)",
                str(SCRIPT),
                "claim-deep-scan-coordinator",
                "--scan-id",
                scan_id,
                "--thread-id",
                thread,
                "--coordinator-generation",
                str(generation),
            ],
            capture_output=True,
            text=True,
            env={**os.environ, "CODEX_SECURITY_STATE_DIR": str(state), "CODEX_HOME": str(home)},
        )

    if release == "wrong-owner":
        rejected = host_release("different-synthetic-owner")
        assert rejected.returncode != 0
        observed = claim_deep_scan_coordinator(state, home, scan_id)
        assert observed["coordinatorDisposition"] == "observing"
        assert observed["deepScan"]["coordinatorGeneration"] == 2
        return
    accepted = host_release()
    assert accepted.returncode == 0, accepted.stderr
    if release == "repeat":
        repeated = host_release()
        assert repeated.returncode == 0, repeated.stderr
    adopted = claim_deep_scan_coordinator(state, home, scan_id)
    assert adopted["coordinatorDisposition"] == "adopted"
    assert adopted["deepScan"]["coordinatorGeneration"] == 3
    if release == "stale-generation":
        rejected = host_release()
        assert rejected.returncode != 0
        assert "newer generation" in rejected.stderr
    observed = claim_deep_scan_coordinator(state, home, scan_id)
    assert observed["coordinatorDisposition"] == "observing"
    assert observed["deepScan"]["coordinatorGeneration"] == 3
