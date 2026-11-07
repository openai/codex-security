"""Verify composed Deep Scan accounting and persisted worker receipts."""

from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from test_workbench_scan_usage import (
    _complete_scan,
    _rollout,
    _start_scan,
    _state_graph,
    _token_event,
    _worker_usage_directory,
)
from workbench_test_support import (
    fail_scan,
    mark_deep_aggregate_ready,
    run_workbench,
    write_completed_contract,
)
from workbench_test_support import usage_counts as _counts


@pytest.mark.parametrize("include_cost", [False, True])
def test_cost_envelopes_preserve_usage_without_nesting(workbench_api, include_cost: bool) -> None:
    usage = {
        "coverage": "unavailable",
        "source": "codex_rollout",
        "threadCount": 0,
        "warnings": ["scan_thread_unavailable"],
    }
    measured = {
        "coverage": "complete",
        "source": "codex_rollout",
        **_counts(0, 0, 0),
        "threadCount": 1,
    }
    cost = {
        "model": "synthetic-model",
        "inputTokens": 0,
        "cachedInputTokens": 0,
        "cacheWriteInputTokens": 0,
        "outputTokens": 0,
        "estimatedUsd": 0,
    }
    merge = workbench_api["scan_usage"].merge_scan_cost
    stored = json.dumps({"usage": usage, "cost": cost})
    incoming = json.dumps({"usage": measured, **({"cost": cost} if include_cost else {})})
    assert json.loads(merge(stored, incoming)) == {"usage": measured, "cost": cost}
    assert json.loads(merge(stored, json.dumps(cost))) == {"usage": usage, "cost": cost}
    assert json.loads(merge(None, json.dumps(cost))) == cost
    assert merge(None, None) is None
    with sqlite3.connect(":memory:") as connection:
        connection.execute("CREATE TABLE scans (id TEXT, status TEXT, cost_json TEXT)")
        connection.execute("INSERT INTO scans VALUES ('scan', 'complete', ?)", (stored,))
        connection.commit()
        workbench_api["scan_usage"].reconcile_completed_scan_cost(
            connection, {"id": "scan", "cost_json": stored}, incoming
        )
        receipt = connection.execute("SELECT cost_json FROM scans").fetchone()[0]
        assert json.loads(receipt) == {"usage": measured, "cost": cost}


@pytest.mark.parametrize(
    ("prior_session_unavailable", "child_session_saved", "merge_state"),
    [
        (False, True, "saved"),
        (True, True, "saved"),
        (False, False, "saved"),
        (False, True, "merged"),
        (False, True, "prepared"),
        (False, True, "not-started"),
        (True, True, "not-started"),
        (False, True, "accepted-without-merge"),
        (False, True, "accepted-with-prepared-merge"),
        (False, True, "started"),
        (True, True, "accepted-without-merge"),
    ],
)
def test_completion_counts_ordinary_child_scans_and_descendants(
    tmp_path: Path,
    prior_session_unavailable: bool,
    child_session_saved: bool,
    merge_state: str,
) -> None:
    fixture = _start_scan(tmp_path, mode="deep")
    environment = fixture.environment
    counted = fixture.started_at + timedelta(microseconds=1)
    directory = fixture.scan_dir / "artifacts" / "deep-scan" / "passes" / "pass-1"
    directory.mkdir(parents=True, mode=0o700)
    child = run_workbench(
        fixture.state_dir,
        "register-cli-scan",
        "--repository",
        str(fixture.target),
        "--scan-dir",
        str(directory),
        "--parent-scan-id",
        fixture.scan_id,
        "--registration-json-stdin",
        input_text=json.dumps(
            {
                "parentScanRole": "deep_pass",
                "recipe": {
                    "repository": str(fixture.target),
                    "mode": "standard",
                    "target": {"kind": "repository", "paths": []},
                    "config": {},
                },
            }
        ),
        environment=environment,
    )
    if child_session_saved:
        run_workbench(
            fixture.state_dir,
            "set-scan-thread",
            "--scan-id",
            child["scanId"],
            "--thread-id",
            "sdk-worker",
            environment=environment,
        )
    else:
        run_workbench(
            fixture.state_dir,
            "fail-scan",
            "--scan-id",
            child["scanId"],
            "--message",
            "Synthetic failure after optional session persistence failed.",
            "--cost-json",
            json.dumps({"model": "synthetic-model", "estimatedUsd": 0.01, **_counts(20, 0, 5)}),
            environment=environment,
        )
    checkpoint = mark_deep_aggregate_ready(fixture.state_dir, fixture.scan_id, fixture.scan_dir)
    document = json.loads(checkpoint.read_text())
    document["passes"] = [{"directory": str(directory), "scanId": child["scanId"]}]
    if merge_state != "saved":
        write_completed_contract(directory, child["scanId"], fixture.target, relative_path="app.py")
        run_workbench(
            fixture.state_dir,
            "complete-scan",
            "--scan-id",
            child["scanId"],
            environment=environment,
        )
        document["passes"][0]["completed"] = True
        if merge_state in {"merged", "accepted-without-merge", "accepted-with-prepared-merge"}:
            document["mergedScanIds"] = [child["scanId"]]
        if merge_state in {"accepted-without-merge", "accepted-with-prepared-merge"}:
            document["mergeStarted"] = False
        elif merge_state == "started":
            document["mergeStarted"] = True
        if merge_state in {"prepared", "accepted-with-prepared-merge"}:
            # Preparation is durable before launch; interrupted contents still record intent.
            (checkpoint.parent / "merge-inputs.json").write_text("{")
        with sqlite3.connect(fixture.state_dir / "workbench.sqlite3") as connection:
            connection.execute(
                "UPDATE scans SET continuation_thread_id = NULL WHERE id = ?", (fixture.scan_id,)
            )
    if prior_session_unavailable:
        document["costUnavailable"] = True
    checkpoint.write_text(json.dumps(document))
    _state_graph(
        environment,
        {
            "scan-parent": _rollout(tmp_path, "scan-parent", [_token_event(counted, 10, 3)]),
            "sdk-worker": _rollout(tmp_path, "sdk-worker", [_token_event(counted, 20, 5)]),
            "sdk-child": _rollout(
                tmp_path,
                "sdk-child",
                [_token_event(counted, 7, 2)],
                parent_thread_id="sdk-worker",
            ),
        },
        [("sdk-worker", "sdk-child")],
    )
    usage = _complete_scan(fixture)["scan"]["usage"]
    incomplete = (
        prior_session_unavailable
        or not child_session_saved
        or merge_state in {"merged", "prepared", "accepted-with-prepared-merge", "started"}
    )
    assert (
        usage.items()
        >= {
            "coverage": "partial" if incomplete else "complete",
            "source": "codex_rollout",
            **(_counts(37, 0, 10) if child_session_saved else _counts(10, 0, 3)),
            "threadCount": 3 if child_session_saved else 1,
            **({"warnings": ["scan_thread_unavailable"]} if incomplete else {}),
        }.items()
    )
    assert usage["byRole"] == {
        "parent": {**_counts(10, 0, 3), "threadCount": 1},
        "workers": {
            **(_counts(27, 0, 7) if child_session_saved else _counts(0, 0, 0)),
            "threadCount": 2 if child_session_saved else 0,
        },
    }
    assert datetime.fromisoformat(usage["window"]["startedAt"]) == fixture.started_at


@pytest.mark.parametrize("readable_usage", [False, True])
def test_native_completion_retains_measured_usage_with_sdk_cost(
    tmp_path: Path, readable_usage: bool
) -> None:
    fixture = _start_scan(tmp_path, mode="deep")
    counted = fixture.started_at + timedelta(microseconds=1)
    if readable_usage:
        _state_graph(
            fixture.environment,
            {
                "scan-parent": _rollout(
                    tmp_path, "scan-parent", [_token_event(counted, 15, 6, cached_input_tokens=4)]
                )
            },
            [],
        )
    cost = {
        "model": "synthetic-model",
        "inputTokens": 15,
        "cachedInputTokens": 4,
        "cacheWriteInputTokens": 0,
        "outputTokens": 6,
        "estimatedUsd": 0.002,
    }
    completed = _complete_scan(fixture, cost=cost)["scan"]
    expected_usage = (
        {
            "coverage": "complete",
            "source": "codex_rollout",
            **_counts(15, 4, 6),
            "threadCount": 1,
        }
        if readable_usage
        else {
            "coverage": "unavailable",
            "source": "codex_rollout",
            "threadCount": 0,
            "warnings": ["codex_state_unavailable"],
        }
    )
    assert completed["cost"] == cost
    assert completed["usage"].items() >= expected_usage.items()
    assert completed["progress"]["status"] == "complete"
    repeated = run_workbench(
        fixture.state_dir,
        "complete-scan",
        "--scan-id",
        fixture.scan_id,
        environment=fixture.environment,
    )["scan"]
    assert repeated["cost"] == cost
    assert repeated["usage"] == completed["usage"]


@pytest.mark.parametrize("readable_usage", [False, True])
def test_fresh_completion_does_not_promote_a_running_cost_estimate(
    tmp_path: Path, readable_usage: bool
) -> None:
    fixture = _start_scan(tmp_path, mode="deep")
    cost = {
        "model": "synthetic-model",
        "inputTokens": 10,
        "cachedInputTokens": 0,
        "cacheWriteInputTokens": 0,
        "outputTokens": 5,
        "estimatedUsd": 0.001,
    }
    with sqlite3.connect(fixture.state_dir / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE scans SET cost_json = ? WHERE id = ?", (json.dumps(cost), fixture.scan_id)
        )
    if readable_usage:
        _state_graph(
            fixture.environment,
            {
                "scan-parent": _rollout(
                    tmp_path,
                    "scan-parent",
                    [_token_event(fixture.started_at + timedelta(microseconds=1), 30, 10)],
                )
            },
            [],
        )
    completed = _complete_scan(fixture)["scan"]
    assert "cost" not in completed
    assert completed["usage"]["coverage"] == ("complete" if readable_usage else "unavailable")
    if readable_usage:
        assert completed["usage"]["totalTokens"] == 40
    with sqlite3.connect(fixture.state_dir / "workbench.sqlite3") as connection:
        receipt = connection.execute(
            "SELECT cost_json FROM scans WHERE id = ?", (fixture.scan_id,)
        ).fetchone()[0]
    assert json.loads(receipt) == {"usage": completed["usage"]}


@pytest.mark.parametrize(
    ("native_database", "native_worker_tokens", "unmeasured_attempt"),
    [(False, None, True), (True, None, True), (True, 150, True), (True, 150, False)],
)
def test_stopped_deep_scan_reconciles_cumulative_worker_receipts(
    tmp_path: Path,
    native_database: bool,
    native_worker_tokens: int | None,
    unmeasured_attempt: bool,
) -> None:
    fixture = _start_scan(tmp_path, mode="deep")
    counted = fixture.started_at + timedelta(microseconds=1)
    timestamp = counted.isoformat()
    directory = _worker_usage_directory(fixture)
    directory.mkdir(parents=True)
    for index, amount in enumerate([100, 150, None] if unmeasured_attempt else [100, 150]):
        attempt_id = str(uuid.uuid4())
        token_counts = (
            _token_event(counted, amount, 0)["payload"]["info"]["total_token_usage"]
            if amount is not None
            else None
        )
        (directory / f"{attempt_id}.json").write_text(
            json.dumps(
                {
                    "schemaVersion": 1,
                    "source": "codex_sdk",
                    "usageScope": "thread_cumulative",
                    "scanId": fixture.scan_id,
                    "workerId": "synthetic-worker",
                    "kind": "discovery",
                    "attemptId": attempt_id,
                    "attempt": index + 1,
                    "resumed": index > 0,
                    "threadId": "receipt-worker" if amount is not None else "unmeasured-worker",
                    "startedAt": timestamp,
                    "observedAt": timestamp,
                    "outcome": "succeeded" if index == 0 else "failed",
                    "usage": token_counts,
                }
            ),
            encoding="utf-8",
        )
    paths = {"scan-parent": _rollout(tmp_path, "scan-parent", [_token_event(counted, 0, 0)])}
    edges = []
    if native_worker_tokens is not None:
        paths["receipt-worker"] = _rollout(
            tmp_path,
            "receipt-worker",
            [_token_event(counted, native_worker_tokens, 0)],
            parent_thread_id="scan-parent",
        )
        edges.append(("scan-parent", "receipt-worker"))
    if native_database:
        _state_graph(fixture.environment, paths, edges)
    for _ in range(2):
        measurement = fail_scan(
            fixture.state_dir, fixture.scan_id, "Fixture failure.", environment=fixture.environment
        )["scan"]["usage"]
        assert measurement["coverage"] == (
            "partial" if unmeasured_attempt or native_worker_tokens is None else "complete"
        )
        assert measurement["totalTokens"] == 150
        assert measurement["byRole"]["workers"]["totalTokens"] == 150
        assert measurement["threadCount"] == (2 if native_database else 1)
        assert measurement.get("missingThreadCount", 0) == (
            int(unmeasured_attempt) + int(native_worker_tokens is None) + int(not native_database)
        )
        assert ("worker_usage_unavailable" in measurement.get("warnings", [])) == unmeasured_attempt
        assert measurement["source"] == (
            "codex_rollout" if native_worker_tokens is not None else "codex_runtime"
        )


@pytest.mark.parametrize("reverse_files", [False, True])
@pytest.mark.parametrize("native_workers", [False, True])
def test_worker_receipts_preserve_cumulative_totals_and_known_cache_writes(
    tmp_path: Path, reverse_files: bool, native_workers: bool
) -> None:
    fixture = _start_scan(tmp_path, mode="deep")
    counted = fixture.started_at + timedelta(microseconds=1)
    directory = _worker_usage_directory(fixture)
    directory.mkdir(parents=True)
    snapshots = [
        ("first-worker", 100, 5, True, 0),
        ("first-worker", 150, 8, True, 1),
        ("first-worker", 150, 12, True, 2),
        ("first-worker", 150, 0, False, 3),
        ("second-worker", 40, 4, True, 1),
    ]
    for index, (thread_id, amount, cache_writes, reported, delay) in enumerate(snapshots):
        attempt_id = str(uuid.UUID(int=len(snapshots) - index if reverse_files else index + 1))
        tokens = _token_event(counted, amount, 0)["payload"]["info"]["total_token_usage"]
        tokens["cache_write_input_tokens"] = cache_writes
        if not reported:
            tokens["cache_write_input_tokens_reported"] = False
        (directory / f"{attempt_id}.json").write_text(
            json.dumps(
                {
                    "schemaVersion": 1,
                    "source": "codex_sdk",
                    "usageScope": "thread_cumulative",
                    "scanId": fixture.scan_id,
                    "workerId": thread_id,
                    "kind": "discovery",
                    "attemptId": attempt_id,
                    "attempt": index + 1,
                    "resumed": index > 0,
                    "threadId": thread_id,
                    "startedAt": counted.isoformat(),
                    "observedAt": (counted + timedelta(microseconds=delay)).isoformat(),
                    "outcome": "succeeded",
                    "usage": tokens,
                }
            ),
            encoding="utf-8",
        )
    paths = {"scan-parent": _rollout(tmp_path, "scan-parent", [_token_event(counted, 0, 0)])}
    edges = []
    if native_workers:
        for thread_id, amount in (("first-worker", 150), ("second-worker", 40)):
            event = _token_event(counted, amount, 0)
            event["payload"]["info"]["total_token_usage"].pop("cache_write_input_tokens")
            paths[thread_id] = _rollout(
                tmp_path, thread_id, [event], parent_thread_id="scan-parent"
            )
            edges.append(("scan-parent", thread_id))
    _state_graph(fixture.environment, paths, edges)
    for _ in range(2):
        measurement = fail_scan(
            fixture.state_dir, fixture.scan_id, "Fixture failure.", environment=fixture.environment
        )["scan"]["usage"]
        assert measurement["totalTokens"] == 190
        assert measurement["cacheWriteInputTokens"] == 16
        assert "cacheWriteInputTokensReported" not in measurement
        assert measurement["source"] == "codex_runtime"
        assert measurement["threadCount"] == 3
        assert measurement["coverage"] == ("complete" if native_workers else "partial")
        assert measurement.get("missingThreadCount", 0) == (0 if native_workers else 2)


@pytest.mark.parametrize(
    "native_state",
    ["complete", "partial", "absent", "unknown_thread", "late_thread_id", "sdk_subtotal_larger"],
)
def test_stopped_deep_scan_reconciles_missing_sdk_receipts_with_native_usage(
    tmp_path: Path, native_state: str
) -> None:
    fixture = _start_scan(tmp_path, mode="deep")
    counted = fixture.started_at + timedelta(microseconds=1)
    directory = _worker_usage_directory(fixture)
    directory.mkdir(parents=True)
    for amount in [None, 30] if native_state == "sdk_subtotal_larger" else [None]:
        attempt_id = str(uuid.uuid4())
        (directory / f"{attempt_id}.json").write_text(
            json.dumps(
                {
                    "schemaVersion": 1,
                    "source": "codex_sdk",
                    "usageScope": "thread_cumulative",
                    "scanId": fixture.scan_id,
                    "workerId": "synthetic-worker",
                    "kind": "discovery",
                    "attemptId": attempt_id,
                    "attempt": 1 if amount is None else 2,
                    "resumed": amount is not None,
                    "threadId": (
                        None
                        if native_state in ("unknown_thread", "late_thread_id")
                        else "receipt-worker"
                    ),
                    "startedAt": counted.isoformat(),
                    "observedAt": counted.isoformat(),
                    "outcome": "failed",
                    "usage": (
                        _token_event(counted, amount, 0)["payload"]["info"]["total_token_usage"]
                        if amount is not None
                        else None
                    ),
                }
            ),
            encoding="utf-8",
        )
    parent = _rollout(tmp_path, "scan-parent", [_token_event(counted, 0, 0)])
    worker = parent.with_name("receipt-worker.jsonl")
    _state_graph(
        fixture.environment,
        {"scan-parent": parent, "receipt-worker": worker},
        [("scan-parent", "receipt-worker")],
    )
    initial = fail_scan(
        fixture.state_dir, fixture.scan_id, "Fixture failure.", environment=fixture.environment
    )["scan"]["usage"]
    assert initial["coverage"] == "partial"
    assert "worker_usage_unavailable" in initial["warnings"]
    attempt_scope = {f"worker-attempt:{path.stem}" for path in directory.glob("*.json")}
    assert attempt_scope.issubset(initial["coverageScope"])
    if native_state == "late_thread_id":
        path = directory / f"{attempt_id}.json"
        receipt = json.loads(path.read_text(encoding="utf-8"))
        receipt["threadId"] = "receipt-worker"
        path.write_text(json.dumps(receipt), encoding="utf-8")

    if native_state != "absent":
        _rollout(
            tmp_path,
            "receipt-worker",
            [_token_event(counted, 20, 5)],
            parent_thread_id="scan-parent",
            include_task_complete=native_state != "partial",
        )
    for _ in range(2):
        measurement = fail_scan(
            fixture.state_dir, fixture.scan_id, "Fixture failure.", environment=fixture.environment
        )["scan"]["usage"]
        complete = native_state in ("complete", "late_thread_id")
        assert measurement["coverage"] == ("complete" if complete else "partial")
        assert measurement["totalTokens"] == (
            30 if native_state == "sdk_subtotal_larger" else 0 if native_state == "absent" else 25
        )
        assert measurement.get("missingThreadCount", 0) == int(not complete)
        assert ("worker_usage_unavailable" in measurement.get("warnings", [])) == (not complete)
        assert attempt_scope.issubset(measurement["coverageScope"])
        if native_state == "partial":
            assert "turn_in_progress" in measurement["warnings"]
