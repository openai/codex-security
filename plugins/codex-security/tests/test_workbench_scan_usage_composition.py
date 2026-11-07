"""Verify composed Deep Scan accounting and persisted worker receipts."""

from __future__ import annotations

import json
import os
import sqlite3
import sys
import uuid
from dataclasses import replace
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from test_workbench_scan_usage import (
    ScanFixture,
    _allowance_event,
    _complete_scan,
    _rollout,
    _start_scan,
    _state_graph,
    _token_event,
    _worker_usage_directory,
)
from workbench_test_support import (
    create_saved_workspace,
    fail_scan,
    mark_deep_aggregate_ready,
    private_directory,
    published_artifacts,
    register,
    run_workbench,
    scan_command,
    start_delivered_scan,
    write_completed_contract,
)
from workbench_test_support import usage_counts as _counts

pytestmark = pytest.mark.native_macos


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
    assert json.loads(merge(stored, incoming)) == json.loads(incoming)
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
        assert json.loads(receipt) == json.loads(incoming)


@pytest.mark.parametrize(
    ("prior_session_unavailable", "child_session_saved", "merge_kind"),
    [
        (False, True, "recorded"),
        (True, True, "recorded"),
        (False, False, "recorded"),
        (False, True, "missing"),
        (False, True, "deterministic"),
        (False, True, "deterministic-implicit"),
    ],
)
def test_completion_counts_ordinary_child_scans_and_descendants(
    tmp_path: Path,
    prior_session_unavailable: bool,
    child_session_saved: bool,
    merge_kind: str,
) -> None:
    fixture = _start_scan(tmp_path, mode="deep")
    environment = fixture.environment
    counted = fixture.started_at + timedelta(microseconds=1)
    directory = fixture.scan_dir / "artifacts" / "deep-scan" / "passes" / "pass-1"
    private_directory(directory)
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
    if merge_kind == "deterministic-implicit":
        document.pop("mergeStarted", None)
    else:
        document["mergeStarted"] = merge_kind != "deterministic"
    if merge_kind == "recorded":
        run_workbench(
            fixture.state_dir,
            "set-scan-thread",
            "--scan-id",
            fixture.scan_id,
            "--thread-id",
            "scan-parent",
            environment=environment,
        )
    else:
        write_completed_contract(directory, child["scanId"], fixture.target, relative_path="app.py")
        run_workbench(
            fixture.state_dir,
            "complete-scan",
            "--scan-id",
            child["scanId"],
            environment=environment,
        )
        document["passes"][0]["completed"] = True
        document["mergedScanIds"] = [child["scanId"]]
        with sqlite3.connect(fixture.state_dir / "workbench.sqlite3") as connection:
            connection.execute(
                "UPDATE scans SET continuation_thread_id = NULL WHERE id = ?", (fixture.scan_id,)
            )
    if prior_session_unavailable:
        document["costUnavailable"] = True
    checkpoint.write_text(json.dumps(document))
    _state_graph(
        fixture.environment,
        {
            "scan-parent": _rollout(tmp_path, "scan-parent", [_token_event(counted, 10, 3)]),
            "sdk-worker": _rollout(tmp_path, "sdk-worker", [_token_event(counted, 20, 5)]),
            "sdk-child": _rollout(
                tmp_path,
                "sdk-child",
                [_token_event(counted, 7, 2)],
                parent_thread_id="sdk-worker",
            ),
            "sdk-retry": _rollout(tmp_path, "sdk-retry", [_token_event(counted, 30, 3)]),
        },
        [("sdk-worker", "sdk-child")],
    )
    usage = _complete_scan(fixture)["scan"]["usage"]
    incomplete = prior_session_unavailable or not child_session_saved or merge_kind == "missing"
    expected = {
        "coverage": "partial" if incomplete else "complete",
        "source": "codex_rollout",
        **(_counts(37, 0, 10) if child_session_saved else _counts(10, 0, 3)),
        "threadCount": 3 if child_session_saved else 1,
        **({"warnings": ["scan_thread_unavailable"]} if incomplete else {}),
    }

    assert usage.items() >= expected.items()
    assert usage.get("warnings", []) == expected.get("warnings", [])
    assert usage["byRole"] == {
        "parent": {**_counts(10, 0, 3), "threadCount": 1},
        "workers": {
            **(_counts(27, 0, 7) if child_session_saved else _counts(0, 0, 0)),
            "threadCount": 2 if child_session_saved else 0,
        },
    }


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


@pytest.mark.parametrize("home_variable", ["CODEX_HOME", "CODEX_SQLITE_HOME"])
@pytest.mark.parametrize("home_kind", ["absolute", "literal_tilde", "relative_home", "home"])
def test_completion_reads_usage_from_literal_home(
    tmp_path: Path, home_variable: str, home_kind: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = _start_scan(tmp_path)
    home = tmp_path / ("native home" if sys.platform == "win32" else "native home ")
    if home_kind == "literal_tilde":
        home = tmp_path / ("~ literal" if sys.platform == "win32" else "~ ")
    fixture.environment["CODEX_SQLITE_HOME"] = str(home)
    parent = _rollout(
        tmp_path,
        "scan-parent",
        [_token_event(fixture.started_at + timedelta(microseconds=1), 12, 3)],
    )
    _state_graph(fixture.environment, {"scan-parent": parent}, [])
    configured_home = str(home)
    if home_kind == "literal_tilde":
        monkeypatch.chdir(tmp_path)
        configured_home = home.name
    elif home_kind in {"relative_home", "home"}:
        monkeypatch.setenv("HOME", str(home if home_kind == "home" else tmp_path))
        monkeypatch.setenv("USERPROFILE", str(home if home_kind == "home" else tmp_path))
        configured_home = "~" if home_kind == "home" else f"~/{home.name}"
    fixture.environment[home_variable] = configured_home
    if home_variable == "CODEX_HOME":
        fixture.environment["CODEX_SQLITE_HOME"] = ""

    usage = _complete_scan(fixture)["scan"]["usage"]

    assert usage["coverage"] == "complete"
    assert usage["totalTokens"] == 15


@pytest.mark.parametrize("mode", ["standard", "deep"])
@pytest.mark.parametrize("delayed_cache_counts", [False, True])
def test_completion_preserves_explicit_legacy_cost(
    tmp_path: Path, mode: str, delayed_cache_counts: bool
) -> None:
    fixture = _start_scan(tmp_path, mode=mode)
    # Ordinary SDK registration has no native execution owner.
    with sqlite3.connect(fixture.state_dir / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE scans SET deep_scan_owner_thread_id = NULL WHERE id = ?", (fixture.scan_id,)
        )
    counted = fixture.started_at + timedelta(microseconds=1)
    _state_graph(
        fixture.environment,
        {
            "scan-parent": _rollout(
                tmp_path,
                "scan-parent",
                [
                    _token_event(fixture.started_at - timedelta(seconds=1), 100, 0),
                    _token_event(
                        counted, 115, 6, cached_input_tokens=100 if delayed_cache_counts else 0
                    ),
                    _allowance_event(counted, 6),
                ],
            )
        },
        [],
    )
    cost = {
        "model": "gpt-5.6-sol",
        "inputTokens": 15,
        "cachedInputTokens": 4,
        "cacheWriteInputTokens": 0,
        "outputTokens": 6,
        "estimatedUsd": 0.002,
    }
    completed = _complete_scan(fixture, cost=cost)["scan"]
    assert completed["cost"] == cost
    assert completed["usage"]["accountRateLimits"][0]["primary"]["usedPercent"] == 6
    if delayed_cache_counts:
        assert completed["usage"]["coverage"] == "unavailable"
        assert completed["usage"]["warnings"] == ["token_breakdown_unavailable"]
        assert "totalTokens" not in completed["usage"]
    else:
        assert completed["usage"]["totalTokens"] == 21


@pytest.mark.parametrize("checkpoint_kind", ["malformed", "directory", "symlink"])
@pytest.mark.parametrize("supplied_cost", [False, True])
def test_optional_usage_failure_does_not_hide_invalid_scan_state(
    tmp_path: Path, workbench_api, monkeypatch, capsys, checkpoint_kind: str, supplied_cost: bool
) -> None:
    if checkpoint_kind == "symlink" and os.name == "nt":
        pytest.skip("Creating symbolic links requires separate Windows privileges.")
    state, target = tmp_path / "state", tmp_path / "target"
    monkeypatch.setenv("CODEX_SECURITY_STATE_DIR", str(state))
    target.mkdir()
    (target / "app.py").write_text("print('fixture')\n")
    environment = {"CODEX_HOME": str(tmp_path / "codex-home"), "CODEX_STATE_DB": ""}
    workspace = create_saved_workspace(state, target, thread_id="scan-parent", mode="deep")
    scan = start_delivered_scan(state, workspace["id"], "--scan-root", str(tmp_path / "scans"))
    scan_id, scan_dir = scan["scanId"], Path(scan["scanDir"])
    run_workbench(
        state,
        "begin-deep-scan",
        "--scan-id",
        scan_id,
        "--thread-id",
        "scan-parent",
        environment=environment,
    )
    mark_deep_aggregate_ready(state, scan_id, scan_dir)
    write_completed_contract(
        scan_dir, scan_id, target, relative_path="app.py", coverage_mode="deep_repository"
    )
    checkpoint = scan_dir / "artifacts/deep-scan/checkpoint.json"
    checkpoint.parent.mkdir(parents=True, exist_ok=True)
    checkpoint.unlink(missing_ok=True)
    outside = tmp_path / "outside.json"
    outside.write_text('{"synthetic":"outside checkpoint"}')
    if checkpoint_kind == "malformed":
        checkpoint.write_text("{")
    elif checkpoint_kind == "directory":
        checkpoint.mkdir()
    else:
        checkpoint.symlink_to(outside)
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.row_factory = sqlite3.Row
        stored = connection.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        with pytest.raises(workbench_api["ContractError"]) as rejected:
            workbench_api["load_composition"](connection, stored)
        usage = workbench_api["scan_usage"].collect_scan_usage(connection, stored)
    diagnostic = str(rejected.value)
    assert diagnostic in capsys.readouterr().err
    cost = {
        "model": "synthetic-model",
        "inputTokens": 15,
        "cachedInputTokens": 4,
        "cacheWriteInputTokens": 0,
        "outputTokens": 6,
        "estimatedUsd": 0.002,
    }
    arguments = ["--cost-json", json.dumps(cost)] if supplied_cost else []
    result = run_workbench(
        state,
        "complete-scan",
        "--scan-id",
        scan_id,
        *arguments,
        environment=environment,
        check=False,
    )
    assert result["returncode"] != 0
    assert diagnostic in result["stderr"]
    assert usage == {
        "coverage": "unavailable",
        "source": "codex_rollout",
        "threadCount": 0,
        "warnings": ["composition_checkpoint_unavailable"],
    }
    assert outside.read_text() == '{"synthetic":"outside checkpoint"}'
    if checkpoint_kind == "malformed":
        assert checkpoint.read_text() == "{"
    elif checkpoint_kind == "directory":
        assert checkpoint.is_dir()
    else:
        assert checkpoint.is_symlink()


@pytest.mark.parametrize("merged_scan_ids", [None, []])
def test_optional_usage_incomplete_checkpoint_allows_completion_retry(
    tmp_path: Path, merged_scan_ids: list[str] | None
) -> None:
    state, target = tmp_path / "state", tmp_path / "target"
    target.mkdir()
    (target / "app.py").write_text("print('fixture')\n")
    environment = {
        "CODEX_HOME": str(tmp_path / "home"),
        "CODEX_SQLITE_HOME": str(tmp_path / "sqlite"),
        "CODEX_STATE_DB": "",
    }
    _state_graph(environment, {}, [])
    scan = run_workbench(
        state,
        "begin-deep-scan",
        "--target-path",
        str(target),
        "--thread-id",
        "synthetic-owner",
        "--scope",
        ".",
        "--scan-root",
        str(tmp_path / "scans"),
        environment=environment,
    )["scan"]
    scan_id, scan_dir = scan["scanId"], Path(scan["scanDir"])
    mark_deep_aggregate_ready(state, scan_id, scan_dir)
    write_completed_contract(
        scan_dir, scan_id, target, relative_path="app.py", coverage_mode="deep_repository"
    )
    checkpoint = json.loads((scan_dir / "artifacts/deep-scan/checkpoint.json").read_text())
    checkpoint.pop("mergedScanIds", None)
    if merged_scan_ids is not None:
        checkpoint["mergedScanIds"] = merged_scan_ids
    checkpoint_path = scan_dir / "artifacts/deep-scan/checkpoint.json"
    checkpoint_path.write_text(json.dumps(checkpoint))
    original = checkpoint_path.read_bytes()
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        assert connection.execute(
            "SELECT continuation_thread_id FROM scans WHERE id = ?", (scan_id,)
        ).fetchone() == ("synthetic-owner",)
        claim_token = connection.execute(
            "SELECT handoff_claim_token FROM scans WHERE id = ?", (scan_id,)
        ).fetchone()[0]
    documents = None
    for _ in range(2):
        completed = run_workbench(
            state,
            "complete-scan",
            "--scan-id",
            scan_id,
            "--claim-token",
            claim_token,
            environment=environment,
        )["scan"]
        assert completed["progress"]["status"] == "complete"
        assert completed["findingCount"] == 1
        assert completed["reportAvailable"] is True
        assert completed["usage"]["coverage"] == "unavailable"
        assert checkpoint_path.read_bytes() == original
        current = tuple(
            (scan_dir / name).read_bytes()
            for name in ("scan-manifest.json", "findings.json", "coverage.json")
        )
        if documents is not None:
            assert current == documents
        documents = current


def test_usage_is_returned_by_completion_without_an_extra_command(tmp_path: Path) -> None:
    fixture = _start_scan(tmp_path)
    counted = fixture.started_at + timedelta(microseconds=1)
    _state_graph(
        fixture.environment,
        {"scan-parent": _rollout(tmp_path, "scan-parent", [_token_event(counted, 12, 4)])},
        [],
    )
    assert _complete_scan(fixture)["scan"]["usage"]["totalTokens"] == 16
    extra_command = scan_command(
        fixture.state_dir,
        "get-scan-usage",
        fixture.scan_id,
        check=False,
        environment=fixture.environment,
    )
    assert extra_command["returncode"] != 0
    assert "invalid choice" in str(extra_command["stderr"])


def test_failed_scan_preserves_legacy_failure_behavior(tmp_path: Path) -> None:
    fixture = _start_scan(tmp_path)
    counted = fixture.started_at + timedelta(microseconds=1)
    _state_graph(
        fixture.environment,
        {"scan-parent": _rollout(tmp_path, "scan-parent", [_token_event(counted, 21, 8)])},
        [],
    )
    failed = fail_scan(
        fixture.state_dir, fixture.scan_id, "Fixture failure.", environment=fixture.environment
    )["scan"]
    assert failed["progress"]["status"] == "failed"
    assert failed["usage"]["totalTokens"] == 29
    assert failed["usage"]["threadCount"] == 1


def test_completed_accounting_survives_migration_without_importing_sidecar_sessions(
    tmp_path: Path,
) -> None:
    fixture = _start_scan(tmp_path, mode="deep")
    counted = fixture.started_at + timedelta(microseconds=1)
    for thread in ("prior-merge", "scan-parent"):
        run_workbench(
            fixture.state_dir,
            "set-scan-thread",
            "--scan-id",
            fixture.scan_id,
            "--thread-id",
            thread,
            environment=fixture.environment,
        )
    _state_graph(
        fixture.environment,
        {
            "scan-parent": _rollout(tmp_path, "scan-parent", [_token_event(counted, 10, 3)]),
            "prior-merge": _rollout(tmp_path, "prior-merge", [_token_event(counted, 20, 5)]),
        },
        [],
    )
    completed = _complete_scan(fixture)["scan"]
    assert completed["usage"]["coverage"] == "complete"
    assert completed["usage"]["totalTokens"] == 38
    sidecar = fixture.scan_dir / "artifacts/deep-scan/execution-threads.json"
    original = json.dumps(["prior-merge", "follow-up"]).encode()
    sidecar.write_bytes(original)
    database = fixture.state_dir / "workbench.sqlite3"
    with sqlite3.connect(database) as connection:
        receipt = connection.execute(
            "SELECT cost_json FROM scans WHERE id = ?", (fixture.scan_id,)
        ).fetchone()[0]
        connection.execute("DROP TABLE scan_execution_threads")
        connection.execute(
            "DELETE FROM schema_migrations WHERE name = 'persist scan execution sessions'"
        )
    migrated = run_workbench(
        fixture.state_dir,
        "get-scan",
        "--scan-id",
        fixture.scan_id,
        environment=fixture.environment,
    )["scan"]
    assert migrated["usage"] == completed["usage"]
    assert not {"prior-merge", "follow-up"} & set(migrated["executionThreadIds"])
    assert sidecar.read_bytes() == original
    with sqlite3.connect(database) as connection:
        assert (
            connection.execute(
                "SELECT cost_json FROM scans WHERE id = ?", (fixture.scan_id,)
            ).fetchone()[0]
            == receipt
        )
    sidecar.write_text('["not-imported-on-reopen"]')
    reopened = run_workbench(
        fixture.state_dir,
        "get-scan",
        "--scan-id",
        fixture.scan_id,
        environment=fixture.environment,
    )["scan"]
    assert reopened["executionThreadIds"] == migrated["executionThreadIds"]
    assert reopened["usage"] == completed["usage"]


def test_historical_worker_sessions_still_contribute_after_schema_migration(tmp_path: Path) -> None:
    fixture = _start_scan(tmp_path, mode="deep")
    timestamp = fixture.started_at.isoformat()
    # This database has already applied the execution-thread migration. Older
    # versions could subsequently append worker associations to their own table.
    with sqlite3.connect(fixture.state_dir / "workbench.sqlite3") as connection:
        connection.execute(
            "INSERT INTO deep_scan_workers "
            "(id, scan_id, kind, status, sdk_thread_id, prompt_path, artifact_dir, "
            "created_at, updated_at) VALUES (?, ?, 'discovery', 'succeeded', ?, ?, ?, ?, ?)",
            (
                str(uuid.uuid4()),
                fixture.scan_id,
                "historical-worker",
                str(tmp_path / "prompt.md"),
                str(tmp_path / "worker"),
                timestamp,
                timestamp,
            ),
        )
    counted = fixture.started_at + timedelta(microseconds=1)
    _state_graph(
        fixture.environment,
        {
            "scan-parent": _rollout(tmp_path, "scan-parent", [_token_event(counted, 10, 0)]),
            "historical-worker": _rollout(
                tmp_path, "historical-worker", [_token_event(counted, 100, 0)]
            ),
        },
        [],
    )
    completed = _complete_scan(fixture)["scan"]
    expected = {
        "coverage": "complete",
        "source": "codex_rollout",
        **_counts(110, 0, 0),
        "threadCount": 2,
    }
    assert "historical-worker" in completed["executionThreadIds"]
    assert "historical-worker" in completed["threadIds"]

    assert completed["usage"].items() >= expected.items()

    assert completed["usage"]["byRole"] == {
        "parent": {**_counts(10, 0, 0), "threadCount": 1},
        "workers": {**_counts(100, 0, 0), "threadCount": 1},
    }


@pytest.mark.parametrize("include_current_cost", [False, True])
def test_completion_refreshes_usage_preserved_before_more_work(
    tmp_path: Path, include_current_cost: bool
) -> None:
    fixture = _start_scan(tmp_path)
    cost = {
        "model": "synthetic-model",
        "inputTokens": 15,
        "cachedInputTokens": 0,
        "cacheWriteInputTokens": 0,
        "outputTokens": 6,
        "estimatedUsd": 0.002,
    }
    prior_usage = {
        "coverage": "complete",
        "source": "codex_rollout",
        **_counts(5, 0, 1),
        "threadCount": 1,
    }
    with sqlite3.connect(fixture.state_dir / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE scans SET cost_json = ?, deep_scan_owner_thread_id = NULL WHERE id = ?",
            (json.dumps({"usage": prior_usage, "cost": cost}), fixture.scan_id),
        )
    _state_graph(
        fixture.environment,
        {
            "scan-parent": _rollout(
                tmp_path,
                "scan-parent",
                [_token_event(fixture.started_at + timedelta(microseconds=1), 15, 6)],
            )
        },
        [],
    )
    completed = _complete_scan(fixture, cost=cost if include_current_cost else None)["scan"]
    assert completed["cost"] == cost
    assert completed["usage"].items() >= {**prior_usage, **_counts(15, 0, 6)}.items()


@pytest.mark.parametrize("mode", ["standard", "diff"])
@pytest.mark.parametrize(
    ("saved_coverage", "final_usage"),
    [
        ("complete", "unavailable"),
        ("partial", "unavailable"),
        ("unavailable", "unavailable"),
        ("complete", "measured"),
        ("complete", "explicit"),
    ],
)
def test_completion_marks_retained_usage_partial_when_final_measurement_is_unavailable(
    tmp_path: Path, mode: str, saved_coverage: str, final_usage: str
) -> None:
    fixture = _start_scan(tmp_path, mode=mode)
    earlier_usage: dict[str, Any] = {
        "coverage": saved_coverage,
        "source": "codex_rollout",
        "threadCount": 0 if saved_coverage == "unavailable" else 1,
    }
    if saved_coverage != "unavailable":
        earlier_usage.update(_counts(10, 0, 2))
    if saved_coverage != "complete":
        earlier_usage["warnings"] = ["rollout_unavailable"]
    earlier_cost = {
        "model": "synthetic-model",
        "inputTokens": 10,
        "cachedInputTokens": 0,
        "cacheWriteInputTokens": 0,
        "outputTokens": 2,
        "estimatedUsd": 0.01,
    }
    preserved = run_workbench(
        fixture.state_dir,
        "preserve-scan-results",
        "--scan-id",
        fixture.scan_id,
        "--cost-json",
        json.dumps({"cost": earlier_cost, "usage": earlier_usage}),
        environment=fixture.environment,
    )["scan"]
    assert preserved["usage"] == earlier_usage
    current_cost = {**earlier_cost, "inputTokens": 30, "outputTokens": 6, "estimatedUsd": 0.03}
    current_usage = {
        "coverage": "complete",
        "source": "codex_rollout",
        **_counts(30, 0, 6),
        "threadCount": 1,
    }
    if final_usage == "measured":
        counted = fixture.started_at + timedelta(microseconds=1)
        _state_graph(
            fixture.environment,
            {"scan-parent": _rollout(tmp_path, "scan-parent", [_token_event(counted, 30, 6)])},
            [],
        )
    incoming = (
        {"cost": current_cost, "usage": current_usage}
        if final_usage == "explicit"
        else current_cost
    )
    completed = _complete_scan(fixture, cost=incoming)["scan"]
    if final_usage != "unavailable":
        expected_usage = current_usage
    elif saved_coverage == "unavailable":
        expected_usage = {
            "coverage": "unavailable",
            "source": "codex_rollout",
            "threadCount": 0,
            "warnings": ["codex_state_unavailable"],
        }
    else:
        expected_usage = {
            **earlier_usage,
            "coverage": "partial",
            "warnings": sorted({*earlier_usage.get("warnings", []), "codex_state_unavailable"}),
        }
    assert completed["usage"].items() >= expected_usage.items()
    assert completed["cost"] == current_cost
    documents = published_artifacts(fixture.scan_dir)
    for command in ("get-scan", "complete-scan"):
        repeated = run_workbench(
            fixture.state_dir,
            command,
            "--scan-id",
            fixture.scan_id,
            environment=fixture.environment,
        )["scan"]
        assert repeated["usage"] == completed["usage"]
        assert repeated["cost"] == current_cost
    with sqlite3.connect(fixture.state_dir / "workbench.sqlite3") as connection:
        stored = connection.execute(
            "SELECT cost_json FROM scans WHERE id = ?", (fixture.scan_id,)
        ).fetchone()[0]
    assert json.loads(stored) == {"cost": current_cost, "usage": completed["usage"]}
    assert published_artifacts(fixture.scan_dir) == documents


@pytest.mark.parametrize("mode", ["standard", "diff"])
@pytest.mark.parametrize("final_usage", ["partial", "larger_partial", "complete", "explicit"])
def test_completion_retains_known_usage_when_only_some_rollouts_remain(
    tmp_path: Path, monkeypatch, workbench_api, mode: str, final_usage: str
) -> None:
    fixture = _start_scan(tmp_path, mode=mode)
    for name, value in fixture.environment.items():
        monkeypatch.setenv(name, value)
    counted = fixture.started_at + timedelta(microseconds=1)
    parent = _rollout(
        tmp_path,
        "scan-parent",
        [_token_event(counted, 100, 20, cached_input_tokens=10, reasoning_output_tokens=4)],
    )
    worker = _rollout(
        tmp_path,
        "scan-worker",
        [_token_event(counted, 1000, 200, cached_input_tokens=100, reasoning_output_tokens=40)],
        parent_thread_id="scan-parent",
    )
    _state_graph(
        fixture.environment,
        {"scan-parent": parent, "scan-worker": worker},
        [("scan-parent", "scan-worker")],
    )
    with sqlite3.connect(fixture.state_dir / "workbench.sqlite3") as connection:
        connection.row_factory = sqlite3.Row
        scan = connection.execute("SELECT * FROM scans WHERE id = ?", (fixture.scan_id,)).fetchone()
        earlier_usage = workbench_api["scan_usage"].collect_scan_usage(connection, scan)
    earlier_expected = {
        "coverage": "complete",
        "source": "codex_rollout",
        **_counts(1100, 110, 220, 44),
        "threadCount": 2,
    }
    assert earlier_usage.items() >= earlier_expected.items()
    cost = {
        "model": "synthetic-model",
        "inputTokens": 1100,
        "cachedInputTokens": 110,
        "cacheWriteInputTokens": 0,
        "outputTokens": 220,
        "estimatedUsd": 0.11,
    }
    preserved = run_workbench(
        fixture.state_dir,
        "preserve-scan-results",
        "--scan-id",
        fixture.scan_id,
        "--cost-json",
        json.dumps({"cost": cost, "usage": earlier_usage}),
        environment=fixture.environment,
    )["scan"]
    assert preserved["usage"] == earlier_usage
    large = final_usage == "larger_partial"
    _rollout(
        tmp_path,
        "scan-parent",
        [
            _token_event(
                counted,
                2000 if large else 200,
                300 if large else 30,
                cached_input_tokens=200 if large else 20,
                reasoning_output_tokens=60 if large else 6,
            )
        ],
    )
    if final_usage != "complete":
        worker.unlink()
    with sqlite3.connect(fixture.state_dir / "workbench.sqlite3") as connection:
        connection.row_factory = sqlite3.Row
        scan = connection.execute("SELECT * FROM scans WHERE id = ?", (fixture.scan_id,)).fetchone()
        measured = workbench_api["scan_usage"].collect_scan_usage(connection, scan)
    assert measured["coverage"] == ("complete" if final_usage == "complete" else "partial")
    current_cost = {**cost, "inputTokens": 1200, "outputTokens": 230, "estimatedUsd": 0.12}
    explicit = {
        "coverage": "complete",
        "source": "codex_rollout",
        **_counts(50, 5, 5, 1),
        "threadCount": 1,
    }
    incoming = (
        {"cost": current_cost, "usage": explicit} if final_usage == "explicit" else current_cost
    )
    completed = _complete_scan(fixture, cost=incoming)["scan"]
    expected = (
        {**earlier_usage, "coverage": "partial", "warnings": ["rollout_unavailable"]}
        if final_usage == "partial"
        else explicit
        if final_usage == "explicit"
        else measured
    )
    if large:
        expected = {
            **expected,
            "warnings": sorted(
                {*expected.get("warnings", []), "cost_estimate_covers_earlier_usage"}
            ),
        }
    assert (
        completed["usage"].items()
        >= {
            key: value for key, value in expected.items() if key not in {"window", "observedAt"}
        }.items()
    )
    assert completed["cost"] == current_cost
    documents = published_artifacts(fixture.scan_dir)
    repeated = run_workbench(
        fixture.state_dir,
        "complete-scan",
        "--scan-id",
        fixture.scan_id,
        environment=fixture.environment,
    )["scan"]
    assert repeated["usage"] == completed["usage"]
    assert repeated["cost"] == current_cost
    assert published_artifacts(fixture.scan_dir) == documents


def _record_composition_thread(fixture: ScanFixture, directory: Path, thread_id: str) -> str:
    with sqlite3.connect(fixture.state_dir / "workbench.sqlite3") as connection:
        row = connection.execute(
            "SELECT id FROM scans WHERE scan_dir = ?", (str(directory),)
        ).fetchone()
    child = (
        row[0]
        if row
        else register(
            fixture.state_dir, fixture.target, directory, parent=fixture.scan_id, role="deep_pass"
        )["scanId"]
    )
    run_workbench(
        fixture.state_dir,
        "set-scan-thread",
        "--scan-id",
        child,
        "--thread-id",
        thread_id,
        environment=fixture.environment,
    )
    return child


def test_completion_counts_child_scan_sessions_and_descendants(tmp_path: Path) -> None:
    fixture = _start_scan(tmp_path, mode="deep")
    counted = fixture.started_at + timedelta(microseconds=1)
    artifact = fixture.scan_dir / "artifacts" / "usage-worker"
    private_directory(artifact)
    for thread in ["sdk-worker", "sdk-retry", "sdk-retry"]:
        _record_composition_thread(fixture, artifact, thread)

    _state_graph(
        fixture.environment,
        {
            "scan-parent": _rollout(tmp_path, "scan-parent", [_token_event(counted, 10, 3)]),
            "sdk-worker": _rollout(tmp_path, "sdk-worker", [_token_event(counted, 20, 5)]),
            "sdk-child": _rollout(
                tmp_path,
                "sdk-child",
                [_token_event(counted, 7, 2)],
                parent_thread_id="sdk-worker",
            ),
            "sdk-retry": _rollout(tmp_path, "sdk-retry", [_token_event(counted, 30, 3)]),
        },
        [("sdk-worker", "sdk-child")],
    )
    usage = _complete_scan(fixture)["scan"]["usage"]
    assert (
        usage.items()
        >= {
            "coverage": "complete",
            "source": "codex_rollout",
            **_counts(67, 0, 13),
            "threadCount": 4,
        }.items()
    )


def test_completion_recovers_replaced_child_scan_threads(tmp_path: Path) -> None:
    fixture = _start_scan(tmp_path, mode="deep")
    fixture = replace(
        fixture,
        started_at=(fixture.started_at - timedelta(seconds=1)).replace(microsecond=500123),
    )
    with sqlite3.connect(fixture.state_dir / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE scans SET started_at = ? WHERE id = ?",
            (fixture.started_at.isoformat(), fixture.scan_id),
        )
    counted = fixture.started_at + timedelta(microseconds=1)
    before_scan = counted - timedelta(days=1)
    boundary_predecessor = fixture.started_at.replace(microsecond=400000)
    after_scan = counted + timedelta(days=1)
    artifact = fixture.scan_dir / "artifacts" / "usage-worker"
    private_directory(artifact)
    child = _record_composition_thread(fixture, artifact, "sdk-first-attempt")
    for _ in range(2):
        _record_composition_thread(fixture, artifact, "sdk-current-attempt")

    _state_graph(
        fixture.environment,
        {
            "scan-parent": _rollout(tmp_path, "scan-parent", [_token_event(counted, 10, 3)]),
            "sdk-first-attempt": _rollout(
                tmp_path,
                "sdk-first-attempt",
                [_token_event(counted, 20, 5)],
                session_started_at=fixture.started_at.replace(microsecond=500000),
            ),
            "sdk-first-child": _rollout(
                tmp_path,
                "sdk-first-child",
                [_token_event(counted, 7, 2)],
                parent_thread_id="sdk-first-attempt",
            ),
            "sdk-current-attempt": _rollout(
                tmp_path,
                "sdk-current-attempt",
                [_token_event(counted, 20, 5), _token_event(counted, 30, 8)],
                session_started_at=before_scan,
            ),
            "finding-comparison": _rollout(
                tmp_path, "finding-comparison", [_token_event(counted, 12, 4)]
            ),
            "other-scan-worker": _rollout(
                tmp_path, "other-scan-worker", [_token_event(counted, 80_000, 20_000)]
            ),
            "archived-worker": _rollout(
                tmp_path, "archived-worker", [_token_event(before_scan, 100, 10)]
            ),
            "archived-missing-worker": tmp_path / "archived-missing.jsonl",
            "boundary-archived-worker": _rollout(
                tmp_path,
                "boundary-archived-worker",
                [_token_event(boundary_predecessor, 100, 10)],
                session_started_at=boundary_predecessor,
            ),
            "boundary-archived-child": tmp_path / "boundary-archived-child.jsonl",
            "later-worker": _rollout(tmp_path, "later-worker", [_token_event(after_scan, 100, 10)]),
            "later-missing-worker": tmp_path / "later-missing.jsonl",
        },
        [
            ("sdk-first-attempt", "sdk-first-child"),
            ("boundary-archived-worker", "boundary-archived-child"),
        ],
    )
    working_directory = artifact
    with sqlite3.connect(
        Path(fixture.environment["CODEX_SQLITE_HOME"]) / "state_5.sqlite"
    ) as connection:
        connection.executemany(
            "UPDATE threads SET cwd = ?, created_at = ? WHERE id = ?",
            [
                (
                    str(fixture.scan_dir / "artifacts" / "deep_discovery"),
                    int(counted.timestamp()),
                    "finding-comparison",
                ),
                (str(working_directory), int(counted.timestamp()), "sdk-first-attempt"),
                (str(working_directory), int(counted.timestamp()), "sdk-first-child"),
                (str(working_directory), int(counted.timestamp()), "sdk-current-attempt"),
                (
                    str(tmp_path / "other-scan" / "artifacts"),
                    int(counted.timestamp()),
                    "other-scan-worker",
                ),
                (str(working_directory), int(before_scan.timestamp()), "archived-worker"),
                (str(working_directory), int(before_scan.timestamp()), "archived-missing-worker"),
                (
                    str(working_directory),
                    int(boundary_predecessor.timestamp()),
                    "boundary-archived-worker",
                ),
                (str(working_directory), int(after_scan.timestamp()), "later-worker"),
                (str(working_directory), int(after_scan.timestamp()), "later-missing-worker"),
            ],
        )
    fail_scan(fixture.state_dir, child, "Pass retired.", environment=fixture.environment)
    arguments = ("--thread-id", "scan-parent", "--turn-id", "turn-scan-parent")
    completed = _complete_scan(fixture, *arguments)["scan"]
    usage = completed["usage"]
    assert (
        usage.items()
        >= {
            "coverage": "partial",
            "warnings": ["turn_in_progress"],
            "source": "codex_rollout",
            **_counts(79, 0, 22),
            "threadCount": 5,
        }.items()
    )
    run_workbench(
        fixture.state_dir,
        "register-cli-scan",
        "--repository",
        str(fixture.target),
        "--scan-dir",
        str(fixture.scan_dir),
        "--archive-existing",
        "--recipe-json",
        json.dumps(
            {
                "config": {},
                "mode": "deep",
                "repository": str(fixture.target),
                "target": {"kind": "repository", "paths": []},
            }
        ),
        environment=fixture.environment,
    )
    ended = datetime.fromisoformat(completed["usage"]["window"]["endedAt"])
    replacement_started = ended + timedelta(microseconds=1)
    replacement = _rollout(
        tmp_path,
        "new-comparison",
        [_token_event(replacement_started, 100, 10)],
        session_started_at=replacement_started,
    )
    with sqlite3.connect(Path(fixture.environment["CODEX_SQLITE_HOME"]) / "state_5.sqlite") as db:
        db.execute(
            "INSERT INTO threads (id, rollout_path, cwd, created_at) VALUES (?, ?, ?, ?)",
            (
                "new-comparison",
                str(replacement),
                str(fixture.scan_dir / "artifacts" / "deep_discovery"),
                int(ended.timestamp()),
            ),
        )
    finalized = fixture.command("finalize-scan-usage", *arguments)["scan"]["usage"]
    assert finalized["completion"]["finalized"] is True
    assert (finalized["totalTokens"], finalized["threadCount"]) == (101, 5)


def test_usage_has_no_separate_workbench_command(workbench_api, monkeypatch, capsys) -> None:
    monkeypatch.setattr(sys, "argv", ["workbench_db.py", "get-scan-usage"])
    with pytest.raises(SystemExit) as rejected:
        workbench_api["parse_args"]("workbench")
    assert rejected.value.code == 2
    assert "invalid choice: 'get-scan-usage'" in capsys.readouterr().err
