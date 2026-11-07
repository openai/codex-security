"""Attribute usage receipts to their recorded scan, owner, worker, turn, and model."""

from __future__ import annotations

import json
import sqlite3
import sys
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from test_workbench_scan_usage import (
    ScanFixture,
    _complete_scan,
    _event,
    _rollout,
    _start_scan,
    _state_graph,
    _token_event,
)
from workbench_test_support import (
    begin_deep_scan,
    run_workbench,
    scan_command,
    upsert_deep_worker,
    worker_paths,
)
from workbench_test_support import usage_counts as _counts


@pytest.mark.parametrize(
    "worker_state",
    ["absent", "measured", "missing_graph_child", "missing_registered_worker", "unmeasured"],
)
def test_completion_persists_direct_control_zero_without_hiding_missing_workers(
    tmp_path: Path, worker_state: str
) -> None:
    fixture = _start_scan(tmp_path, mode="deep")
    counted = fixture.started_at + timedelta(microseconds=1)
    threads = {
        # The app-server client persists this originator while injecting context,
        # without starting a model turn or producing a native token receipt.
        "scan-parent": _rollout(
            tmp_path,
            "scan-parent",
            [
                _event(counted, "turn_context", {}),
                _event(counted, "response_item", {"type": "message"}),
            ],
            originator="codex_security_deep_scan",
        ),
    }
    edges = []
    measured_worker = worker_state not in {"absent", "unmeasured"}
    if worker_state != "absent":
        threads["scan-worker"] = _rollout(
            tmp_path,
            "scan-worker",
            [_token_event(counted, 100, 10)] if measured_worker else [],
            parent_thread_id="scan-parent",
            task_started_at=counted,
            originator="codex_security_deep_scan",
        )
        edges.append(("scan-parent", "scan-worker"))
    if worker_state == "missing_graph_child":
        threads["missing-worker"] = tmp_path / "missing-worker.jsonl"
        edges.append(("scan-parent", "missing-worker"))
    elif worker_state == "missing_registered_worker":
        with sqlite3.connect(fixture.state_dir / "workbench.sqlite3") as connection:
            connection.execute(
                "INSERT INTO deep_scan_worker_threads (scan_id, worker_id, sdk_thread_id) "
                "VALUES (?, ?, ?)",
                (fixture.scan_id, "earlier-attempt", "missing-worker"),
            )
    _state_graph(fixture.environment, threads, edges)
    missing_warnings = {
        "missing_graph_child": ["rollout_unavailable"],
        "missing_registered_worker": ["scan_root_unavailable"],
        "unmeasured": ["token_record_missing", "token_usage_unavailable", "turn_in_progress"],
    }.get(worker_state, [])
    usage = {
        "coverage": "partial" if missing_warnings else "complete",
        "source": "codex_rollout",
        **_counts(100 if measured_worker else 0, 0, 10 if measured_worker else 0),
        "threadCount": 2 if measured_worker else 1,
        **({"missingThreadCount": 1, "warnings": missing_warnings} if missing_warnings else {}),
    }

    completed = _complete_scan(fixture)["scan"]

    assert completed["usage"].items() >= usage.items()
    usage = completed["usage"]
    assert usage["byRole"]["parent"] == {**_counts(0, 0, 0), "threadCount": 1}
    assert usage["byRole"]["workers"] == {
        **_counts(100 if measured_worker else 0, 0, 10 if measured_worker else 0),
        "threadCount": 1 if measured_worker else 0,
    }
    assert "cost" not in completed
    repeated = fixture.command("complete-scan")["scan"]
    assert repeated["usage"] == usage
    assert "cost" not in repeated
    with sqlite3.connect(fixture.state_dir / "workbench.sqlite3") as connection:
        stored = connection.execute(
            "SELECT cost_json FROM scans WHERE id = ?", (fixture.scan_id,)
        ).fetchone()[0]
    assert json.loads(stored) == {"usage": usage}


@pytest.mark.parametrize(
    ("persisted_owner", "token_receipt"),
    [(False, False), (True, False), (True, True)],
    ids=["legacy-metadata-only", "dedicated-metadata-only", "dedicated-explicit-zero"],
)
def test_completion_persists_zero_usage_for_dedicated_owner(
    tmp_path: Path, persisted_owner: bool, token_receipt: bool
) -> None:
    fixture = _start_scan(tmp_path, mode="deep")
    if persisted_owner:
        with sqlite3.connect(fixture.state_dir / "workbench.sqlite3") as connection:
            connection.execute(
                "UPDATE deep_scan_runs SET usage_owner_json = ? WHERE scan_id = ?",
                (
                    json.dumps(
                        {
                            "threadId": "scan-parent",
                            "turnId": None,
                            "startedAt": fixture.started_at.isoformat(),
                            "dedicated": True,
                        }
                    ),
                    fixture.scan_id,
                ),
            )
    counted = fixture.started_at + timedelta(microseconds=1)
    _state_graph(
        fixture.environment,
        {
            "scan-parent": _rollout(
                tmp_path,
                "scan-parent",
                [_token_event(counted, 0, 0)] if token_receipt else [],
                originator="codex_security_deep_scan",
            ),
        },
        [],
    )

    completed = _complete_scan(fixture)["scan"]

    usage = completed["usage"]
    assert (
        usage.items()
        >= {
            "coverage": "complete",
            "source": "codex_rollout",
            **_counts(0, 0, 0),
            "threadCount": 1,
        }.items()
    )
    if token_receipt:
        assert usage["modelUsage"] == [{"model": None, **_counts(0, 0, 0)}]
    else:
        assert "modelUsage" not in usage
    with sqlite3.connect(fixture.state_dir / "workbench.sqlite3") as connection:
        status, stored = connection.execute(
            "SELECT status, cost_json FROM scans WHERE id = ?", (fixture.scan_id,)
        ).fetchone()
    assert status == "complete"
    assert json.loads(stored) == {"usage": usage}
    repeated = scan_command(
        fixture.state_dir, "complete-scan", fixture.scan_id, environment=fixture.environment
    )["scan"]
    assert repeated["usage"] == usage


@pytest.mark.parametrize("turn_start", ["before_scan", "during_scan", "untimestamped", "post_scan"])
def test_direct_control_resumed_model_turn_requires_a_usage_receipt(
    tmp_path: Path, turn_start: str
) -> None:
    fixture = _start_scan(tmp_path, mode="deep")
    counted = fixture.started_at + timedelta(microseconds=1)
    timestamp = (
        fixture.started_at - timedelta(seconds=1)
        if turn_start == "before_scan"
        else counted + timedelta(days=1)
        if turn_start == "post_scan"
        else counted
    )
    event = _event(timestamp, "event_msg", {"type": "task_started", "turn_id": "resumed-turn"})
    if turn_start == "untimestamped":
        del event["timestamp"]
    _state_graph(
        fixture.environment,
        {
            "scan-parent": _rollout(
                tmp_path, "scan-parent", [event], originator="codex_security_deep_scan"
            ),
            "scan-worker": _rollout(
                tmp_path,
                "scan-worker",
                [_token_event(counted, 100, 10)],
                parent_thread_id="scan-parent",
            ),
        },
        [("scan-parent", "scan-worker")],
    )

    usage = _complete_scan(fixture)["scan"]["usage"]

    expected = {
        "coverage": "complete" if turn_start == "post_scan" else "partial",
        "source": "codex_rollout",
        **_counts(100, 0, 10),
        "threadCount": 2 if turn_start == "post_scan" else 1,
        **(
            {}
            if turn_start == "post_scan"
            else {
                "missingThreadCount": 1,
                "warnings": [
                    "token_record_missing",
                    "token_usage_unavailable",
                    "turn_record_invalid" if turn_start == "untimestamped" else "turn_in_progress",
                ],
            }
        ),
    }
    assert usage.items() >= expected.items()


@pytest.mark.parametrize("originator", ["codex_sdk_ts", "synthetic_override", None])
def test_metadata_only_deep_owner_requires_direct_control_originator(
    tmp_path: Path, originator: str | None
) -> None:
    fixture = _start_scan(tmp_path, mode="deep")
    fixture.write_parent_rollout([], originator=originator)

    assert _complete_scan(fixture)["scan"]["usage"] == {
        "coverage": "unavailable",
        "source": "codex_rollout",
        "threadCount": 0,
        "warnings": ["token_record_missing", "token_usage_unavailable"],
    }


@pytest.mark.parametrize("reported", ["missing", "null-counter", "explicit-zero"])
def test_completion_distinguishes_missing_token_records_from_zero(
    tmp_path: Path, reported: str
) -> None:
    fixture = _start_scan(tmp_path)
    counted = fixture.started_at + timedelta(microseconds=1)
    events = []
    if reported == "explicit-zero":
        events.append(_token_event(counted, 0, 0))
    elif reported == "null-counter":
        events.append(
            _event(counted, "event_msg", {"type": "token_count", "info": None, "rate_limits": None})
        )
    parent = _rollout(tmp_path, "scan-parent", events)
    _state_graph(fixture.environment, {"scan-parent": parent}, [])
    usage = _complete_scan(fixture)["scan"]["usage"]
    if reported == "explicit-zero":
        assert usage["coverage"] == "complete"
        assert usage["totalTokens"] == 0
    else:
        assert usage["coverage"] == "unavailable"
        assert "token_usage_unavailable" in usage["warnings"]
        assert "token_record_invalid" not in usage["warnings"]
        assert "totalTokens" not in usage


def test_completion_counts_deep_sdk_workers_and_descendants(tmp_path: Path) -> None:
    state_dir = tmp_path / "workbench-state"
    target = tmp_path / "target"
    target.mkdir()
    environment = {
        "CODEX_HOME": str(tmp_path / "codex-home"),
        "CODEX_SQLITE_HOME": str(tmp_path / "codex-sqlite"),
        "CODEX_STATE_DB": "",
    }
    deep = begin_deep_scan(
        state_dir,
        "scan-parent",
        "--target-path",
        str(target),
        "--scope",
        ".",
        "--scan-root",
        str(tmp_path / "scans"),
        "--available-parallelism",
        "4",
        environment=environment,
    )["deepScan"]
    scan_id = str(deep["scanId"])
    scan_dir = Path(str(deep["scanDir"]))
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        row = connection.execute("SELECT started_at FROM scans WHERE id = ?", (scan_id,)).fetchone()
    assert row is not None
    fixture = ScanFixture(
        state_dir,
        target,
        scan_id,
        scan_dir,
        datetime.fromisoformat(row[0].replace("Z", "+00:00")),
        environment,
        "deep",
    )
    # Read an owner binding already persisted by a newer writer release.
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE deep_scan_runs SET usage_owner_json = ? WHERE scan_id = ?",
            (
                json.dumps(
                    {
                        "threadId": "scan-parent",
                        "turnId": None,
                        "startedAt": fixture.started_at.isoformat(),
                        "dedicated": False,
                    }
                ),
                scan_id,
            ),
        )
    counted = fixture.started_at + timedelta(microseconds=1)
    artifact = scan_dir / "artifacts" / "usage-worker"
    artifact.mkdir(parents=True)
    prompt = artifact / "prompt.md"
    prompt.write_text("Review the fixture target.\n", encoding="utf-8")
    upsert_deep_worker(
        state_dir,
        scan_id,
        str(uuid.uuid4()),
        "discovery",
        "running",
        str(prompt),
        str(artifact),
        "--sdk-thread-id",
        "sdk-worker",
        environment=environment,
    )
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
    assert (
        usage.items()
        >= {
            "coverage": "partial",
            "source": "codex_rollout",
            **_counts(27, 0, 7),
            "threadCount": 2,
            "missingThreadCount": 1,
            "warnings": ["scan_owner_turn_unavailable"],
            "modelUsage": [{"model": None, **_counts(27, 0, 7)}],
        }.items()
    )


@pytest.mark.parametrize(
    "worker_home",
    [
        "recorded",
        "recorded-committed",
        "recorded-tampered",
        "recorded-owner",
        "external-owner",
        "current",
        "inherited-sqlite",
        "current-prefix",
        "recorded-prefix",
        "current-unreadable",
        "current-mismatched",
        "external-sqlite",
        "external-archived",
        "external-late-parent",
        "external-shared-home",
        "external-missing-copy",
        "external-missing-child",
        "unavailable",
    ],
)
def test_completion_keeps_owner_and_workers_in_their_recorded_homes(
    tmp_path: Path, worker_home: str
) -> None:
    current_home = tmp_path / "current-home"
    copied_rollout = worker_home in {
        "current-prefix",
        "recorded-prefix",
        "current-unreadable",
        "current-mismatched",
    }
    environment = {
        "CODEX_HOME": str(current_home),
        "CODEX_SQLITE_HOME": str(current_home / "sqlite"),
        "CODEX_STATE_DB": str(current_home / "sqlite" / "state_5.sqlite"),
    }
    owners = {
        f"owner-{index}": _rollout(
            tmp_path,
            f"owner-{index}",
            [_event(datetime.now().astimezone(), "turn_context", {"turn_id": "original"})],
        )
        for index in (1, 2)
    }
    _state_graph(environment, owners, [])

    def complete(index: int) -> dict[str, Any]:
        root = tmp_path / f"scan-{index}"
        root.mkdir(mode=0o700)
        target = root / "target"
        target.mkdir()
        selected_home = current_home if worker_home == "current" else root / "original-home"
        if worker_home == "external-shared-home":
            selected_home = tmp_path / "shared-original-home"
        deep = run_workbench(
            root / "state",
            "begin-deep-scan",
            "--thread-id",
            f"owner-{index}",
            "--target-path",
            str(target),
            "--scan-root",
            str(root / "scans"),
            environment=environment,
        )["deepScan"]
        scan_id, scan_dir = deep["scanId"], Path(deep["scanDir"])
        snapshot = scan_dir / "artifacts/deep_discovery/execution-settings.json"
        assert not snapshot.exists()
        # These original facts were persisted by a newer writer release.
        snapshot.parent.mkdir(parents=True, exist_ok=True)
        snapshot.write_text(
            json.dumps(
                {
                    "version": 1,
                    "settings": {
                        "codexHome": str(selected_home),
                        "codexPath": sys.executable,
                    },
                }
            )
        )
        owner_json = json.dumps(
            {
                "threadId": f"owner-{index}",
                "turnId": "original",
                "startedAt": deep["createdAt"],
                "dedicated": False,
            }
        )
        with sqlite3.connect(root / "state" / "workbench.sqlite3") as connection:
            assert connection.execute(
                "SELECT usage_owner_json FROM deep_scan_runs WHERE scan_id = ?", (scan_id,)
            ).fetchone() == (None,)
            connection.execute(
                "UPDATE deep_scan_runs SET usage_owner_json = ?, execution_settings_json = ? "
                "WHERE scan_id = ?",
                (owner_json, snapshot.read_text(), scan_id),
            )
        if worker_home == "recorded-committed":
            snapshot.unlink()
        elif worker_home == "recorded-tampered":
            snapshot.write_text(
                json.dumps({"version": 1, "settings": {"codexHome": str(current_home)}})
            )
        original_bytes = snapshot.read_bytes() if snapshot.exists() else None
        fixture = ScanFixture(
            root / "state",
            target,
            scan_id,
            scan_dir,
            datetime.fromisoformat(deep["createdAt"].replace("Z", "+00:00")),
            environment,
            "deep",
        )
        counted = fixture.started_at + timedelta(microseconds=1)
        with owners[f"owner-{index}"].open("a") as stream:
            stream.write(json.dumps(_token_event(counted, index * 10, 2)) + "\n")
            stream.write(json.dumps(_event(counted, "turn_context", {"turn_id": "later"})) + "\n")
            stream.write(json.dumps(_token_event(counted, 9000, 900)) + "\n")
        worker_threads = {}
        if worker_home in {"recorded-owner", "external-owner"}:
            owner_id = f"owner-{index}"
            worker_threads[owner_id] = owners[owner_id]
            worker_threads[f"unrelated-owner-child-{index}"] = _rollout(
                root,
                f"unrelated-owner-child-{index}",
                [_token_event(counted, 7000, 700)],
                parent_thread_id=owner_id,
            )
            with sqlite3.connect(environment["CODEX_STATE_DB"]) as connection:
                connection.execute("DELETE FROM threads WHERE id = ?", (owner_id,))
        for kind in ("discovery", "second-discovery"):
            thread_id = f"{kind}-{index}"
            artifact = scan_dir / "artifacts" / thread_id
            artifact.mkdir()
            prompt = artifact / "prompt.md"
            prompt.write_text("Review the synthetic target.\n")
            run_workbench(
                fixture.state_dir,
                "upsert-deep-scan-worker",
                "--scan-id",
                scan_id,
                "--worker-id",
                str(uuid.uuid4()),
                "--kind",
                "discovery",
                "--status",
                "running",
                "--prompt-path",
                str(prompt),
                "--artifact-dir",
                str(artifact),
                "--sdk-thread-id",
                thread_id,
                environment=environment,
            )
            worker_threads[thread_id] = _rollout(
                root,
                thread_id,
                [
                    *(
                        [_event(counted, "turn_context", {"model": "model-alpha"})]
                        if copied_rollout and kind == "discovery"
                        else []
                    ),
                    _token_event(counted, index * 20, 3),
                    _event(
                        counted,
                        "turn_context",
                        {
                            "turn_id": "resumed",
                            **(
                                {"model": "model-beta"}
                                if copied_rollout and kind == "discovery"
                                else {}
                            ),
                        },
                    ),
                    _token_event(counted, index * 30, 5),
                ],
            )
        middle_id = f"middle-{index}"
        if worker_home == "external-late-parent":
            worker_threads[middle_id] = _rollout(
                root,
                middle_id,
                [_token_event(counted, index * 9, 2)],
                parent_thread_id=f"discovery-{index}",
            )
        child_id = f"child-{index}"
        worker_threads[child_id] = _rollout(
            root,
            child_id,
            [_token_event(counted, index * 7, 1)],
            parent_thread_id=(
                middle_id if worker_home == "external-late-parent" else f"discovery-{index}"
            ),
        )
        if worker_home in {"current", "inherited-sqlite"}:
            with sqlite3.connect(environment["CODEX_STATE_DB"]) as connection:
                connection.executemany(
                    "INSERT INTO threads (id, rollout_path) VALUES (?, ?)",
                    [(key, str(path)) for key, path in worker_threads.items()],
                )
                connection.execute(
                    "INSERT INTO thread_spawn_edges VALUES (?, ?)", (f"discovery-{index}", child_id)
                )
            if worker_home == "inherited-sqlite":
                # Earlier launches used A; the resumed process forwards its
                # explicit SQLite home C even while workers keep Codex home A.
                _state_graph(
                    {"CODEX_SQLITE_HOME": str(selected_home)},
                    {f"discovery-{index}": worker_threads[f"discovery-{index}"]},
                    [],
                )
        elif worker_home in {
            "recorded",
            "recorded-committed",
            "recorded-tampered",
            "recorded-owner",
            "current-prefix",
            "recorded-prefix",
            "current-unreadable",
            "current-mismatched",
        }:
            recorded_threads = dict(worker_threads)
            if worker_home not in {"recorded", "recorded-committed", "recorded-tampered"}:
                thread_id = f"discovery-{index}"
                full = worker_threads[thread_id]
                copied = full.with_name(f"copied-{thread_id}.jsonl")
                copied.write_bytes(b"\n".join(full.read_bytes().splitlines()[:3]) + b"\n")
                if worker_home == "current-unreadable":
                    copied.write_text("invalid session metadata\n")
                elif worker_home == "current-mismatched":
                    copied.write_text(full.read_text().replace(thread_id, "unrelated-thread"))
                current_copy = copied
                if worker_home == "recorded-prefix":
                    recorded_threads[thread_id] = copied
                    current_copy = full
                with sqlite3.connect(environment["CODEX_STATE_DB"]) as connection:
                    connection.execute(
                        "INSERT INTO threads (id, rollout_path) VALUES (?, ?)",
                        (thread_id, str(current_copy)),
                    )
            _state_graph(
                {"CODEX_SQLITE_HOME": str(selected_home)},
                recorded_threads,
                [
                    (f"discovery-{index}", child_id),
                    *(
                        [(f"owner-{index}", f"unrelated-owner-child-{index}")]
                        if worker_home == "recorded-owner"
                        else []
                    ),
                ],
            )
        elif worker_home in {
            "external-sqlite",
            "external-archived",
            "external-owner",
            "external-late-parent",
            "external-shared-home",
            "external-missing-copy",
            "external-missing-child",
        }:
            # Native keeps rollouts in its Codex home even when its SQLite
            # index lives elsewhere and recovery chooses a different index.
            sessions = (
                selected_home / "archived_sessions"
                if worker_home == "external-archived"
                else selected_home / "sessions" / "2026" / "01" / "01"
            )
            sessions.mkdir(parents=True, exist_ok=True)
            for thread_id, path in worker_threads.items():
                recorded = sessions / f"rollout-{thread_id}.jsonl"
                path.rename(recorded)
                worker_threads[thread_id] = recorded
            _state_graph(
                {"CODEX_SQLITE_HOME": str(root / "original-external-sqlite")},
                worker_threads,
                (
                    [(f"discovery-{index}", middle_id), (middle_id, child_id)]
                    if worker_home == "external-late-parent"
                    else [
                        (f"discovery-{index}", child_id),
                        *(
                            [(f"owner-{index}", f"unrelated-owner-child-{index}")]
                            if worker_home == "external-owner"
                            else []
                        ),
                    ]
                ),
            )
        if worker_home == "external-late-parent":
            # Recovery's index knows the grandchild; its parent remains only
            # in the recorded worker home after the external index changed.
            with sqlite3.connect(environment["CODEX_STATE_DB"]) as connection:
                connection.executemany(
                    "INSERT INTO threads (id, rollout_path) VALUES (?, ?)",
                    [
                        (thread_id, str(worker_threads[thread_id]))
                        for thread_id in (f"discovery-{index}", child_id)
                    ],
                )
                connection.executemany(
                    "INSERT INTO thread_spawn_edges VALUES (?, ?)",
                    [(f"discovery-{index}", middle_id), (middle_id, child_id)],
                )
        if worker_home in {"external-missing-copy", "external-missing-child"}:
            first_id = f"discovery-{index}"
            with sqlite3.connect(environment["CODEX_STATE_DB"]) as connection:
                connection.execute(
                    "INSERT INTO threads (id, rollout_path) VALUES (?, ?)",
                    (
                        first_id,
                        str(root / "missing-copy.jsonl")
                        if worker_home == "external-missing-copy"
                        else str(worker_threads[first_id]),
                    ),
                )
                if worker_home == "external-missing-child":
                    connection.execute(
                        "INSERT INTO thread_spawn_edges VALUES (?, ?)", (first_id, child_id)
                    )
                    worker_threads[child_id].unlink()
        result = _complete_scan(fixture)["scan"]["usage"]
        assert (snapshot.read_bytes() if snapshot.exists() else None) == original_bytes
        with sqlite3.connect(fixture.state_dir / "workbench.sqlite3") as connection:
            assert connection.execute(
                "SELECT usage_owner_json FROM deep_scan_runs WHERE scan_id = ?", (scan_id,)
            ).fetchone() == (owner_json,)
            assert connection.execute("SELECT COUNT(*) FROM deep_scan_attempts").fetchone() == (0,)
            assert connection.execute(
                "SELECT COUNT(*) FROM deep_scan_attempt_sessions"
            ).fetchone() == (0,)
        return result

    # Both completions share current home B; each scan retains its own worker home A.
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(complete, (1, 2)))
    for index, usage in enumerate(results, 1):
        if worker_home == "unavailable":
            assert usage["coverage"] == "partial"
            assert usage["inputTokens"] == index * 10
            assert usage["outputTokens"] == 2
            assert usage["threadCount"] == 1
            assert usage["missingThreadCount"] == 2
        elif worker_home == "external-missing-child":
            assert (
                usage.items()
                >= {
                    "coverage": "partial",
                    "source": "codex_rollout",
                    **_counts(index * 70, 0, 12),
                    "threadCount": 3,
                    "missingThreadCount": 1,
                    "warnings": [
                        "codex_state_unavailable",
                        "rollout_unavailable",
                        "scan_root_unavailable",
                    ],
                    "modelUsage": [{"model": None, **_counts(index * 70, 0, 12)}],
                }.items()
            )
        else:
            expected_input = index * (86 if worker_home == "external-late-parent" else 77)
            expected_output = 15 if worker_home == "external-late-parent" else 13
            assert (
                usage.items()
                >= {
                    "coverage": "complete",
                    "source": "codex_rollout",
                    **_counts(expected_input, 0, expected_output),
                    "threadCount": 5 if worker_home == "external-late-parent" else 4,
                    "modelUsage": (
                        [
                            {"model": None, **_counts(index * 47, 0, 8)},
                            {"model": "model-alpha", **_counts(index * 20, 0, 3)},
                            {"model": "model-beta", **_counts(index * 10, 0, 2)},
                        ]
                        if copied_rollout
                        else [{"model": None, **_counts(expected_input, 0, expected_output)}]
                    ),
                }.items()
            )


def test_attempt_history_without_owner_binding_preserves_legacy_usage(
    tmp_path: Path, workbench_api, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = _start_scan(tmp_path, mode="deep")
    counted = fixture.started_at + timedelta(microseconds=1)
    parent = _rollout(tmp_path, "scan-parent", [_token_event(counted, 12, 3)])
    worker = _rollout(
        tmp_path,
        "worker",
        [_token_event(counted, 20, 5)],
        parent_thread_id="scan-parent",
    )
    _state_graph(
        fixture.environment, {"scan-parent": parent, "worker": worker}, [("scan-parent", "worker")]
    )
    worker_id = str(uuid.uuid4())
    prompt, artifacts, _ = worker_paths(fixture.scan_dir, "discovery")
    upsert_deep_worker(
        fixture.state_dir,
        fixture.scan_id,
        worker_id,
        "discovery",
        "running",
        str(prompt),
        str(artifacts),
        "--sdk-thread-id",
        "worker",
        environment=fixture.environment,
    )
    for name, value in fixture.environment.items():
        monkeypatch.setenv(name, value)
    usage_reader = workbench_api["scan_usage"]
    with sqlite3.connect(fixture.state_dir / "workbench.sqlite3") as connection:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        scan = connection.execute("SELECT * FROM scans WHERE id = ?", (fixture.scan_id,)).fetchone()
        assert (
            connection.execute(
                "SELECT usage_owner_json FROM deep_scan_runs WHERE scan_id = ?", (fixture.scan_id,)
            ).fetchone()[0]
            is None
        )
        before = usage_reader.collect_scan_usage(connection, scan, completed_at=counted.isoformat())
        assert before["coverage"] == "complete"
        assert before["totalTokens"] == 40
        connection.execute(
            "INSERT INTO deep_scan_attempts "
            "(scan_id, worker_id, attempt, status, started_at) VALUES (?, ?, 1, 'running', ?)",
            (fixture.scan_id, worker_id, fixture.started_at.isoformat()),
        )
        after = usage_reader.collect_scan_usage(connection, scan, completed_at=counted.isoformat())
    assert after["coverage"] == "complete"
    assert after["totalTokens"] == 40
    assert after["byRole"] == before["byRole"]


def test_rollout_usage_reconciles_stale_cumulative_events_and_models(
    tmp_path: Path, workbench_api
) -> None:
    usage_reader = sys.modules["workbench_scan_usage"]
    start = datetime.fromisoformat("2026-01-01T00:00:00+00:00")
    events = [
        _event(start, "turn_context", {"turn_id": "own-turn", "model": "gpt-5.6-sol"}),
        _token_event(start, 100, 10),
        _token_event(start, 60, 6),
        _event(start, "turn_context", {"turn_id": "own-turn", "model": "gpt-6-astra"}),
        _token_event(start, 200, 20),
    ]
    rollout = _rollout(tmp_path, "worker", events)
    measurement = usage_reader._read_rollout_usage(
        usage_reader.RolloutSession("worker", None, rollout),
        started_at=start,
        completed_at=None,
    )
    counts, warnings = measurement.tokens, measurement.warnings
    assert counts == _counts(200, 0, 20)
    assert warnings == {"token_counter_regressed"}
    models = {}
    measurement = usage_reader._read_rollout_usage(
        usage_reader.RolloutSession("worker", None, rollout),
        started_at=start,
        completed_at=None,
        model_usage=models,
    )
    counts, warnings = measurement.tokens, measurement.warnings
    assert counts == _counts(200, 0, 20)
    assert warnings == {"token_counter_regressed"}
    assert models == {"gpt-5.6-sol": _counts(100, 0, 10), "gpt-6-astra": _counts(100, 0, 10)}


def test_shared_parent_usage_requires_original_turn_and_scan_interval(
    tmp_path: Path, workbench_api
) -> None:
    usage_reader = sys.modules["workbench_scan_usage"]
    start = datetime.fromisoformat("2026-01-01T00:00:00+00:00")
    end = start + timedelta(seconds=5)
    events = [
        _event(
            start - timedelta(seconds=1),
            "turn_context",
            {"turn_id": "prior", "model": "gpt-5.6-sol"},
        ),
        _token_event(start - timedelta(seconds=1), 100, 10),
        _event(start, "turn_context", {"turn_id": "scan-turn", "model": "gpt-6-astra"}),
        _token_event(start, 110, 12),
        _event(start, "turn_context", {"turn_id": "unrelated", "model": "gpt-5.6-sol"}),
        _token_event(start, 910, 92),
        _event(
            end + timedelta(seconds=1),
            "turn_context",
            {"turn_id": "scan-turn", "model": "gpt-6-astra"},
        ),
        _token_event(end + timedelta(seconds=1), 1000, 100),
    ]
    models = {}
    measurement = usage_reader._read_rollout_usage(
        usage_reader.RolloutSession("parent", None, _rollout(tmp_path, "parent", events)),
        started_at=start,
        completed_at=end,
        owner_turn_id="scan-turn",
        model_usage=models,
    )
    counts, warnings = measurement.tokens, measurement.warnings
    assert counts == _counts(10, 0, 2)
    assert warnings == set()
    assert models == {"gpt-6-astra": _counts(10, 0, 2)}


@pytest.mark.parametrize(
    "counter_info,receipt_state,expected_warning",
    [
        (None, "complete", None),
        ({}, "complete", "token_record_invalid"),
        ({"total_token_usage": {"input_tokens": -1}}, "complete", "token_record_invalid"),
        (None, "missing-response", "token_receipts_incomplete"),
        (None, "incomplete-line", "rollout_record_incomplete"),
        (None, "invalid-timestamp", "token_record_invalid"),
    ],
    ids=[
        "null-counter",
        "empty-info",
        "malformed-usage",
        "missing-response",
        "incomplete-line",
        "invalid-timestamp",
    ],
)
def test_completion_handles_no_usage_counter_without_hiding_incomplete_receipts(
    tmp_path: Path, counter_info: Any, receipt_state: str, expected_warning: str | None
) -> None:
    fixture = _start_scan(tmp_path)
    counted = fixture.started_at + timedelta(microseconds=1)
    tokens = dict(
        input_tokens=100,
        cached_input_tokens=20,
        cache_write_input_tokens=0,
        output_tokens=10,
        total_tokens=110,
    )
    response = _event(
        counted,
        "token_usage_record",
        dict(
            response_id="response-one",
            thread_id="scan-parent",
            model="gpt-5.6-sol",
            usage=tokens,
            thread_token_usage=(
                {**tokens, "input_tokens": 150, "total_tokens": 160}
                if receipt_state == "missing-response"
                else tokens
            ),
        ),
    )
    counter = _event(
        counted,
        "event_msg",
        {"type": "token_count", "info": counter_info, "rate_limits": None},
    )
    events = [counter, response, counter]
    if receipt_state == "invalid-timestamp":
        events.append(
            {
                **response,
                "timestamp": None,
                "payload": {**response["payload"], "response_id": "response-two"},
            }
        )
    parent = _rollout(tmp_path, "scan-parent", events)
    if receipt_state == "incomplete-line":
        with parent.open("a") as stream:
            stream.write('{"type":"token_usage_record"')
    _state_graph(fixture.environment, {"scan-parent": parent}, [])
    usage = _complete_scan(fixture)["scan"]["usage"]
    assert usage["totalTokens"] == 110
    assert usage["modelUsage"] == [{"model": "gpt-5.6-sol", **_counts(100, 20, 10)}]
    assert usage["coverage"] == ("partial" if expected_warning else "complete")
    assert usage.get("warnings", []) == ([expected_warning] if expected_warning else [])


@pytest.mark.parametrize("counters", [False, True])
def test_response_receipts_count_compaction_once_across_resets(
    tmp_path: Path, workbench_api, counters: bool
) -> None:
    reader = sys.modules["workbench_scan_usage"]
    start = datetime.fromisoformat("2026-01-01T00:00:00+00:00")

    def usage(input_tokens, cached, output):
        return dict(
            input_tokens=input_tokens,
            cached_input_tokens=cached,
            cache_write_input_tokens=0,
            output_tokens=output,
            reasoning_output_tokens=0,
            total_tokens=input_tokens + output,
        )

    def receipt(response, count, cumulative, model="gpt-5.6-sol", turn="scan-turn", second=1):
        return _event(
            start + timedelta(seconds=second),
            "token_usage_record",
            dict(
                response_id=response,
                thread_id="parent",
                turn_id=turn,
                model=model,
                usage=count,
                thread_token_usage=cumulative,
            ),
        )

    first = receipt("first", usage(100, 80, 10), usage(100, 80, 10))
    compact = receipt("compaction", usage(50, 40, 5), usage(150, 120, 15), model="gpt-6-astra")
    second = receipt("second", usage(120, 90, 12), usage(120, 90, 12))
    events = [
        first,
        *([_token_event(start + timedelta(seconds=1), 100, 10)] if counters else []),
        compact,
        _event(start + timedelta(seconds=1), "compacted", {"message": "Synthetic summary"}),
        compact,
        second,
        *([_token_event(start + timedelta(seconds=1), 220, 22)] if counters else []),
        first,
        receipt("other", usage(900, 0, 0), usage(900, 0, 0), turn="other-turn"),
        receipt("post", usage(800, 0, 0), usage(1700, 0, 0), second=11),
    ]
    models = {}
    measurement = reader._read_rollout_usage(
        reader.RolloutSession("parent", None, _rollout(tmp_path, "parent", events)),
        started_at=start,
        completed_at=start + timedelta(seconds=10),
        owner_turn_id="scan-turn",
        model_usage=models,
    )
    total, warnings = measurement.tokens, measurement.warnings
    assert total == _counts(270, 210, 27)
    assert warnings == {"turn_in_progress"}
    assert models == {"gpt-5.6-sol": _counts(220, 170, 22), "gpt-6-astra": _counts(50, 40, 5)}


def test_delayed_response_receipt_resolves_missing_cumulative_usage(
    tmp_path: Path, workbench_api
) -> None:
    reader = sys.modules["workbench_scan_usage"]
    start = datetime.fromisoformat("2026-01-01T00:00:00+00:00")

    def receipt(response, tokens, cumulative):
        def usage(value):
            return dict(
                input_tokens=value, cache_write_input_tokens=0, output_tokens=0, total_tokens=value
            )

        return _event(
            start,
            "token_usage_record",
            dict(
                response_id=response,
                thread_id="parent",
                model="gpt-5.6-sol",
                usage=usage(tokens),
                thread_token_usage=usage(cumulative),
            ),
        )

    rollout = _rollout(tmp_path, "parent", [receipt("first", 100, 100), receipt("third", 50, 180)])
    session = reader.RolloutSession("parent", None, rollout)
    measurement = reader._read_rollout_usage(session, started_at=start, completed_at=None)
    total, warnings = measurement.tokens, measurement.warnings
    assert total == _counts(150, 0, 0)
    assert warnings == {"token_receipts_incomplete"}
    with rollout.open("a") as source:
        source.write(json.dumps(receipt("second", 30, 130)) + "\n")
    measurement = reader._read_rollout_usage(session, started_at=start, completed_at=None)
    total, warnings = measurement.tokens, measurement.warnings
    assert total == _counts(180, 0, 0)
    assert warnings == set()


def test_exact_receipts_replace_overlapping_legacy_counter(tmp_path: Path, workbench_api) -> None:
    reader = sys.modules["workbench_scan_usage"]
    start = datetime.fromisoformat("2026-01-01T00:00:00+00:00")

    def receipt(response, tokens, cumulative):
        def usage(value):
            return dict(
                input_tokens=value, cache_write_input_tokens=0, output_tokens=0, total_tokens=value
            )

        return _event(
            start,
            "token_usage_record",
            dict(
                response_id=response,
                thread_id="parent",
                model="gpt-5.6-sol",
                usage=usage(tokens),
                thread_token_usage=usage(cumulative),
            ),
        )

    rollout = _rollout(
        tmp_path,
        "parent",
        [
            _token_event(start, 100, 0),
            receipt("new", 10, 110),
            receipt("old", 100, 100),
            _token_event(start, 10, 0),
        ],
    )
    models = {}
    measurement = reader._read_rollout_usage(
        reader.RolloutSession("parent", None, rollout),
        started_at=start,
        completed_at=None,
        model_usage=models,
    )
    total, warnings = measurement.tokens, measurement.warnings
    assert total == _counts(110, 0, 0)
    assert warnings == set()
    assert models == {"gpt-5.6-sol": _counts(110, 0, 0)}


@pytest.mark.parametrize("receipt", [None, "other-turn", "after-completion"])
def test_rejected_receipt_preserves_priced_legacy_usage(tmp_path: Path, workbench_api, receipt):
    reader = sys.modules["workbench_scan_usage"]
    start = datetime.fromisoformat("2026-09-01T00:00:00+00:00")
    at = start + timedelta(seconds=1)
    events = [
        _event(at, "turn_context", {"turn_id": "owned-turn", "model": "gpt-5.6-sol"}),
        _token_event(at, 1000, 0),
    ]
    if receipt is not None:
        events.append(
            _event(
                at if receipt == "other-turn" else start + timedelta(seconds=11),
                "token_usage_record",
                {
                    "thread_id": "owner",
                    "turn_id": "other-turn" if receipt == "other-turn" else "owned-turn",
                    "response_id": "foreign-response",
                    "model": "synthetic-unpriced-model",
                    "usage": {"input_tokens": 9000, "output_tokens": 0, "total_tokens": 9000},
                },
            )
        )
    models = {}
    measurement = reader._read_rollout_usage(
        reader.RolloutSession("owner", None, _rollout(tmp_path, "owner", events)),
        started_at=start,
        completed_at=start + timedelta(seconds=10),
        owner_turn_id="owned-turn",
        model_usage=models,
    )
    total, warnings = measurement.tokens, measurement.warnings
    assert total == _counts(1000, 0, 0)
    assert warnings == set()
    assert models == {"gpt-5.6-sol": _counts(1000, 0, 0)}


@pytest.mark.parametrize(
    "case",
    [
        "history",
        "history-gap",
        "pre-window-reset",
        "counter-categories",
        "disjoint-reset-gap",
        "disjoint-reset-complete",
    ],
)
def test_completion_usage_matches_its_admitted_window_and_model_partition(tmp_path, case):
    fixture = _start_scan(tmp_path)
    start = fixture.started_at

    def receipt(
        second, response, input_tokens, output_tokens, cumulative_input, cumulative_output=0
    ):
        return _event(
            start + timedelta(seconds=second),
            "token_usage_record",
            {
                "thread_id": "scan-parent",
                "response_id": response,
                "model": "gpt-5.6-sol",
                "usage": {
                    "input_tokens": input_tokens,
                    "output_tokens": output_tokens,
                    "total_tokens": input_tokens + output_tokens,
                },
                "thread_token_usage": {
                    "input_tokens": cumulative_input,
                    "output_tokens": cumulative_output,
                    "total_tokens": cumulative_input + cumulative_output,
                },
            },
        )

    if case in {"history", "history-gap"}:
        events = [
            receipt(-2, "history", 900, 0, 900),
            receipt(0, "owned", 20, 0, 920 if case == "history" else 940),
        ]
        expected = _counts(20, 0, 0)
        partial = case == "history-gap"
    elif case.startswith("disjoint-reset"):
        events = [
            _token_event(start - timedelta(seconds=1), 900, 0),
            receipt(0, "one", 100, 0, 1000),
            *([receipt(0.001, "two", 20, 0, 20)] if case.endswith("complete") else []),
            receipt(0.002, "three", 20, 0, 40),
        ]
        expected = _counts(140 if case.endswith("complete") else 120, 0, 0)
        partial = case.endswith("gap")
    elif case == "pre-window-reset":
        events = [
            _token_event(start - timedelta(seconds=3), 1000, 0),
            _token_event(start - timedelta(seconds=2), 100, 0),
            _token_event(start, 120, 0),
        ]
        expected = _counts(20, 0, 0)
        partial = False
    else:
        events = [receipt(0, "owned", 100, 50, 100, 50), _token_event(start, 200, 10)]
        expected = _counts(200, 0, 50)
        partial = True
    events.insert(
        0,
        _event(
            start - timedelta(seconds=5),
            "turn_context",
            {"turn_id": "scan-turn", "model": "gpt-5.6-sol"},
        ),
    )
    _state_graph(
        fixture.environment, {"scan-parent": _rollout(tmp_path, "scan-parent", events)}, []
    )
    # Exercise complete-scan's public usage validation, not just the private reader.
    usage = _complete_scan(fixture)["scan"]["usage"]
    assert all(usage[key] == value for key, value in expected.items()), usage
    assert usage["coverage"] == ("partial" if partial else "complete")
    assert usage.get("warnings", []) == (["token_receipts_incomplete"] if partial else [])
    for key in expected:
        assert sum(part[key] for part in usage["modelUsage"]) == usage[key]


@pytest.mark.parametrize("foreign_first", [False, True])
def test_foreign_response_cumulative_does_not_hide_an_earlier_owned_gap(
    tmp_path, workbench_api, foreign_first
):
    reader = sys.modules["workbench_scan_usage"]
    start = datetime.fromisoformat("2026-01-01T00:00:00+00:00")

    def receipt(second, response, count, cumulative, turn="scan-turn"):
        return _event(
            start + timedelta(seconds=second),
            "token_usage_record",
            {
                "thread_id": "parent",
                "turn_id": turn,
                "response_id": response,
                "model": "gpt-5.6-sol",
                "usage": {
                    "input_tokens": count,
                    "cache_write_input_tokens": 0,
                    "output_tokens": 0,
                    "total_tokens": count,
                },
                "thread_token_usage": {
                    "input_tokens": cumulative,
                    "output_tokens": 0,
                    "total_tokens": cumulative,
                },
            },
        )

    history = receipt(-2, "history", 900, 900)
    foreign = receipt(
        1 if foreign_first else 2,
        "foreign",
        20 if foreign_first else 900,
        920 if foreign_first else 1840,
        "other-turn",
    )
    owned = receipt(2 if foreign_first else 1, "owned", 20, 940)
    events = [history, *([foreign, owned] if foreign_first else [owned, foreign])]
    models = {}
    measurement = reader._read_rollout_usage(
        reader.RolloutSession("parent", None, _rollout(tmp_path, "parent", events)),
        started_at=start,
        completed_at=None,
        owner_turn_id="scan-turn",
        model_usage=models,
    )
    total, warnings = measurement.tokens, measurement.warnings
    assert total == _counts(20, 0, 0)
    assert warnings == {
        "turn_in_progress",
        *([] if foreign_first else ["token_receipts_incomplete"]),
    }
    assert models == {"gpt-5.6-sol": _counts(20, 0, 0)}


@pytest.mark.parametrize(
    "scenario", ["prefix-first", "prefix-last", "continuation-only", "legacy-only"]
)
def test_rollout_copies_retain_the_continuations_native_receipt_model(
    tmp_path: Path, workbench_api, scenario: str
) -> None:
    reader = sys.modules["workbench_scan_usage"]
    start = datetime.fromisoformat("2026-09-01T00:00:00+00:00")
    prefix = [
        {
            "type": "session_meta",
            "payload": {"id": "worker", "timestamp": "2026-09-01T00:00:00Z", "source": "exec"},
        },
        _event(start, "turn_context", {"model": "gpt-5.6-sol", "turn_id": "turn"}),
        _token_event(start + timedelta(seconds=1), 200, 0),
    ]
    continuation = [
        *prefix,
        _event(
            start + timedelta(seconds=2),
            "token_usage_record",
            {
                "thread_id": "worker",
                "turn_id": "turn",
                "response_id": "response",
                "model": "gpt-6-astra",
                "usage": {
                    "input_tokens": 150,
                    "cache_write_input_tokens": 0,
                    "output_tokens": 0,
                    "total_tokens": 150,
                },
            },
        ),
    ]
    events = {
        "prefix-first": [prefix, continuation],
        "prefix-last": [continuation, prefix],
        "continuation-only": [continuation],
        "legacy-only": [prefix],
    }[scenario]
    copies = [
        reader.RolloutSession(
            "worker", None, _rollout(tmp_path, f"copy-{index}", value, recorded_thread_id="worker")
        )
        for index, value in enumerate(events)
    ]
    models = {}
    measurement = reader._read_rollout_copies_usage(
        copies, started_at=start, completed_at=None, owner_turn_id=None, model_usage=models
    )
    total, warnings = measurement.tokens, measurement.warnings
    assert total == _counts(200, 0, 0)
    if scenario == "legacy-only":
        assert warnings == set()
        assert models == {"gpt-5.6-sol": _counts(200, 0, 0)}
    else:
        assert warnings == {"token_receipts_incomplete"}
        assert models == {"gpt-6-astra": _counts(150, 0, 0), None: _counts(50, 0, 0)}
