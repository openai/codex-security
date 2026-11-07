"""Compute scan usage from session events and receipts, accounting for legacy duplicates and partial turns."""

from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from workbench_test_support import (
    SCRIPT,
    begin_deep_scan,
    cancel_scan,
    create_saved_workspace,
    fail_scan,
    initialize_git_repository,
    mark_deep_coordinator_succeeded,
    run_workbench,
    scan_command,
    start_delivered_scan,
    upsert_deep_worker,
    write_completed_contract,
)
from workbench_test_support import (
    usage_counts as _counts,
)


@pytest.fixture(scope="session")
def scan_usage(workbench_api):
    return workbench_api["scan_usage"]


@dataclass(frozen=True)
class ScanFixture:
    """Hold the CLI environment, scan identity, and launch time for replaying rollout events in usage tests."""

    state_dir: Path
    target: Path
    scan_id: str
    scan_dir: Path
    started_at: datetime
    environment: dict[str, str]
    mode: str = "standard"
    diff_target: dict[str, Any] | None = None

    def write_parent_rollout(
        self, events: list[dict[str, Any]], *, originator: str | None = None
    ) -> Path:
        """Write a parent rollout, register it in the fixture state graph, and return its path."""
        rollout = _rollout(self.target.parent, "scan-parent", events, originator=originator)
        _state_graph(self.environment, {"scan-parent": rollout}, [])
        return rollout

    def command(self, name: str, *arguments: str, check: bool = True) -> dict[str, Any]:
        return scan_command(
            self.state_dir,
            name,
            self.scan_id,
            *arguments,
            check=check,
            environment=self.environment,
        )


def _worker_usage_directory(fixture: ScanFixture) -> Path:
    return fixture.state_dir / "codex-home" / "worker-usage" / fixture.scan_id


def _start_scan(tmp_path: Path, *, mode: str = "standard", dedicated: bool = False) -> ScanFixture:
    state_dir = tmp_path / "workbench-state"
    target = tmp_path / "target"
    environment = {
        "CODEX_HOME": str(tmp_path / "codex-home"),
        "CODEX_SQLITE_HOME": str(tmp_path / "codex-sqlite"),
        "CODEX_STATE_DB": "",
    }
    diff_target = None
    if mode == "diff":
        revision = initialize_git_repository(target)
        workspace_id = str(uuid.uuid4())
        arguments = (
            "--workspace-id",
            workspace_id,
            "--target-path",
            str(target),
            "--mode",
            "diff",
            "--diff-target-kind",
            "commit",
            "--diff-head-revision",
            revision,
        )
        run_workbench(
            state_dir,
            "create-workspace",
            *arguments,
            "--thread-id",
            "scan-parent",
            environment=environment,
        )
        saved = run_workbench(
            state_dir,
            "save-workspace",
            *arguments,
            "--scope",
            ".",
            environment=environment,
        )
        diff_target = saved["diffTarget"]
    else:
        target.mkdir()
        (target / "app.py").write_text("print('fixture')\n", encoding="utf-8")
        workspace = create_saved_workspace(state_dir, target, thread_id="scan-parent", mode=mode)
        workspace_id = str(workspace["id"])

    if dedicated:
        scan_dir = tmp_path / "cli-scan"
        scan_dir.mkdir(mode=0o700)
        started = run_workbench(
            state_dir,
            "register-cli-scan",
            "--scan-dir",
            str(scan_dir),
            "--repository",
            str(target),
            "--registration-json-stdin",
            input_text=json.dumps(
                {
                    "recipe": {
                        "config": {},
                        "mode": mode,
                        "repository": str(target),
                        "target": {"kind": "repository", "paths": []},
                    }
                }
            ),
            environment=environment,
        )
    else:
        started = start_delivered_scan(
            state_dir,
            workspace_id,
            "--scan-root",
            str(tmp_path / "scans"),
            environment=environment,
        )
    if mode == "deep":
        begin_deep_scan(
            state_dir,
            "scan-parent",
            "--scan-id",
            str(started["scanId"]),
            "--available-parallelism",
            "4",
            environment=environment,
        )
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        row = connection.execute(
            "SELECT started_at FROM scans WHERE id = ?", (started["scanId"],)
        ).fetchone()
    assert row is not None
    return ScanFixture(
        state_dir,
        target,
        str(started["scanId"]),
        Path(str(started["scanDir"])),
        datetime.fromisoformat(row[0].replace("Z", "+00:00")),
        environment,
        mode,
        diff_target,
    )


def _event(timestamp: datetime, event_type: str, payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "timestamp": timestamp.isoformat().replace("+00:00", "Z"),
        "type": event_type,
        "payload": payload,
    }


def _token_event(
    timestamp: datetime,
    input_tokens: int,
    output_tokens: int,
    *,
    cached_input_tokens: int = 0,
) -> dict[str, Any]:
    return _event(
        timestamp,
        "event_msg",
        {
            "type": "token_count",
            "info": {
                "total_token_usage": {
                    "input_tokens": input_tokens,
                    "cached_input_tokens": cached_input_tokens,
                    "cache_write_input_tokens": 0,
                    "output_tokens": output_tokens,
                    "reasoning_output_tokens": 0,
                    "total_tokens": input_tokens + output_tokens,
                }
            },
        },
    )


def _rollout(
    root: Path,
    thread_id: str,
    events: list[dict[str, Any]],
    *,
    parent_thread_id: str | None = None,
    recorded_thread_id: str | None = None,
    include_task_start: bool = True,
    include_task_complete: bool = True,
    include_task_start_timestamp: bool = True,
    task_started_at: datetime | None = None,
    session_started_at: datetime | None = None,
    copied_events: list[dict[str, Any]] | None = None,
    originator: str | None = None,
) -> Path:
    directory = root / "rollouts"
    directory.mkdir(exist_ok=True)
    rollout = directory / f"{thread_id}.jsonl"
    source: Any = "cli"
    if parent_thread_id is not None:
        source = {"subagent": {"thread_spawn": {"parent_thread_id": parent_thread_id}}}
    own_started_at = (
        task_started_at.isoformat().replace("+00:00", "Z")
        if task_started_at is not None
        else next((item["timestamp"] for item in events if "timestamp" in item), None)
    )
    records: list[dict[str, Any]] = [
        {
            "type": "session_meta",
            "payload": {
                "id": recorded_thread_id or thread_id,
                "source": source,
                "timestamp": own_started_at,
            },
        },
        *(copied_events or []),
    ]
    if originator is not None:
        records[0]["payload"]["originator"] = originator
    if session_started_at is not None:
        records[0]["payload"]["timestamp"] = session_started_at.isoformat().replace("+00:00", "Z")
    if parent_thread_id is not None and include_task_start:
        event: dict[str, Any] = {
            "type": "event_msg",
            "payload": {
                "type": "task_started",
                "turn_id": f"turn-{thread_id}",
                "started_at": int(
                    datetime.fromisoformat(own_started_at.replace("Z", "+00:00")).timestamp()
                )
                if own_started_at is not None
                else None,
            },
        }
        if include_task_start_timestamp:
            event["timestamp"] = (
                task_started_at.isoformat().replace("+00:00", "Z")
                if task_started_at is not None
                else next(item["timestamp"] for item in events if "timestamp" in item)
            )
        records.append(event)
    records.extend(events)
    if events and parent_thread_id is not None and include_task_complete:
        records.append(
            {
                "timestamp": events[-1]["timestamp"],
                "type": "event_msg",
                "payload": {"type": "task_complete"},
            }
        )
    rollout.write_text(
        "".join(f"{json.dumps(item, separators=(',', ':'))}\n" for item in records),
        encoding="utf-8",
    )
    return rollout.resolve()


def _measure_rollout(
    scan_usage,
    path: Path,
    started_at: datetime,
    completed_at: datetime,
    *,
    thread_id: str = "scan-parent",
    parent_id: str | None = None,
    **options: str | None,
):
    return scan_usage._read_rollout_usage(
        scan_usage.RolloutSession(thread_id, parent_id, path),
        started_at=started_at,
        completed_at=completed_at,
        **options,
    )


def _allowance_event(timestamp: datetime, percent: int, limit: str = "codex") -> dict[str, Any]:
    return _event(
        timestamp,
        "event_msg",
        {
            "type": "token_count",
            "info": None,
            "rate_limits": {
                "limit_id": limit,
                "primary": {
                    "used_percent": percent,
                    "window_minutes": 10080,
                    "resets_at": 1800000000,
                },
                "secondary": None,
            },
        },
    )


def _response_event(
    timestamp: datetime,
    thread_id: str,
    response_id: str,
    input_tokens: int,
    output_tokens: int,
    *,
    turn_usage: tuple[int, int] | None = None,
    turn_id: str | None = None,
    cached_input_tokens: int = 0,
) -> dict[str, Any]:
    usage = _token_event(
        timestamp, input_tokens, output_tokens, cached_input_tokens=cached_input_tokens
    )["payload"]["info"]["total_token_usage"]
    total = (
        _token_event(timestamp, *turn_usage)["payload"]["info"]["total_token_usage"]
        if turn_usage is not None
        else usage
    )
    return _event(
        timestamp,
        "token_usage_record",
        {
            "thread_id": thread_id,
            "turn_id": turn_id or f"turn-{thread_id}",
            "session_id": "session-fixture",
            "root_turn_id": turn_id or f"turn-{thread_id}",
            "response_id": response_id,
            "usage": usage,
            "turn_token_usage": total,
            "thread_token_usage": total,
        },
    )


def _state_graph(
    environment: dict[str, str],
    threads: dict[str, Path],
    edges: list[tuple[str, str]],
) -> None:
    sqlite_home = Path(environment["CODEX_SQLITE_HOME"])
    sqlite_home.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(sqlite_home / "state_5.sqlite") as connection:
        connection.execute(
            "CREATE TABLE threads "
            "(id TEXT PRIMARY KEY, rollout_path TEXT NOT NULL, cwd TEXT, created_at INTEGER)"
        )
        connection.execute(
            "CREATE TABLE thread_spawn_edges "
            "(parent_thread_id TEXT NOT NULL, child_thread_id TEXT NOT NULL)"
        )
        connection.executemany(
            "INSERT INTO threads (id, rollout_path) VALUES (?, ?)",
            [(thread_id, str(path)) for thread_id, path in threads.items()],
        )
        connection.executemany(
            "INSERT INTO thread_spawn_edges (parent_thread_id, child_thread_id) VALUES (?, ?)",
            edges,
        )


def _complete_scan(fixture: ScanFixture, *arguments: str) -> dict[str, Any]:
    options: dict[str, Any] = {"relative_path": "app.py"}
    if fixture.mode == "diff":
        assert fixture.diff_target is not None
        options.update(
            relative_path="README.md",
            target_kind="git_diff",
            diff_base_revision=str(fixture.diff_target["baseRevision"]),
            diff_head_revision=str(fixture.diff_target["headRevision"]),
        )
    elif fixture.mode == "deep":
        options["coverage_mode"] = "deep_repository"
        mark_deep_coordinator_succeeded(fixture.state_dir, fixture.scan_id, fixture.scan_dir)
    write_completed_contract(
        fixture.scan_dir,
        fixture.scan_id,
        fixture.target,
        **options,
    )
    return fixture.command("complete-scan", *arguments)


@pytest.mark.parametrize(
    ("info", "coverage"),
    [("missing", "partial"), ("null", "complete"), ("invalid", "partial"), ("valid", "complete")],
)
def test_completion_preserves_usage_record_warnings(
    tmp_path: Path, info: str, coverage: str
) -> None:
    fixture = _start_scan(tmp_path)
    counted = fixture.started_at + timedelta(microseconds=1)
    event = _token_event(counted, 10, 5)
    if info == "missing":
        del event["payload"]["info"]
    elif info == "null":
        event["payload"]["info"] = None
    elif info == "invalid":
        event["payload"]["info"] = {}
    fixture.write_parent_rollout([event, _token_event(counted, 20, 10)])

    usage = _complete_scan(fixture)["scan"]["usage"]

    assert usage["coverage"] == coverage
    assert usage["totalTokens"] == 30
    assert usage.get("warnings", []) == (["token_record_invalid"] if coverage == "partial" else [])


def test_completion_counts_native_responses_and_compaction_without_legacy_duplicates(
    tmp_path: Path,
) -> None:
    fixture = _start_scan(tmp_path)
    counted = fixture.started_at + timedelta(microseconds=1)
    compaction = _response_event(counted, "scan-parent", "compaction", 40, 3, turn_usage=(60, 5))
    fixture.write_parent_rollout(
        [
            _token_event(fixture.started_at - timedelta(seconds=1), 100, 10),
            _token_event(counted, 150, 15),
            _event(counted, "event_msg", {"type": "task_started", "turn_id": "turn-scan-parent"}),
            _response_event(counted, "scan-parent", "first", 20, 2),
            _token_event(counted, 170, 17),
            compaction,
            _event(
                counted,
                "compacted",
                {
                    "message": "Summary.",
                    "replacement_history": [],
                    "compaction_response_id": "compaction",
                },
            ),
            _token_event(counted, 170, 17),
            compaction,
            _response_event(counted, "scan-parent", "last", 30, 4, turn_usage=(90, 9)),
            _event(counted, "event_msg", {"type": "task_complete"}),
        ]
    )

    assert (
        _complete_scan(fixture)["scan"]["usage"].items()
        >= {
            "coverage": "complete",
            "source": "codex_rollout",
            **_counts(140, 0, 14),
            "threadCount": 1,
        }.items()
    )


@pytest.mark.parametrize(
    ("scope", "native", "expected_warning"),
    [
        ("before", False, False),
        ("counted", False, True),
        ("after", False, False),
        ("completion_turn", False, True),
        ("counted", True, False),
        ("completion_turn", True, False),
        ("non_model", False, False),
    ],
)
def test_legacy_compaction_usage_is_unverifiable_only_inside_scan_window(
    scan_usage, tmp_path: Path, scope: str, native: bool, expected_warning: bool
) -> None:
    started = datetime.fromisoformat("2026-01-01T00:00:01+00:00")
    completed = started + timedelta(seconds=1)
    compacted_at = (
        started - timedelta(seconds=1)
        if scope == "before"
        else completed + timedelta(seconds=1)
        if scope in {"after", "completion_turn"}
        else started
    )
    marker = _event(compacted_at, "compacted", {"message": "Summary.", "replacement_history": []})
    if scope == "non_model":
        marker["payload"]["compaction_response_id"] = None
    events = [
        _event(started, "event_msg", {"type": "task_started", "turn_id": "turn-scan-parent"}),
        _response_event(started, "scan-parent", "compaction", 10, 1)
        if native
        else _token_event(started, 10, 1),
    ]
    events.insert(0 if scope == "before" else len(events), marker)
    events.append(_event(completed, "event_msg", {"type": "task_complete"}))
    parent = _rollout(tmp_path, "scan-parent", events)

    usage = _measure_rollout(
        scan_usage,
        parent,
        started,
        completed,
        completed_turn_id="turn-scan-parent" if scope == "completion_turn" else None,
    )

    assert usage.tokens == _counts(10, 0, 1)
    assert usage.warnings == ({"compaction_usage_unavailable"} if expected_warning else set())


def test_legacy_compaction_warning_survives_a_later_native_turn(scan_usage, tmp_path: Path) -> None:
    started = datetime.fromisoformat("2026-01-01T00:00:00+00:00")
    parent = _rollout(
        tmp_path,
        "scan-parent",
        [
            _token_event(started, 10, 1),
            _event(started, "compacted", {"message": "Summary.", "replacement_history": []}),
            _event(started, "event_msg", {"type": "task_started", "turn_id": "native-turn"}),
            _response_event(started, "scan-parent", "native", 20, 2, turn_id="native-turn"),
            _event(started, "event_msg", {"type": "task_complete"}),
        ],
    )

    usage = _measure_rollout(scan_usage, parent, started, started)

    assert usage.tokens == _counts(30, 0, 3)
    assert usage.warnings == {"compaction_usage_unavailable"}


def test_native_usage_respects_scan_window_and_preserves_cache_details(
    scan_usage, tmp_path: Path
) -> None:
    started = datetime.fromisoformat("2026-01-01T00:00:00+00:00")
    before = started - timedelta(seconds=1)
    completed = started + timedelta(seconds=1)
    response = _response_event(
        started, "scan-parent", "counted", 20, 2, turn_usage=(120, 12), cached_input_tokens=3
    )
    response["payload"]["usage"]["cache_write_input_tokens"] = 4
    response["payload"]["turn_token_usage"].update(
        cached_input_tokens=3, cache_write_input_tokens=4
    )
    parent = _rollout(
        tmp_path,
        "scan-parent",
        [
            _response_event(before, "scan-parent", "before", 100, 10),
            _token_event(before, 100, 10),
            response,
            _token_event(started, 120, 12),
            _event(completed, "event_msg", {"type": "task_complete"}),
            _response_event(
                completed + timedelta(seconds=1),
                "scan-parent",
                "after",
                80,
                8,
                turn_usage=(200, 20),
            ),
        ],
    )

    usage = _measure_rollout(scan_usage, parent, started, completed)

    assert usage.tokens == _counts(20, 3, 2, cache_write_input_tokens=4)
    assert usage.warnings == set()


def test_native_worker_usage_excludes_inherited_totals_and_survives_resume(
    scan_usage, tmp_path: Path
) -> None:
    started = datetime.fromisoformat("2026-01-01T00:00:00+00:00")
    inherited = _response_event(started, "scan-parent", "parent-response", 1_000, 100)
    owned = _response_event(started, "scan-worker", "worker-response", 20, 2)
    owned["payload"]["thread_token_usage"] = _token_event(started, 1_020, 102)["payload"]["info"][
        "total_token_usage"
    ]
    worker = _rollout(
        tmp_path,
        "scan-worker",
        [
            owned,
            inherited,
            _token_event(started, 1_020, 102),
            _event(started, "event_msg", {"type": "task_complete"}),
            _event(started, "event_msg", {"type": "task_started", "turn_id": "resumed-turn"}),
            _response_event(
                started, "scan-worker", "resumed-response", 30, 3, turn_id="resumed-turn"
            ),
            _token_event(started, 1_050, 105),
            _event(started, "event_msg", {"type": "task_complete"}),
            _event(started, "event_msg", {"type": "task_started", "turn_id": "legacy-turn"}),
            _token_event(started, 1_060, 106),
        ],
        parent_thread_id="scan-parent",
        copied_events=[inherited, _token_event(started, 1_000, 100)],
    )

    usage = _measure_rollout(
        scan_usage, worker, started, started, thread_id="scan-worker", parent_id="scan-parent"
    )

    assert usage.tokens == _counts(60, 0, 6)
    assert usage.warnings == set()


@pytest.mark.parametrize("gap", ["before", "after", "inside"])
def test_native_usage_only_marks_receipt_gaps_inside_scan_window(
    scan_usage, tmp_path: Path, gap: str
) -> None:
    started = datetime.fromisoformat("2026-01-01T00:00:00+00:00")
    baseline = 120 if gap == "before" else 20
    in_window = baseline + (40 if gap == "inside" else 30)
    after = in_window + (20 if gap == "after" else 10)
    parent = _rollout(
        tmp_path,
        "scan-parent",
        [
            _response_event(
                started - timedelta(seconds=1),
                "scan-parent",
                "before",
                20,
                0,
                turn_usage=(baseline, 0),
            ),
            _response_event(started, "scan-parent", "counted", 30, 0, turn_usage=(in_window, 0)),
            _event(started, "event_msg", {"type": "task_complete"}),
            _response_event(
                started + timedelta(seconds=1),
                "scan-parent",
                "after",
                10,
                0,
                turn_usage=(after, 0),
            ),
        ],
    )

    usage = _measure_rollout(scan_usage, parent, started, started)

    assert usage.tokens == _counts(30, 0, 0)
    assert usage.warnings == ({"token_record_incomplete"} if gap == "inside" else set())


def test_native_usage_continues_cumulative_baseline_when_recovering_same_turn(
    scan_usage,
    tmp_path: Path,
) -> None:
    started = datetime.fromisoformat("2026-01-01T00:00:00+00:00")
    turn_started = _event(
        started, "event_msg", {"type": "task_started", "turn_id": "turn-scan-parent"}
    )
    parent = _rollout(
        tmp_path,
        "scan-parent",
        [
            turn_started,
            _response_event(started, "scan-parent", "first", 10, 1),
            _token_event(started, 10, 1),
            turn_started,
            _response_event(started, "scan-parent", "recovered", 20, 2, turn_usage=(30, 3)),
            _token_event(started, 30, 3),
            _event(started, "event_msg", {"type": "task_complete"}),
        ],
    )

    usage = _measure_rollout(scan_usage, parent, started, started)

    assert usage.tokens == _counts(30, 0, 3)
    assert usage.warnings == set()


@pytest.mark.parametrize(
    "failure",
    [
        "invalid_usage",
        "invalid_timestamp",
        "timestamp_underflow",
        "timestamp_overflow",
        "boolean_cache_write",
        "float_cache_write",
        "missing_receipt",
        "truncated",
    ],
)
def test_native_usage_preserves_partial_measurement_warnings(
    scan_usage, tmp_path: Path, failure: str
) -> None:
    started = datetime.fromisoformat("2026-01-01T00:00:00+00:00")
    first = _response_event(started, "scan-parent", "first", 10, 1)
    second = _response_event(started, "scan-parent", "second", 20, 2, turn_usage=(30, 3))
    if failure == "invalid_usage":
        second["payload"]["usage"] = {}
    elif failure == "invalid_timestamp":
        del second["timestamp"]
    elif failure == "timestamp_underflow":
        second["timestamp"] = "0001-01-01T00:00:00+00:01"
    elif failure == "timestamp_overflow":
        second["timestamp"] = "9999-12-31T23:59:59-00:01"
    elif failure in {"boolean_cache_write", "float_cache_write"}:
        second["payload"]["usage"].update(
            cache_write_input_tokens=False if failure == "boolean_cache_write" else 0.0,
            cache_write_tokens=1,
        )
    events = [second] if failure == "missing_receipt" else [first, second]
    parent = _rollout(tmp_path, "scan-parent", events)
    if failure == "truncated":
        parent.write_bytes(parent.read_bytes().removesuffix(b"\n"))

    usage = _measure_rollout(scan_usage, parent, started, started)

    assert usage.tokens == (
        _counts(20, 0, 2) if failure == "missing_receipt" else _counts(10, 0, 1)
    )
    assert usage.warnings == {
        "token_record_incomplete"
        if failure == "missing_receipt"
        else "rollout_record_incomplete"
        if failure == "truncated"
        else "token_record_invalid",
        "turn_in_progress",
    }


@pytest.mark.native_macos
@pytest.mark.parametrize("mode", ["standard", "diff"])
def test_completion_counts_only_scan_owned_parent_and_descendants(
    tmp_path: Path,
    mode: str,
) -> None:
    fixture = _start_scan(tmp_path, mode=mode)
    before = fixture.started_at - timedelta(seconds=1)
    counted = fixture.started_at + timedelta(microseconds=1)
    parent_snapshot = _token_event(counted, 150, 25, cached_input_tokens=45)
    parent = _rollout(
        tmp_path,
        "scan-parent",
        [
            _token_event(before, 100, 10, cached_input_tokens=20),
            parent_snapshot,
        ],
    )
    worker_snapshot = _token_event(counted, 180, 32, cached_input_tokens=55)
    worker = _rollout(
        tmp_path,
        "scan-worker",
        [worker_snapshot],
        parent_thread_id="scan-parent",
        copied_events=[parent_snapshot],
    )
    descendant = _rollout(
        tmp_path,
        "nested-worker",
        [_token_event(counted, 8, 3, cached_input_tokens=2)],
        parent_thread_id="scan-worker",
    )
    unrelated = _rollout(tmp_path, "unrelated", [_token_event(counted, 80_000, 20_000)])
    # The completion subprocess must open the spaced CODEX_HOME through its SQLite URI.
    fixture.environment["CODEX_HOME"] = str(tmp_path / "native home")
    fixture.environment["CODEX_SQLITE_HOME"] = ""
    _state_graph(
        {"CODEX_SQLITE_HOME": fixture.environment["CODEX_HOME"]},
        {
            "scan-parent": parent,
            "scan-worker": worker,
            "nested-worker": descendant,
            "unrelated": unrelated,
        },
        [("scan-parent", "scan-worker"), ("scan-worker", "nested-worker")],
    )

    completed = _complete_scan(fixture)
    expected = {
        "coverage": "complete",
        "source": "codex_rollout",
        **_counts(88, 37, 25),
        "threadCount": 3,
    }
    assert completed["scan"]["mode"] == mode
    usage = completed["scan"]["usage"]
    assert usage.items() >= expected.items()
    assert usage["byRole"] == {
        "parent": {**_counts(50, 25, 15), "threadCount": 1},
        "workers": {**_counts(38, 12, 10), "threadCount": 2},
    }
    assert datetime.fromisoformat(usage["window"]["startedAt"]) == fixture.started_at
    assert datetime.fromisoformat(usage["tokensUpdatedAt"]) == counted
    assert datetime.fromisoformat(usage["observedAt"]) >= datetime.fromisoformat(
        usage["window"]["endedAt"]
    )
    expected = usage
    assert completed["workspace"]["results"]["usage"] == expected
    assert "byModel" not in completed["scan"]["usage"]
    assert (
        run_workbench(fixture.state_dir, "list-scans", environment=fixture.environment)["scans"][0][
            "usage"
        ]
        == expected
    )
    with sqlite3.connect(fixture.state_dir / "workbench.sqlite3") as connection:
        stored = connection.execute(
            "SELECT cost_json FROM scans WHERE id = ?", (fixture.scan_id,)
        ).fetchone()
    assert stored is not None
    assert json.loads(stored[0]) == {"usage": expected}


@pytest.mark.parametrize("cache_write_field", ["cache_write_input_tokens", "cache_write_tokens"])
def test_scan_usage_helper_preserves_cached_token_totals(
    scan_usage,
    cache_write_field: str,
) -> None:
    usage = {
        "input_tokens": 120,
        "cached_input_tokens": 30,
        cache_write_field: 12,
        "output_tokens": 15,
        "reasoning_output_tokens": 0,
        "total_tokens": 135,
    }

    assert scan_usage._token_snapshot({"info": {"total_token_usage": usage}}) == _counts(
        120, 30, 15, cache_write_input_tokens=12
    )


@pytest.mark.parametrize(
    ("canonical", "legacy", "expected"),
    [(0, 12, 12), (0, 0, 0), (5, 12, 5), (False, 12, None), (0.0, 12, None)],
)
def test_scan_usage_helper_requires_integer_cache_write_placeholder(
    scan_usage, canonical: object, legacy: int, expected: int | None
) -> None:
    usage = {
        "input_tokens": 120,
        "cached_input_tokens": 30,
        "cache_write_input_tokens": canonical,
        "cache_write_tokens": legacy,
        "output_tokens": 15,
        "total_tokens": 135,
    }

    assert scan_usage._usage_counts(usage) == (
        None if expected is None else _counts(120, 30, 15, cache_write_input_tokens=expected)
    )


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("0001-01-01T00:00:00+00:01", None),
        ("9999-12-31T23:59:59-00:01", None),
        ("0001-01-01T00:00:00Z", "0001-01-01T00:00:00+00:00"),
        ("9999-12-31T23:59:59Z", "9999-12-31T23:59:59+00:00"),
        ("2026-01-01T01:00:00+01:00", "2026-01-01T00:00:00+00:00"),
        ("2026-01-01T00:00:00", None),
    ],
)
def test_scan_usage_timestamp_handles_utc_boundaries(
    scan_usage, value: str, expected: str | None
) -> None:
    assert scan_usage._timestamp(value) == (
        datetime.fromisoformat(expected) if expected is not None else None
    )


@pytest.mark.parametrize("amount", [10**400, -(10**400)])
@pytest.mark.parametrize("measured", [False, True])
def test_scan_cost_preserves_diagnostics_for_overflowing_amount(
    workbench_api, amount: int, measured: bool
) -> None:
    cost = {
        "model": "fixture-model",
        "inputTokens": 120,
        "cachedInputTokens": 30,
        "cacheWriteInputTokens": 12,
        "outputTokens": 15,
        "estimatedUsd": amount,
    }
    value = (
        {
            "usage": {
                "coverage": "complete",
                "source": "codex_rollout",
                "threadCount": 1,
                **_counts(120, 30, 15),
            },
            "cost": cost,
        }
        if measured
        else cost
    )
    expected = (
        "Scan cost includes invalid measured token usage."
        if measured
        else "Scan cost must include a model, nonnegative token counts, and an estimated USD amount."
    )
    with pytest.raises(SystemExit) as error:
        workbench_api["parse_scan_cost"](json.dumps(value))
    assert str(error.value) == expected
    cost["estimatedUsd"] = 0.5
    assert json.loads(workbench_api["parse_scan_cost"](json.dumps(value))) == value


@pytest.mark.parametrize("coverage", [[], ["complete"], {}])
def test_scan_cost_preserves_diagnostics_for_non_scalar_coverage(workbench_api, coverage) -> None:
    value = {"usage": {"coverage": coverage, "source": "codex_rollout", "threadCount": 0}}
    with pytest.raises(SystemExit) as error:
        workbench_api["parse_scan_cost"](json.dumps(value))
    assert str(error.value) == "Scan cost includes invalid measured token usage."


@pytest.mark.parametrize(
    "warning", ["cost_estimate_covers_earlier_usage", "token_usage_unavailable"]
)
def test_only_price_warning_can_accompany_complete_token_coverage(workbench_api, warning) -> None:
    value = {
        "usage": {
            "coverage": "complete",
            "source": "codex_runtime",
            "threadCount": 1,
            "warnings": [warning],
            **_counts(120, 30, 15),
        }
    }
    if warning == "cost_estimate_covers_earlier_usage":
        assert json.loads(workbench_api["parse_scan_cost"](json.dumps(value))) == value
    else:
        with pytest.raises(SystemExit, match="invalid measured token usage"):
            workbench_api["parse_scan_cost"](json.dumps(value))


@pytest.mark.parametrize("cache_write_field", ["cache_write_input_tokens", "cache_write_tokens"])
def test_completion_includes_cached_and_cache_write_tokens(
    tmp_path: Path,
    cache_write_field: str,
) -> None:
    fixture = _start_scan(tmp_path)
    counted = fixture.started_at + timedelta(microseconds=1)
    event = _token_event(counted, 120, 15, cached_input_tokens=30)
    reported = event["payload"]["info"]["total_token_usage"]
    reported.pop("cache_write_input_tokens")
    reported[cache_write_field] = 12
    fixture.write_parent_rollout([event])

    usage = _complete_scan(fixture)["scan"]["usage"]

    assert (
        usage.items()
        >= {
            "coverage": "complete",
            "source": "codex_rollout",
            **_counts(120, 30, 15, cache_write_input_tokens=12),
            "threadCount": 1,
        }.items()
    )


@pytest.mark.parametrize("cache_writes", [None, 0, 12])
def test_completion_distinguishes_missing_cache_writes_from_zero(
    tmp_path: Path, cache_writes: int | None
) -> None:
    fixture = _start_scan(tmp_path)
    counted = fixture.started_at + timedelta(microseconds=1)
    event = _token_event(counted, 120, 15, cached_input_tokens=30)
    reported = event["payload"]["info"]["total_token_usage"]
    if cache_writes is None:
        reported.pop("cache_write_input_tokens")
    else:
        reported["cache_write_input_tokens"] = cache_writes
    _state_graph(
        fixture.environment,
        {"scan-parent": _rollout(tmp_path, "scan-parent", [event])},
        [],
    )
    live = fixture.command("read-scan-usage", "--thread-id", "scan-parent")
    assert live["cacheWriteInputTokensReported"] is (cache_writes is not None)
    measurement = _complete_scan(fixture)["scan"]["usage"]
    assert measurement["totalTokens"] == 135
    assert measurement["cacheWriteInputTokens"] == (cache_writes or 0)
    assert measurement["coverage"] == "complete"
    if cache_writes is None:
        assert measurement["cacheWriteInputTokensReported"] is False
        assert measurement["byRole"]["parent"]["cacheWriteInputTokensReported"] is False
    else:
        assert "cacheWriteInputTokensReported" not in measurement


@pytest.mark.parametrize(
    "cache_field", ["cached_input_tokens", "cache_write_input_tokens", "cache_write_tokens"]
)
@pytest.mark.parametrize(
    ("snapshots", "expected_input", "expected_cache"),
    [
        ([(100, 50), (100, None), (100, 50)], 100, 50),
        ([(100, 100), (200, None), (200, 100)], 200, 100),
        ([(100, 40), (200, None), (300, 60)], 300, 60),
        ([(100, 40), (20, None), (100, 20)], 200, 60),
        ([(100, 40), (200, 20), (300, 30)], 300, 70),
        ([(100, None), (100, 50)], 100, 50),
    ],
    ids=[
        "same-total",
        "increasing",
        "new-writes",
        "epoch-reset",
        "explicit-decrease",
        "initial-omission",
    ],
)
def test_completion_retains_cache_baseline_across_omissions(
    tmp_path: Path,
    cache_field: str,
    snapshots: list[tuple[int, int | None]],
    expected_input: int,
    expected_cache: int,
) -> None:
    fixture = _start_scan(tmp_path)
    counted = fixture.started_at + timedelta(microseconds=1)
    events = []
    is_cache_read = cache_field == "cached_input_tokens"
    for input_tokens, cache_tokens in snapshots:
        event = _token_event(counted, input_tokens, 0)
        reported = event["payload"]["info"]["total_token_usage"]
        reported.pop("cached_input_tokens" if is_cache_read else "cache_write_input_tokens")
        if cache_tokens is not None:
            reported[cache_field] = cache_tokens
        events.append(event)
    parent = _rollout(tmp_path, "scan-parent", events)
    _state_graph(fixture.environment, {"scan-parent": parent}, [])

    usage = _complete_scan(fixture)["scan"]["usage"]

    assert (
        usage.items()
        >= {
            "coverage": "complete",
            "source": "codex_rollout",
            **_counts(
                expected_input,
                expected_cache if is_cache_read else 0,
                0,
                cache_write_input_tokens=0 if is_cache_read else expected_cache,
            ),
            "threadCount": 1,
        }.items()
    )


@pytest.mark.parametrize("recovered", [False, True])
def test_inconsistent_partial_cache_snapshot_cannot_establish_a_baseline(
    scan_usage, tmp_path: Path, recovered: bool
) -> None:
    started = datetime.fromisoformat("2026-01-01T00:00:00+00:00")
    initial = _token_event(started, 100, 0, cached_input_tokens=80)
    partial = _token_event(started, 100, 0)
    partial_usage = partial["payload"]["info"]["total_token_usage"]
    del partial_usage["cached_input_tokens"]
    partial_usage["cache_write_input_tokens"] = 50
    events = [initial, partial]
    if recovered:
        latest = _token_event(started, 140, 0, cached_input_tokens=80)
        latest["payload"]["info"]["total_token_usage"]["cache_write_input_tokens"] = 60
        events.append(latest)
    result = _measure_rollout(
        scan_usage, _rollout(tmp_path, "scan-parent", events), started, started
    )
    assert result.warnings == {"token_breakdown_unavailable"}
    assert result.tokens == _counts(
        140 if recovered else 100, 80, 0, cache_write_input_tokens=60 if recovered else 0
    )


@pytest.mark.parametrize("category", ["cached_input_tokens", "cache_write_input_tokens"])
@pytest.mark.parametrize("missing", [None, "refined", "other"])
@pytest.mark.parametrize("new_input", [0, 1000])
def test_late_cache_classification_only_excludes_ambiguous_categories(
    tmp_path: Path, category: str, missing: str | None, new_input: int
) -> None:
    fixture = _start_scan(tmp_path)
    counted = fixture.started_at + timedelta(microseconds=1)
    prefix = _token_event(fixture.started_at - timedelta(seconds=1), 1000, 0)
    owned = _token_event(counted, 2000, 0)
    refined = _token_event(counted, 2000 + new_input, 0)
    if missing is not None:
        other = (
            "cache_write_input_tokens"
            if category == "cached_input_tokens"
            else "cached_input_tokens"
        )
        absent = category if missing == "refined" else other
        for event in (prefix, owned, refined):
            del event["payload"]["info"]["total_token_usage"][absent]
    refined["payload"]["info"]["total_token_usage"][category] = 1000
    _state_graph(
        fixture.environment,
        {
            "scan-parent": _rollout(tmp_path, "scan-parent", [prefix, owned, refined]),
            "child": _rollout(
                tmp_path, "child", [_token_event(counted, 30, 5)], parent_thread_id="scan-parent"
            ),
        },
        [("scan-parent", "child")],
    )
    usage = fixture.command("read-scan-usage", "--thread-id", "scan-parent")
    ambiguous = missing == "refined"
    assert usage["coverage"] == ("partial" if ambiguous else "complete")
    assert usage["totalTokens"] == (35 if ambiguous else 1035 + new_input)
    assert usage["byRole"]["parent"]["threadCount"] == (0 if ambiguous else 1)
    assert usage.get("warnings", []) == (["token_breakdown_unavailable"] if ambiguous else [])


@pytest.mark.parametrize("previous_native", [False, True])
@pytest.mark.parametrize("current_native", [False, True])
def test_legacy_cache_refinement_survives_turn_boundaries(
    scan_usage, tmp_path: Path, previous_native: bool, current_native: bool
) -> None:
    started = datetime.fromisoformat("2026-01-01T00:00:00+00:00")
    initial = _token_event(started, 100, 10)
    initial["payload"]["info"]["total_token_usage"].pop("cache_write_input_tokens")
    refined = _token_event(started, 100, 10, cached_input_tokens=20)
    refined["payload"]["info"]["total_token_usage"]["cache_write_input_tokens"] = 30
    later = _token_event(started, 150, 20, cached_input_tokens=20)
    later["payload"]["info"]["total_token_usage"]["cache_write_input_tokens"] = 30
    events = [
        _event(started, "event_msg", {"type": "task_started", "turn_id": "previous"}),
        initial,
    ]
    if previous_native:
        events.append(
            _response_event(
                started,
                "scan-parent",
                "previous",
                100,
                10,
                turn_id="previous",
                cached_input_tokens=7,
            )
        )
    events.extend(
        [
            _event(started, "event_msg", {"type": "task_started", "turn_id": "current"}),
            refined,
        ]
    )
    if current_native:
        events.append(
            _response_event(
                started,
                "scan-parent",
                "current",
                50,
                10,
                turn_id="current",
                cached_input_tokens=5,
            )
        )
    events.append(later)
    events.extend(
        _event(started, "event_msg", {"type": "task_complete", "turn_id": turn})
        for turn in ("previous", "current")
    )
    parent = _rollout(tmp_path, "scan-parent", events)
    result = _measure_rollout(scan_usage, parent, started, started)

    expected = _counts(
        150,
        (7 if previous_native else 20) + (5 if current_native else 0),
        20,
        cache_write_input_tokens=0 if previous_native else 30,
    )
    # Native per-response receipts establish both cache counters. Legacy
    # measurements retain their omission marker alongside the refined subtotal.
    if not (previous_native and current_native):
        expected["cacheWriteInputTokensReported"] = False
    assert result.tokens == expected
    assert result.warnings == set()


def test_completion_excludes_separately_inherited_worker_snapshots(tmp_path: Path) -> None:
    fixture = _start_scan(tmp_path)
    counted = fixture.started_at + timedelta(microseconds=1)
    first_snapshot = _token_event(counted, 120, 10, cached_input_tokens=20)
    second_snapshot = _token_event(counted, 170, 25, cached_input_tokens=40)
    parent = _rollout(tmp_path, "scan-parent", [first_snapshot, second_snapshot])
    first = _rollout(
        tmp_path,
        "first-worker",
        [_token_event(counted, 150, 17, cached_input_tokens=30)],
        parent_thread_id="scan-parent",
        copied_events=[first_snapshot],
    )
    second = _rollout(
        tmp_path,
        "second-worker",
        [_token_event(counted, 210, 35, cached_input_tokens=55)],
        parent_thread_id="scan-parent",
        copied_events=[second_snapshot],
    )
    _state_graph(
        fixture.environment,
        {"scan-parent": parent, "first-worker": first, "second-worker": second},
        [("scan-parent", "first-worker"), ("scan-parent", "second-worker")],
    )
    usage = _complete_scan(fixture)["scan"]["usage"]
    assert (
        usage.items()
        >= {
            "coverage": "complete",
            "source": "codex_rollout",
            **_counts(240, 65, 42),
            "threadCount": 3,
        }.items()
    )


def test_completion_ignores_worker_families_started_before_scan(tmp_path: Path) -> None:
    fixture = _start_scan(tmp_path)
    before = fixture.started_at - timedelta(minutes=30)
    counted = fixture.started_at + timedelta(microseconds=1)
    parent = _rollout(tmp_path, "scan-parent", [_token_event(counted, 10, 0)])
    worker = _rollout(
        tmp_path,
        "old-worker",
        [_token_event(before, 100, 0), _token_event(counted, 200, 0)],
        parent_thread_id="scan-parent",
        task_started_at=before,
    )
    descendant = _rollout(
        tmp_path,
        "old-descendant",
        [_token_event(before, 50, 0), _token_event(counted, 90, 0)],
        parent_thread_id="old-worker",
        task_started_at=before,
    )
    _state_graph(
        fixture.environment,
        {"scan-parent": parent, "old-worker": worker, "old-descendant": descendant},
        [("scan-parent", "old-worker"), ("old-worker", "old-descendant")],
    )
    assert (
        _complete_scan(fixture)["scan"]["usage"].items()
        >= {
            "coverage": "complete",
            "source": "codex_rollout",
            **_counts(10, 0, 0),
            "threadCount": 1,
        }.items()
    )


@pytest.mark.parametrize(
    ("failure", "warning"),
    [
        ("missing_rollout", "rollout_unavailable"),
        ("wrong_identity", "thread_identity_mismatch"),
        ("missing_ownership", "thread_ownership_unavailable"),
        ("missing_timestamp", "thread_ownership_unavailable"),
    ],
)
def test_completion_marks_unverifiable_workers_partial(
    tmp_path: Path,
    failure: str,
    warning: str,
) -> None:
    fixture = _start_scan(tmp_path)
    counted = fixture.started_at + timedelta(microseconds=1)
    parent = _rollout(
        tmp_path,
        "scan-parent",
        [_token_event(counted, 12, 4, cached_input_tokens=3)],
    )
    worker = (
        (tmp_path / "missing-rollout.jsonl").resolve()
        if failure == "missing_rollout"
        else _rollout(
            tmp_path,
            "scan-worker",
            [_token_event(counted, 800, 200)],
            parent_thread_id="scan-parent",
            recorded_thread_id="other-worker" if failure == "wrong_identity" else None,
            include_task_start=failure != "missing_ownership",
            include_task_start_timestamp=failure != "missing_timestamp",
        )
    )
    _state_graph(
        fixture.environment,
        {"scan-parent": parent, "scan-worker": worker},
        [("scan-parent", "scan-worker")],
    )
    usage = _complete_scan(fixture)["scan"]["usage"]
    assert usage["coverage"] == "partial"
    assert usage["threadCount"] == 1
    assert usage["missingThreadCount"] == 1
    assert warning in usage["warnings"]
    assert usage["totalTokens"] == 16


@pytest.mark.cross_platform
@pytest.mark.parametrize("home_variable", ["CODEX_HOME", "CODEX_SQLITE_HOME"])
@pytest.mark.parametrize("home_kind", ["absolute", "literal_tilde", "relative_home", "home"])
def test_usage_finds_state_database_in_configured_home(
    tmp_path: Path,
    home_variable: str,
    home_kind: str,
    monkeypatch: pytest.MonkeyPatch,
    scan_usage,
) -> None:
    home = tmp_path / ("native home" if sys.platform == "win32" else "native home ")
    if home_kind == "literal_tilde":
        home = tmp_path / ("~ literal" if sys.platform == "win32" else "~ ")
    home.mkdir()
    database = home / "state_5.sqlite"
    database.touch()
    monkeypatch.setenv("CODEX_STATE_DB", "")
    monkeypatch.setenv("CODEX_SQLITE_HOME", "")
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "unused"))
    configured_home = str(home)
    if home_kind == "literal_tilde":
        monkeypatch.chdir(tmp_path)
        configured_home = home.name
    elif home_kind in {"relative_home", "home"}:
        monkeypatch.setenv("HOME", str(home if home_kind == "home" else tmp_path))
        monkeypatch.setenv("USERPROFILE", str(home if home_kind == "home" else tmp_path))
        configured_home = "~" if home_kind == "home" else f"~/{home.name}"
    monkeypatch.setenv(home_variable, configured_home)

    assert scan_usage._codex_state_database() == database.resolve()


def test_completion_reports_unavailable_without_fabricating_zero(tmp_path: Path) -> None:
    fixture = _start_scan(tmp_path)
    usage = _complete_scan(fixture)["scan"]["usage"]
    assert (
        usage.items()
        >= {
            "coverage": "unavailable",
            "source": "codex_rollout",
            "threadCount": 0,
            "warnings": ["codex_state_unavailable"],
        }.items()
    )
    assert "totalTokens" not in usage


@pytest.mark.parametrize("observation", ["missing", "null", "before", "legacy_zero", "native_zero"])
def test_completion_distinguishes_missing_usage_from_observed_zero(
    tmp_path: Path, observation: str
) -> None:
    fixture = _start_scan(tmp_path)
    counted = fixture.started_at + timedelta(microseconds=1)
    events = []
    if observation == "null":
        events = [_event(counted, "event_msg", {"type": "token_count", "info": None})]
    elif observation == "before":
        events = [_token_event(fixture.started_at - timedelta(seconds=1), 10, 1)]
    elif observation == "legacy_zero":
        events = [_token_event(counted, 0, 0)]
    elif observation == "native_zero":
        events = [
            _response_event(counted, "scan-parent", "zero-response", 0, 0),
            _event(counted, "event_msg", {"type": "task_complete", "turn_id": "turn-scan-parent"}),
        ]
    fixture.write_parent_rollout(events)

    usage = _complete_scan(fixture)["scan"]["usage"]

    if observation.endswith("_zero"):
        expected = {
            "coverage": "complete",
            "source": "codex_rollout",
            **_counts(0, 0, 0),
            "threadCount": 1,
        }
        assert usage.items() >= expected.items()
    else:
        assert usage == {
            "coverage": "unavailable",
            "source": "codex_rollout",
            "threadCount": 0,
            "warnings": ["token_record_missing", "token_usage_unavailable"],
        }


@pytest.mark.parametrize("missing_thread", ["scan-parent", "scan-worker"])
def test_missing_usage_preserves_measured_parent_or_descendant(
    tmp_path: Path, missing_thread: str
) -> None:
    fixture = _start_scan(tmp_path)
    counted = fixture.started_at + timedelta(microseconds=1)
    _state_graph(
        fixture.environment,
        {
            thread: _rollout(
                tmp_path,
                thread,
                [] if thread == missing_thread else [_token_event(counted, 10, 2)],
                parent_thread_id="scan-parent" if thread == "scan-worker" else None,
                task_started_at=counted,
            )
            for thread in ["scan-parent", "scan-worker"]
        },
        [("scan-parent", "scan-worker")],
    )

    expected = {
        "coverage": "partial",
        "source": "codex_rollout",
        **_counts(10, 0, 2),
        "threadCount": 1,
        "missingThreadCount": 1,
        "warnings": [
            "token_record_missing",
            "token_usage_unavailable",
            *(["turn_in_progress"] if missing_thread == "scan-worker" else []),
        ],
    }
    assert _complete_scan(fixture)["scan"]["usage"].items() >= expected.items()


@pytest.mark.native_macos
@pytest.mark.skipif(sys.platform != "darwin", reason="macOS system path aliases")
@pytest.mark.parametrize("temporary_root", [tempfile.gettempdir(), "/tmp"], ids=["var", "tmp"])
def test_completion_accepts_macos_system_rollout_alias(
    tmp_path: Path,
    temporary_root: str,
) -> None:
    fixture = _start_scan(tmp_path)
    counted = fixture.started_at + timedelta(microseconds=1)
    with tempfile.TemporaryDirectory(dir=temporary_root) as directory:
        root = Path(directory)
        canonical = _rollout(root, "scan-parent", [_token_event(counted, 10, 3)])
        alias = root / "rollouts" / "scan-parent.jsonl"
        assert alias != canonical
        assert alias.resolve() == canonical
        _state_graph(fixture.environment, {"scan-parent": alias}, [])
        usage = _complete_scan(fixture)["scan"]["usage"]
    assert usage["coverage"] == "complete"
    assert usage["totalTokens"] == 13


@pytest.mark.native_macos
def test_completion_rejects_non_system_rollout_symlink(tmp_path: Path) -> None:
    fixture = _start_scan(tmp_path)
    counted = fixture.started_at + timedelta(microseconds=1)
    canonical = _rollout(tmp_path, "scan-parent", [_token_event(counted, 10, 3)])
    symlink = canonical.with_name("linked-rollout.jsonl")
    symlink.symlink_to(canonical)
    _state_graph(fixture.environment, {"scan-parent": symlink}, [])
    assert (
        _complete_scan(fixture)["scan"]["usage"].items()
        >= {
            "coverage": "unavailable",
            "source": "codex_rollout",
            "threadCount": 0,
            "warnings": ["rollout_unavailable", "scan_thread_unavailable"],
        }.items()
    )


def test_completion_counts_deep_worker_retries_and_descendants(tmp_path: Path) -> None:
    fixture = _start_scan(tmp_path, mode="deep")
    counted = fixture.started_at + timedelta(microseconds=1)
    artifact = fixture.scan_dir / "artifacts" / "usage-worker"
    artifact.mkdir(parents=True)
    prompt = artifact / "prompt.md"
    prompt.write_text("Review the fixture target.\n", encoding="utf-8")
    worker_id = str(uuid.uuid4())
    for attempt, thread in [(1, "sdk-worker"), (2, "sdk-retry"), (2, "sdk-retry")]:
        upsert_deep_worker(
            fixture.state_dir,
            fixture.scan_id,
            worker_id,
            "discovery",
            "running",
            str(prompt),
            str(artifact),
            "--attempt",
            str(attempt),
            "--sdk-thread-id",
            thread,
            environment=fixture.environment,
        )
    _state_graph(
        fixture.environment,
        {
            "scan-parent": _rollout(tmp_path, "scan-parent", [_token_event(counted, 10, 3)]),
            "comparison": _rollout(tmp_path, "comparison", [_token_event(counted, 50, 5)]),
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
    with sqlite3.connect(Path(fixture.environment["CODEX_SQLITE_HOME"]) / "state_5.sqlite") as db:
        db.execute(
            "UPDATE threads SET cwd = ?, created_at = ? WHERE id = 'comparison'",
            (str(fixture.scan_dir / "artifacts" / "deep_discovery"), int(counted.timestamp())),
        )
    usage = _complete_scan(fixture)["scan"]["usage"]
    assert (
        usage.items()
        >= {
            "coverage": "partial",
            "source": "codex_rollout",
            # Count the comparison worker alongside both attempts and the child.
            **_counts(107, 0, 15),
            "threadCount": 4,
            "missingThreadCount": 1,
            "warnings": ["scan_owner_turn_unavailable"],
            "modelUsage": [{"model": None, **_counts(107, 0, 15)}],
        }.items()
    )


@pytest.mark.parametrize(
    "worker_home",
    [
        "recorded",
        "current",
        "inherited-sqlite",
        "current-prefix",
        "recorded-prefix",
        "current-equal-incomplete",
        "recorded-equal-incomplete",
        "current-unreadable",
        "current-mismatched",
        "external-sqlite",
        "external-archived",
        "external-home-alias",
        "external-archived-home-alias",
        "external-shared-home",
        "external-missing-copy",
        "external-missing-child",
        "external-current-middle-missing",
        "external-current-middle-complete",
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
        "current-equal-incomplete",
        "recorded-equal-incomplete",
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
        if worker_home in {"external-home-alias", "external-archived-home-alias"}:
            actual_home = root / "actual-home"
            actual_home.mkdir()
            selected_home.symlink_to(actual_home, target_is_directory=True)
        process = subprocess.run(
            [
                sys.executable,
                "-c",
                (
                    "import runpy, sys; script = sys.argv.pop(1); "
                    "runpy.run_path(script)['main'](with_execution_settings=True)"
                ),
                str(SCRIPT),
                "begin-deep-scan",
                "--thread-id",
                f"owner-{index}",
                "--target-path",
                str(target),
                "--scan-root",
                str(root / "scans"),
            ],
            env={**os.environ, **environment, "CODEX_SECURITY_STATE_DIR": str(root / "state")},
            input=json.dumps(
                {
                    "executionSettings": {
                        "codexHome": str(selected_home),
                        "codexPath": sys.executable,
                    }
                }
            ),
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert process.returncode == 0, process.stderr
        deep = json.loads(process.stdout)["deepScan"]
        scan_id, scan_dir = deep["scanId"], Path(deep["scanDir"])
        snapshot = scan_dir / "artifacts/deep_discovery/execution-settings.json"
        original_bytes = snapshot.read_bytes()
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
        for kind in ("discovery", "second-discovery"):
            thread_id = f"{kind}-{index}"
            artifact = scan_dir / "artifacts" / thread_id
            artifact.mkdir(mode=0o700)
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
        child_id = f"child-{index}"
        worker_threads[child_id] = _rollout(
            root,
            child_id,
            [_token_event(counted, index * 7, 1)],
            parent_thread_id=f"discovery-{index}",
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
            "current-prefix",
            "recorded-prefix",
            "current-equal-incomplete",
            "recorded-equal-incomplete",
            "current-unreadable",
            "current-mismatched",
        }:
            recorded_threads = dict(worker_threads)
            if worker_home != "recorded":
                thread_id = f"discovery-{index}"
                full = worker_threads[thread_id]
                copied = full.with_name(f"copied-{thread_id}.jsonl")
                copied.write_bytes(b"\n".join(full.read_bytes().splitlines()[:3]) + b"\n")
                if worker_home in {"current-equal-incomplete", "recorded-equal-incomplete"}:
                    copied.write_bytes(full.read_bytes() + b'{"type":"event_msg"')
                if worker_home == "current-unreadable":
                    copied.write_text("invalid session metadata\n")
                elif worker_home == "current-mismatched":
                    copied.write_text(full.read_text().replace(thread_id, "unrelated-thread"))
                current_copy = copied
                if worker_home in {"recorded-prefix", "recorded-equal-incomplete"}:
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
                [(f"discovery-{index}", child_id)],
            )
        elif worker_home in {
            "external-sqlite",
            "external-archived",
            "external-home-alias",
            "external-archived-home-alias",
            "external-shared-home",
            "external-missing-copy",
            "external-missing-child",
            "external-current-middle-missing",
            "external-current-middle-complete",
        }:
            if worker_home.startswith("external-current-middle"):
                grandchild_id = f"grandchild-{index}"
                worker_threads[grandchild_id] = _rollout(
                    root,
                    grandchild_id,
                    [_token_event(counted, index * 11, 2)],
                    parent_thread_id=child_id,
                )
            # Native keeps rollouts in its Codex home even when its SQLite
            # index lives elsewhere and recovery chooses a different index.
            sessions = (
                selected_home
                / ("archived_sessions" if "archived" in worker_home else "sessions")
                / "2026"
                / "01"
                / "01"
            )
            sessions.mkdir(parents=True, exist_ok=True)
            for thread_id, path in worker_threads.items():
                recorded = sessions / f"rollout-{thread_id}.jsonl"
                path.rename(recorded)
                worker_threads[thread_id] = recorded
            _state_graph(
                {"CODEX_SQLITE_HOME": str(root / "original-external-sqlite")},
                worker_threads,
                [(f"discovery-{index}", child_id)],
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
        if worker_home.startswith("external-current-middle"):
            # Recovery's current index sees the grandchild while its parent
            # rollout is restored later from the worker's original home.
            with sqlite3.connect(environment["CODEX_STATE_DB"]) as connection:
                connection.executemany(
                    "INSERT INTO threads (id, rollout_path) VALUES (?, ?)",
                    [
                        (f"discovery-{index}", str(worker_threads[f"discovery-{index}"])),
                        (
                            child_id,
                            str(root / "missing-middle.jsonl")
                            if worker_home.endswith("missing")
                            else str(worker_threads[child_id]),
                        ),
                        (grandchild_id, str(worker_threads[grandchild_id])),
                    ],
                )
                connection.executemany(
                    "INSERT INTO thread_spawn_edges VALUES (?, ?)",
                    [(f"discovery-{index}", child_id), (child_id, grandchild_id)],
                )
        result = _complete_scan(fixture)["scan"]["usage"]
        assert snapshot.read_bytes() == original_bytes
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
            assert (
                usage.items()
                >= {
                    "coverage": "complete",
                    "source": "codex_rollout",
                    **_counts(
                        index * (88 if worker_home.startswith("external-current-middle") else 77),
                        0,
                        15 if worker_home.startswith("external-current-middle") else 13,
                    ),
                    "threadCount": 5 if worker_home.startswith("external-current-middle") else 4,
                    "modelUsage": (
                        [
                            {"model": None, **_counts(index * 47, 0, 8)},
                            {"model": "model-alpha", **_counts(index * 20, 0, 3)},
                            {"model": "model-beta", **_counts(index * 10, 0, 2)},
                        ]
                        if copied_rollout
                        else [
                            {
                                "model": None,
                                **_counts(
                                    index
                                    * (
                                        88
                                        if worker_home.startswith("external-current-middle")
                                        else 77
                                    ),
                                    0,
                                    15 if worker_home.startswith("external-current-middle") else 13,
                                ),
                            }
                        ]
                    ),
                }.items()
            )


def test_recorded_home_alias_keeps_individual_rollout_links_excluded(
    tmp_path: Path, workbench_api
) -> None:
    reader = sys.modules["workbench_scan_usage"]
    home = tmp_path / "home"
    sessions = home / "sessions"
    sessions.mkdir(parents=True)
    alias = tmp_path / "alias"
    alias.symlink_to(home, target_is_directory=True)
    canonical = _rollout(tmp_path, "worker", [])
    path = sessions / "worker.jsonl"
    canonical.rename(path)
    linked = _rollout(tmp_path, "linked-worker", [])
    (sessions / "linked-worker.jsonl").symlink_to(linked)
    (sessions / "linked-directory").symlink_to(linked.parent, target_is_directory=True)

    discovered = reader._discover_recorded_worker_sessions(alias, {"worker", "linked-worker"})
    assert [(session.thread_id, session.path) for session in discovered] == [("worker", path)]
    assert reader._discover_recorded_worker_sessions(tmp_path / "missing-home", {"worker"}) == []


@pytest.mark.parametrize("owner_first", [True, False])
def test_usage_counts_registered_worker_when_its_parent_rollout_is_missing(
    scan_usage, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, owner_first: bool
) -> None:
    fixture = _start_scan(tmp_path)
    counted = fixture.started_at + timedelta(microseconds=1)
    inherited = _token_event(counted, 100, 10)
    _state_graph(
        fixture.environment,
        {
            "scan-parent": _rollout(tmp_path, "scan-parent", [_token_event(counted, 10, 3)]),
            "missing-parent": tmp_path / "missing.jsonl",
            "registered-worker": _rollout(
                tmp_path,
                "registered-worker",
                [_token_event(counted, 120, 15)],
                parent_thread_id="missing-parent",
                copied_events=[inherited],
            ),
            "worker-child": _rollout(
                tmp_path,
                "worker-child",
                [_token_event(counted, 7, 2)],
                parent_thread_id="registered-worker",
            ),
        },
        [
            ("scan-parent", "missing-parent"),
            ("missing-parent", "registered-worker"),
            ("registered-worker", "worker-child"),
        ],
    )
    for key, value in fixture.environment.items():
        monkeypatch.setenv(key, value)
    with sqlite3.connect(fixture.state_dir / "workbench.sqlite3") as connection:
        connection.row_factory = sqlite3.Row
        connection.execute(
            "UPDATE scans SET continuation_thread_id = ? WHERE id = ?",
            ("registered-worker", fixture.scan_id),
        )
        scan = connection.execute("SELECT * FROM scans WHERE id = ?", (fixture.scan_id,)).fetchone()
        usage = scan_usage.collect_scan_usage(
            connection,
            scan,
            thread_id="scan-parent" if owner_first else None,
            completed_at=counted.isoformat(),
        )

    assert (
        usage.items()
        >= {
            "coverage": "partial",
            "source": "codex_rollout",
            **_counts(37, 0, 10),
            "threadCount": 3,
            "missingThreadCount": 1,
            "warnings": ["rollout_unavailable"],
        }.items()
    )


@pytest.mark.parametrize("delayed_cache_counts", [False, True])
def test_completion_preserves_large_legacy_cost(tmp_path: Path, delayed_cache_counts: bool) -> None:
    fixture = _start_scan(tmp_path)
    counted = fixture.started_at + timedelta(microseconds=1)
    fixture.write_parent_rollout(
        [
            _token_event(fixture.started_at - timedelta(seconds=1), 100, 0),
            _token_event(counted, 115, 6, cached_input_tokens=100 if delayed_cache_counts else 0),
            _allowance_event(counted, 6),
        ]
    )
    cost = {
        "model": "gpt-5.6-sol",
        "inputTokens": 15,
        "cachedInputTokens": 4,
        "cacheWriteInputTokens": 0,
        "outputTokens": 6,
        "estimatedUsd": 0.002,
    }
    write_completed_contract(
        fixture.scan_dir, fixture.scan_id, fixture.target, relative_path="app.py"
    )
    completed = fixture.command("complete-scan", "--cost-json", json.dumps(cost) + " " * 8192)[
        "scan"
    ]
    assert completed["cost"] == cost
    assert completed["usage"]["accountRateLimits"][0]["primary"]["usedPercent"] == 6
    if delayed_cache_counts:
        assert completed["usage"]["coverage"] == "unavailable"
        assert completed["usage"]["warnings"] == ["token_breakdown_unavailable"]
        assert "totalTokens" not in completed["usage"]
    else:
        assert completed["usage"]["totalTokens"] == 21


@pytest.mark.parametrize(
    "native_state",
    ["complete", "missing-worker", "missing-turn", "unavailable", "unavailable-turn"],
)
def test_completion_reconciles_supplied_usage_with_native_evidence(
    tmp_path: Path, native_state: str
) -> None:
    fixture = _start_scan(tmp_path)
    counted = fixture.started_at + timedelta(microseconds=1)
    events = [_token_event(counted, 15, 6), _allowance_event(counted, 6)]
    if native_state == "missing-turn":
        events.extend(
            _event(counted, "event_msg", {"type": kind, "turn_id": "unmeasured-turn"})
            for kind in ("task_started", "task_complete")
        )
    if native_state not in {"unavailable", "unavailable-turn"}:
        _state_graph(
            fixture.environment,
            {"scan-parent": _rollout(tmp_path, "scan-parent", events)},
            [("scan-parent", "missing-worker")] if native_state == "missing-worker" else [],
        )
    runtime = {
        "source": "codex_runtime",
        "coverage": "complete",
        "observedAt": counted.isoformat(),
        "threadCount": 1,
        "missingThreadCount": 0,
        "coverageScope": ["thread:scan-parent"],
        **_counts(15, 0, 6),
    }
    cost = {
        "model": "gpt-5.6-sol",
        "inputTokens": 15,
        "cachedInputTokens": 0,
        "cacheWriteInputTokens": 0,
        "outputTokens": 6,
        "estimatedUsd": 0.002,
    }
    arguments = ["--cost-json", json.dumps({"usage": runtime, "cost": cost})]
    if native_state == "unavailable-turn":
        arguments.extend(["--thread-id", "scan-parent", "--turn-id", "completion-turn"])
    completed = _complete_scan(fixture, *arguments)["scan"]
    assert completed["cost"] == cost
    usage = completed["usage"]
    if native_state == "unavailable":
        assert usage == runtime
        return
    if native_state == "unavailable-turn":
        assert usage == {
            **runtime,
            "coverage": "partial",
            "warnings": ["turn_in_progress"],
            "completion": {
                "threadId": "scan-parent",
                "turnId": "completion-turn",
                "finalized": False,
            },
        }
        return
    assert usage["totalTokens"] == 21
    assert usage["source"] == "codex_rollout"
    assert usage["byRole"] == {
        "parent": {**_counts(15, 0, 6), "threadCount": 1},
        "workers": {**_counts(0, 0, 0), "threadCount": 0},
    }
    assert datetime.fromisoformat(usage["window"]["startedAt"]) == fixture.started_at
    assert datetime.fromisoformat(usage["tokensUpdatedAt"]) == counted
    assert usage["accountRateLimits"][0]["primary"]["usedPercent"] == 6
    assert usage["coverage"] == ("complete" if native_state == "complete" else "partial")
    if native_state == "missing-worker":
        assert usage["missingThreadCount"] == 1
        assert usage["coverageScope"] == ["thread:missing-worker", "thread:scan-parent"]
        assert usage["warnings"] == ["rollout_unavailable"]
    elif native_state == "missing-turn":
        assert usage["warnings"] == ["token_record_missing"]
    else:
        assert not usage.get("warnings")


@pytest.mark.parametrize(
    "worker_state",
    ["absent", "measured", "missing_graph_child", "missing_registered_worker", "unmeasured"],
)
def test_completion_persists_direct_control_zero_without_hiding_missing_workers(
    tmp_path: Path, worker_state: str
) -> None:
    fixture = _start_scan(tmp_path, mode="deep", dedicated=True)
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


@pytest.mark.parametrize("turn_start", ["before_scan", "during_scan", "untimestamped", "post_scan"])
def test_direct_control_resumed_model_turn_requires_a_usage_receipt(
    tmp_path: Path, turn_start: str
) -> None:
    fixture = _start_scan(tmp_path, mode="deep", dedicated=True)
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
    fixture = _start_scan(tmp_path, mode="deep", dedicated=True)
    fixture.write_parent_rollout([], originator=originator)

    assert _complete_scan(fixture)["scan"]["usage"] == {
        "coverage": "unavailable",
        "source": "codex_rollout",
        "threadCount": 0,
        "warnings": ["token_record_missing", "token_usage_unavailable"],
    }


def test_budget_keeps_measured_totals_when_a_started_worker_has_no_thread(tmp_path: Path) -> None:
    fixture = _start_scan(tmp_path, mode="deep")
    counted = fixture.started_at + timedelta(microseconds=1)
    fixture.write_parent_rollout([_token_event(counted, 100, 10)])
    artifact = fixture.scan_dir / "artifacts" / "worker"
    artifact.mkdir(parents=True)
    prompt = artifact / "prompt.md"
    prompt.write_text("Review the fixture.\n", encoding="utf-8")
    upsert_deep_worker(
        fixture.state_dir,
        fixture.scan_id,
        str(uuid.uuid4()),
        "discovery",
        "running",
        str(prompt),
        str(artifact),
        "--attempt",
        "1",
        environment=fixture.environment,
    )
    usage = fixture.command("read-scan-usage", "--thread-id", "scan-parent")
    assert usage["coverage"] == "partial"
    assert usage["totalTokens"] == 110
    assert "worker_thread_unavailable" in usage["warnings"]


@pytest.mark.parametrize("resume", [False, True])
def test_budget_distinguishes_fresh_retry_from_resumed_worker(tmp_path: Path, resume: bool) -> None:
    fixture = _start_scan(tmp_path, mode="deep")
    counted = fixture.started_at + timedelta(microseconds=1)
    worker = str(uuid.uuid4())
    artifact = fixture.scan_dir / "artifacts" / "worker"
    artifact.mkdir(parents=True)
    prompt = artifact / "prompt.md"
    prompt.write_text("Review the fixture.", encoding="utf-8")
    parent = _rollout(tmp_path, "scan-parent", [_token_event(counted, 10, 0)])
    earlier = _rollout(tmp_path, "earlier", [_token_event(counted, 100, 0)])
    later = _rollout(tmp_path, "later", [_token_event(counted, 5, 0)])
    _state_graph(
        fixture.environment, {"scan-parent": parent, "earlier": earlier, "later": later}, []
    )
    with sqlite3.connect(Path(fixture.environment["CODEX_SQLITE_HOME"]) / "state_5.sqlite") as db:
        db.execute(
            "UPDATE threads SET cwd = ?, created_at = ? WHERE id = 'earlier'",
            (str(artifact), int(counted.timestamp())),
        )

    def running(attempt: str, *thread: str) -> None:
        upsert_deep_worker(
            fixture.state_dir,
            fixture.scan_id,
            worker,
            "discovery",
            "running",
            str(prompt),
            str(artifact),
            "--attempt",
            attempt,
            *thread,
            environment=fixture.environment,
        )

    running("1", "--sdk-thread-id", "earlier")
    running("2", *(["--sdk-thread-id", "earlier"] if resume else []))
    # Repeat an update without the optional ID, as the worker runner does after an error.
    running("2")

    def assert_usage(total: int) -> None:
        usage = fixture.command("read-scan-usage", "--thread-id", "scan-parent")
        assert usage["coverage"] == ("complete" if resume else "partial")
        assert usage["totalTokens"] == total
        assert ("worker_thread_unavailable" in usage.get("warnings", [])) == (not resume)

    assert_usage(110)
    running("3", "--sdk-thread-id", "later")
    assert_usage(115)


@pytest.mark.cross_platform
@pytest.mark.parametrize("truncated", [False, True])
@pytest.mark.parametrize("indexed_archive", [False, True])
def test_budget_counts_compressed_comparison_or_reports_partial_usage(
    tmp_path: Path, truncated: bool, indexed_archive: bool
) -> None:
    try:
        from compression import zstd
    except ImportError:
        zstd = pytest.importorskip("backports.zstd")
    fixture = _start_scan(tmp_path, mode="deep")
    counted = fixture.started_at + timedelta(microseconds=1)
    parent = _rollout(tmp_path, "scan-parent", [_token_event(counted, 100, 10)])
    comparison = _rollout(tmp_path, "comparison", [_token_event(counted, 10, 5)])
    archive = comparison.with_suffix(".jsonl.zst")
    frames = zstd.compress(comparison.read_bytes()) + zstd.compress(b"")
    archive.write_bytes(frames[:-1] if truncated else frames)
    comparison.unlink()
    _state_graph(
        fixture.environment,
        {"scan-parent": parent, "comparison": archive if indexed_archive else comparison},
        [],
    )
    with sqlite3.connect(Path(fixture.environment["CODEX_SQLITE_HOME"]) / "state_5.sqlite") as db:
        db.execute(
            "UPDATE threads SET cwd = ?, created_at = ? WHERE id = 'comparison'",
            (str(fixture.scan_dir / "artifacts" / "deep_discovery"), int(counted.timestamp())),
        )
    usage = fixture.command("read-scan-usage", "--thread-id", "scan-parent")
    assert usage["coverage"] == ("partial" if truncated else "complete")
    assert usage["totalTokens"] == (110 if truncated else 125)


@pytest.mark.parametrize("missing_child", [False, True])
def test_budget_usage_includes_final_receipts_and_validation_after_completion(
    tmp_path: Path, missing_child: bool
) -> None:
    fixture = _start_scan(tmp_path)
    stored = _complete_scan(fixture)["scan"]["usage"]
    after = datetime.now(fixture.started_at.tzinfo)
    _state_graph(
        fixture.environment,
        {
            "scan-parent": _rollout(tmp_path, "scan-parent", [_token_event(after, 8, 2)]),
            "validation": _rollout(tmp_path, "validation", [_token_event(after, 40, 10)]),
            "validation-child": (
                tmp_path / "missing.jsonl"
                if missing_child
                else _rollout(
                    tmp_path,
                    "validation-child",
                    [_token_event(after, 20, 5)],
                    parent_thread_id="validation",
                )
            ),
        },
        [("validation", "validation-child")],
    )
    usage = fixture.command(
        "read-scan-usage", "--thread-id", "scan-parent", "--validation-thread-id", "validation"
    )
    assert usage["coverage"] == ("partial" if missing_child else "complete")
    assert usage["totalTokens"] == (60 if missing_child else 85)
    assert usage["byRole"]["parent"]["threadCount"] == 2
    assert fixture.command("get-scan")["scan"]["usage"] == stored


@pytest.mark.parametrize("sdk_ahead", [False, True])
def test_cli_completion_refresh_preserves_native_detail_and_sdk_subtotal(
    tmp_path: Path, sdk_ahead: bool
) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    (target / "app.py").write_text("print('fixture')\n", encoding="utf-8")
    scan_dir = tmp_path / "scan"
    scan_dir.mkdir(mode=0o700)
    environment = {
        "CODEX_HOME": str(tmp_path / "codex-home"),
        "CODEX_SQLITE_HOME": str(tmp_path / "codex-sqlite"),
        "CODEX_STATE_DB": "",
    }
    registration = run_workbench(
        state_dir,
        "register-cli-scan",
        "--repository",
        str(target),
        "--scan-dir",
        str(scan_dir),
        "--recipe-json",
        json.dumps(
            {
                "repository": str(target),
                "target": {"kind": "repository", "paths": []},
                "mode": "standard",
                "config": {},
            }
        ),
        environment=environment,
    )
    scan_id = registration["scanId"]
    thread_id = str(uuid.uuid4())
    turn_id = "completion-turn"
    scan_command(
        state_dir, "set-scan-thread", scan_id, "--thread-id", thread_id, environment=environment
    )
    counted = datetime.now().astimezone()
    parent = _rollout(
        tmp_path,
        thread_id,
        [
            _event(counted, "event_msg", {"type": "task_started", "turn_id": turn_id}),
            _token_event(counted, 15, 6),
            _allowance_event(counted, 6),
            _event(counted, "event_msg", {"type": "task_complete", "turn_id": turn_id}),
        ],
    )
    _state_graph(environment, {thread_id: parent}, [])
    write_completed_contract(scan_dir, scan_id, target, relative_path="app.py")
    arguments = ["--thread-id", thread_id, "--turn-id", turn_id]
    initial = scan_command(
        state_dir, "complete-scan", scan_id, *arguments, environment=environment
    )["scan"]["usage"]
    runtime = {
        "source": "codex_runtime",
        "coverage": "complete",
        "observedAt": datetime.now().astimezone().isoformat(),
        "threadCount": 1,
        "missingThreadCount": 0,
        "coverageScope": [f"thread:{thread_id}"],
        **_counts(40 if sdk_ahead else 15, 0, 6),
    }
    refreshed = scan_command(
        state_dir,
        "complete-scan",
        scan_id,
        "--cost-json",
        json.dumps({"usage": runtime}),
        environment=environment,
    )["scan"]["usage"]
    assert refreshed["totalTokens"] == runtime["totalTokens"]
    assert refreshed["completion"] == initial["completion"]
    assert refreshed["coverage"] == "partial"
    assert refreshed["warnings"] == ["turn_in_progress"]
    assert refreshed["accountRateLimits"] == initial["accountRateLimits"]
    if not sdk_ahead:
        for key in ("byRole", "window", "tokensUpdatedAt", "accountRateLimits"):
            assert refreshed[key] == initial[key]
    finalized = scan_command(
        state_dir, "finalize-scan-usage", scan_id, *arguments, environment=environment
    )["scan"]["usage"]
    assert finalized["totalTokens"] == runtime["totalTokens"]
    assert finalized["completion"] == {**initial["completion"], "finalized": True}
    assert finalized["coverage"] == "complete"
    assert not finalized.get("warnings")
    assert finalized["accountRateLimits"] == initial["accountRateLimits"]


def test_finalized_completion_identity_survives_unknown_usage_scope(tmp_path: Path) -> None:
    fixture = _start_scan(tmp_path)
    counted = fixture.started_at + timedelta(microseconds=1)
    turn_id = "completion-turn"
    parent = _rollout(
        tmp_path,
        "scan-parent",
        [
            _event(counted, "event_msg", {"type": "task_started", "turn_id": turn_id}),
            _token_event(counted, 15, 6),
            _event(counted, "event_msg", {"type": "task_complete", "turn_id": turn_id}),
        ],
    )
    _state_graph(fixture.environment, {"scan-parent": parent}, [])
    supplied = {
        "source": "codex_runtime",
        "coverage": "partial",
        "threadCount": 1,
        "missingThreadCount": 1,
        "warnings": ["worker_usage_unavailable"],
        "observedAt": counted.isoformat(),
        **_counts(40, 0, 6),
    }
    arguments = ["--thread-id", "scan-parent", "--turn-id", turn_id]
    _complete_scan(fixture, *arguments, "--cost-json", json.dumps({"usage": supplied}))
    finalized = scan_command(
        fixture.state_dir,
        "finalize-scan-usage",
        fixture.scan_id,
        *arguments,
        environment=fixture.environment,
    )["scan"]["usage"]
    assert finalized["totalTokens"] == 46
    assert finalized["coverage"] == "partial"
    assert finalized["missingThreadCount"] == 1
    assert "worker_usage_unavailable" in finalized["warnings"]
    assert finalized["completion"] == {
        "threadId": "scan-parent",
        "turnId": turn_id,
        "finalized": True,
    }


@pytest.mark.parametrize("native", [False, True])
@pytest.mark.parametrize("supplied_usage", [False, True])
def test_host_finalizes_exact_completion_turn_without_changing_artifacts(
    scan_usage, tmp_path: Path, native: bool, supplied_usage: bool
) -> None:
    fixture = _start_scan(tmp_path)
    counted = fixture.started_at + timedelta(microseconds=1)
    turn_id = "turn-scan-parent"
    parent = _rollout(
        tmp_path,
        "scan-parent",
        [
            _event(counted, "event_msg", {"type": "task_started", "turn_id": turn_id}),
            _response_event(counted, "scan-parent", "initial", 10, 2)
            if native
            else _token_event(counted, 10, 2),
        ],
    )
    worker = _rollout(
        tmp_path,
        "scan-worker",
        [_token_event(counted, 20, 3)],
        parent_thread_id="scan-parent",
    )
    _state_graph(
        fixture.environment,
        {"scan-parent": parent, "scan-worker": worker},
        [("scan-parent", "scan-worker")],
    )
    arguments = ["--thread-id", "scan-parent", "--turn-id", turn_id]
    if supplied_usage:
        arguments.extend(
            [
                "--cost-json",
                json.dumps(
                    {
                        "usage": {
                            "source": "codex_runtime",
                            "coverage": "complete",
                            "observedAt": counted.isoformat(),
                            "threadCount": 2,
                            "coverageScope": ["thread:scan-parent", "thread:scan-worker"],
                            **_counts(30, 0, 5),
                        }
                    }
                ),
            ]
        )
    initial = _complete_scan(fixture, *arguments)["scan"]
    completion = {"threadId": "scan-parent", "turnId": turn_id, "finalized": False}
    assert (
        initial["usage"].items()
        >= {
            "coverage": "partial",
            "source": "codex_rollout",
            **_counts(30, 0, 5),
            "threadCount": 2,
            "warnings": ["turn_in_progress"],
            "completion": completion,
        }.items()
    )
    sealed_files = {
        name: (fixture.scan_dir / name).read_bytes()
        for name in ("scan-manifest.json", "findings.json", "coverage.json", "report.md")
        if (fixture.scan_dir / name).is_file()
    }
    with sqlite3.connect(fixture.state_dir / "workbench.sqlite3") as connection:
        stopped_at = connection.execute(
            "SELECT completed_at FROM scans WHERE id = ?", (fixture.scan_id,)
        ).fetchone()[0]
    late = datetime.fromisoformat(stopped_at.replace("Z", "+00:00")) + timedelta(seconds=1)
    final_events = (
        [
            _response_event(late, "scan-parent", "final-response", 30, 4, turn_usage=(40, 6)),
            _response_event(late, "scan-parent", "compaction", 50, 5, turn_usage=(90, 11)),
        ]
        if native
        else [_token_event(late, 90, 11)]
    )
    with parent.open("a", encoding="utf-8") as output:
        output.writelines(f"{json.dumps(event)}\n" for event in final_events)
    mismatched = fixture.command(
        "finalize-scan-usage",
        "--thread-id",
        "scan-parent",
        "--turn-id",
        "another-turn",
        check=False,
    )
    assert mismatched["returncode"] != 0
    assert fixture.command("get-scan")["scan"]["usage"] == initial["usage"]
    arguments = ("--thread-id", "scan-parent", "--turn-id", turn_id)
    finalized = fixture.command("finalize-scan-usage", *arguments)["scan"]
    assert (
        finalized["usage"].items()
        >= {
            "coverage": "complete",
            "source": "codex_rollout",
            **_counts(110, 0, 14),
            "threadCount": 2,
            "completion": {**completion, "finalized": True},
        }.items()
    )
    assert datetime.fromisoformat(finalized["usage"]["tokensUpdatedAt"]) == late
    assert datetime.fromisoformat(finalized["usage"]["window"]["endedAt"]) == late
    later_events = [
        _event(late, "event_msg", {"type": "task_complete", "turn_id": turn_id}),
        _event(late, "event_msg", {"type": "task_started", "turn_id": "later-turn"}),
        _response_event(late, "scan-parent", "later-response", 900, 90, turn_id="later-turn")
        if native
        else _token_event(late, 990, 101),
    ]
    with parent.open("a", encoding="utf-8") as output:
        output.writelines(f"{json.dumps(event)}\n" for event in later_events)
    usage = _measure_rollout(
        scan_usage,
        parent,
        fixture.started_at,
        datetime.fromisoformat(stopped_at.replace("Z", "+00:00")),
        completed_turn_id=turn_id,
    )
    assert usage.tokens == _counts(90, 0, 11)
    assert usage.warnings == set()
    assert fixture.command("finalize-scan-usage", *arguments)["scan"]["usage"] == finalized["usage"]
    assert {name: (fixture.scan_dir / name).read_bytes() for name in sealed_files} == sealed_files


@pytest.mark.parametrize("turn_status", ["completed", "interrupted", "failed"])
def test_host_final_usage_preserves_missing_worker_warning(
    tmp_path: Path, turn_status: str
) -> None:
    fixture = _start_scan(tmp_path)
    counted = fixture.started_at + timedelta(microseconds=1)
    turn_id = "turn-scan-parent"
    _state_graph(
        fixture.environment,
        {
            "scan-parent": _rollout(
                tmp_path,
                "scan-parent",
                [_response_event(counted, "scan-parent", "final-response", 10, 2)],
            ),
            "scan-worker": tmp_path / "missing-worker.jsonl",
        },
        [("scan-parent", "scan-worker")],
    )
    _complete_scan(fixture, "--thread-id", "scan-parent", "--turn-id", turn_id)
    usage = fixture.command(
        "finalize-scan-usage",
        "--thread-id",
        "scan-parent",
        "--turn-id",
        turn_id,
        "--turn-status",
        turn_status,
    )["scan"]["usage"]
    assert (
        usage.items()
        >= {
            "coverage": "partial",
            "source": "codex_rollout",
            **_counts(10, 0, 2),
            "threadCount": 1,
            "missingThreadCount": 1,
            "warnings": ["rollout_unavailable"]
            + ([] if turn_status == "completed" else [f"scan_turn_{turn_status}"]),
            "completion": {"threadId": "scan-parent", "turnId": turn_id, "finalized": True},
        }.items()
    )


@pytest.mark.native_macos
def test_host_final_usage_retries_a_locked_native_database_without_losing_counts(
    tmp_path: Path,
) -> None:
    fixture = _start_scan(tmp_path)
    counted = fixture.started_at + timedelta(microseconds=1)
    parent = fixture.write_parent_rollout([_response_event(counted, "scan-parent", "first", 10, 2)])
    arguments = ("--thread-id", "scan-parent", "--turn-id", "turn-scan-parent")
    initial = _complete_scan(fixture, *arguments)["scan"]["usage"]
    with parent.open("a", encoding="utf-8") as output:
        final_response = _response_event(counted, "scan-parent", "final", 20, 3, turn_usage=(30, 5))
        output.write(f"{json.dumps(final_response)}\n")
    with sqlite3.connect(
        Path(fixture.environment["CODEX_SQLITE_HOME"]) / "state_5.sqlite"
    ) as native_database:
        native_database.execute("BEGIN EXCLUSIVE")
        pending = fixture.command("finalize-scan-usage", *arguments)["scan"]["usage"]
        assert pending == initial
        assert pending["totalTokens"] == 12
        assert pending["completion"]["finalized"] is False

    finalized = fixture.command("finalize-scan-usage", *arguments)["scan"]["usage"]
    assert (
        finalized.items()
        >= {
            "coverage": "complete",
            "source": "codex_rollout",
            **_counts(30, 0, 5),
            "threadCount": 1,
            "completion": {**initial["completion"], "finalized": True},
        }.items()
    )


def test_host_final_usage_recovers_initially_unavailable_records(tmp_path: Path) -> None:
    fixture = _start_scan(tmp_path)
    arguments = ("--thread-id", "scan-parent", "--turn-id", "turn-scan-parent")
    initial = _complete_scan(fixture, *arguments)["scan"]["usage"]
    assert initial["coverage"] == "unavailable"
    assert initial["completion"]["finalized"] is False
    assert fixture.command("finalize-scan-usage", *arguments)["scan"]["usage"] == initial
    fixture.write_parent_rollout(
        [_response_event(fixture.started_at, "scan-parent", "final-response", 10, 2)]
    )
    finalized = fixture.command("finalize-scan-usage", *arguments)["scan"]["usage"]
    assert finalized["coverage"] == "complete"
    assert finalized["totalTokens"] == 12
    assert finalized["completion"]["finalized"] is True


def test_host_final_usage_does_not_invent_an_unrecorded_completion_turn(tmp_path: Path) -> None:
    fixture = _start_scan(tmp_path)
    arguments = ("--thread-id", "scan-parent", "--turn-id", "unrecorded-turn")
    fixture.write_parent_rollout(
        [
            _response_event(fixture.started_at, "scan-parent", "earlier-response", 10, 2),
            _event(fixture.started_at, "event_msg", {"type": "task_complete"}),
        ]
    )
    _complete_scan(fixture, *arguments)
    finalized = fixture.command("finalize-scan-usage", *arguments)["scan"]["usage"]
    assert finalized["coverage"] == "partial"
    assert finalized["totalTokens"] == 12
    assert finalized["warnings"] == ["completion_turn_unavailable"]
    assert finalized["completion"]["finalized"] is True


@pytest.mark.parametrize("outcome", ["failed", "canceled"])
def test_stopped_scan_retains_measured_usage(tmp_path: Path, outcome: str) -> None:
    fixture = _start_scan(tmp_path)
    counted = fixture.started_at + timedelta(microseconds=1)
    fixture.write_parent_rollout([_token_event(counted, 21, 8)])
    if outcome == "failed":
        fail_scan(
            fixture.state_dir, fixture.scan_id, "Fixture failure.", environment=fixture.environment
        )
    else:
        cancel_scan(
            fixture.state_dir, fixture.scan_id, "scan-parent", environment=fixture.environment
        )
    stopped = fixture.command("get-scan")["scan"]
    assert stopped["progress"]["status"] == outcome
    assert stopped["usage"]["totalTokens"] == 29
    assert stopped["usage"]["coverage"] == "complete"
    assert "cost" not in stopped


def test_failed_scan_reconciles_runtime_subtotals_without_double_counting(tmp_path: Path) -> None:
    fixture = _start_scan(tmp_path)
    runtime = {
        "coverage": "partial",
        "coverageScope": ["thread:scan-parent"],
        "source": "codex_runtime",
        "threadCount": 1,
        "missingThreadCount": 1,
        "cacheWriteInputTokensReported": False,
        **_counts(40, 0, 5),
    }
    cost = {
        "model": "fixture-model",
        "inputTokens": 40,
        "cachedInputTokens": 0,
        "cacheWriteInputTokens": 0,
        "outputTokens": 5,
        "estimatedUsd": 0.01,
    }
    for _ in range(2):
        failed = fail_scan(
            fixture.state_dir,
            fixture.scan_id,
            "Fixture failure.",
            "--cost-json",
            json.dumps({"usage": runtime, "cost": cost}),
            environment=fixture.environment,
        )["scan"]
        assert failed["usage"] == runtime
        assert failed["cost"] == cost

    counted = fixture.started_at + timedelta(microseconds=1)
    _state_graph(
        fixture.environment,
        {"scan-parent": _rollout(tmp_path, "scan-parent", [_token_event(counted, 50, 8)])},
        [],
    )
    # A terminal retry can reconcile records flushed after the original stop.
    reconciled = fail_scan(
        fixture.state_dir,
        fixture.scan_id,
        "Do not replace failure.",
        environment=fixture.environment,
    )["scan"]
    assert reconciled["usage"]["totalTokens"] == 58
    assert reconciled["usage"]["source"] == "codex_rollout"
    assert reconciled["usage"]["coverage"] == "complete"
    assert reconciled["usage"]["warnings"] == ["cost_estimate_covers_earlier_usage"]
    assert reconciled["cost"] == cost
    assert reconciled["failureMessage"] == "Fixture failure."
    assert reconciled["progress"] == failed["progress"]
    refreshed_cost = {**cost, "inputTokens": 50, "outputTokens": 8, "estimatedUsd": 0.02}
    reconciled = fail_scan(
        fixture.state_dir,
        fixture.scan_id,
        "Do not replace failure.",
        "--cost-json",
        json.dumps(refreshed_cost),
        environment=fixture.environment,
    )["scan"]
    assert reconciled["cost"] == refreshed_cost
    assert reconciled["usage"]["coverage"] == "complete"
    assert "cost_estimate_covers_earlier_usage" not in reconciled["usage"].get("warnings", [])


def test_scan_accounting_failure_does_not_replace_stopped_outcome(
    tmp_path: Path, workbench_api, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    fixture = _start_scan(tmp_path)
    context = workbench_api["_WORKBENCH_DB_CONTEXT"]

    def unavailable(*args, **kwargs):
        raise OSError("Synthetic accounting storage failure.")

    monkeypatch.setattr(context.scan_usage, "collect_scan_usage", unavailable)
    with sqlite3.connect(fixture.state_dir / "workbench.sqlite3") as connection:
        connection.row_factory = sqlite3.Row
        failed = context.saved_results.fail_scan_locked(
            context,
            connection,
            SimpleNamespace(
                scan_id=fixture.scan_id,
                message="Original scan failure.",
                claim_token=None,
                cost_json=None,
            ),
        )["scan"]
    assert failed["progress"]["status"] == "failed"
    assert failed["failureMessage"] == "Original scan failure."
    assert failed["usage"]["coverage"] == "unavailable"
    assert failed["usage"]["warnings"] == ["usage_collection_failed"]
    assert "Synthetic accounting storage failure." in capsys.readouterr().err


@pytest.mark.parametrize("runtime_ahead", [False, True])
def test_late_missing_worker_invalidates_saved_complete_coverage(
    tmp_path: Path, runtime_ahead: bool
) -> None:
    fixture = _start_scan(tmp_path)
    counted = fixture.started_at + timedelta(microseconds=1)
    parent = _rollout(tmp_path, "scan-parent", [_token_event(counted, 21, 8)])
    _state_graph(fixture.environment, {"scan-parent": parent}, [])
    arguments = (
        (
            "--cost-json",
            json.dumps(
                {
                    "usage": {
                        "coverage": "complete",
                        "coverageScope": ["thread:scan-parent"],
                        "source": "codex_runtime",
                        "threadCount": 1,
                        "observedAt": counted.isoformat(),
                        "tokensUpdatedAt": counted.isoformat(),
                        **_counts(37, 0, 8),
                    }
                }
            ),
        )
        if runtime_ahead
        else ()
    )
    complete = fail_scan(
        fixture.state_dir,
        fixture.scan_id,
        "Fixture failure.",
        *arguments,
        environment=fixture.environment,
    )["scan"]["usage"]
    assert complete["coverage"] == "complete"
    with sqlite3.connect(
        Path(fixture.environment["CODEX_SQLITE_HOME"]) / "state_5.sqlite"
    ) as connection:
        connection.execute(
            "INSERT INTO thread_spawn_edges (parent_thread_id, child_thread_id) VALUES (?, ?)",
            ("scan-parent", "late-worker"),
        )
    partial = fail_scan(
        fixture.state_dir, fixture.scan_id, "Fixture failure.", environment=fixture.environment
    )["scan"]["usage"]
    assert partial["totalTokens"] == complete["totalTokens"] == (45 if runtime_ahead else 29)
    assert partial["coverage"] == "partial"
    assert partial["missingThreadCount"] == 1
    assert partial["coverageScope"] == ["thread:late-worker", "thread:scan-parent"]
    assert partial["observedAt"] > complete["observedAt"]
    assert partial["tokensUpdatedAt"] == complete["tokensUpdatedAt"]

    # A delayed complete snapshot and vanished logs cannot erase the newer gap
    # or make the retained observation appear fresh.
    parent.unlink()
    replayed = fail_scan(
        fixture.state_dir,
        fixture.scan_id,
        "Fixture failure.",
        "--cost-json",
        json.dumps({"usage": complete}),
        environment=fixture.environment,
    )["scan"]["usage"]
    assert replayed == partial

    _rollout(tmp_path, "scan-parent", [_token_event(counted, 21, 8)])
    worker = _rollout(
        tmp_path,
        "late-worker",
        [_token_event(counted, 0, 0)],
        parent_thread_id="scan-parent",
    )
    with sqlite3.connect(
        Path(fixture.environment["CODEX_SQLITE_HOME"]) / "state_5.sqlite"
    ) as connection:
        connection.execute(
            "INSERT INTO threads (id, rollout_path) VALUES (?, ?)", ("late-worker", str(worker))
        )
    resolved = fail_scan(
        fixture.state_dir, fixture.scan_id, "Fixture failure.", environment=fixture.environment
    )["scan"]["usage"]
    assert resolved["totalTokens"] == partial["totalTokens"]
    assert resolved["coverage"] == "complete"
    assert resolved["threadCount"] == 2
    if runtime_ahead:
        assert "byRole" not in resolved
    else:
        assert resolved["byRole"]["parent"]["threadCount"] == 1
        assert resolved["byRole"]["workers"]["threadCount"] == 1
    assert resolved.get("missingThreadCount", 0) == 0
    assert not resolved.get("warnings")
    assert resolved["observedAt"] > partial["observedAt"]

    parent.unlink()
    worker.unlink()
    replayed = fail_scan(
        fixture.state_dir,
        fixture.scan_id,
        "Fixture failure.",
        "--cost-json",
        json.dumps({"usage": partial}),
        environment=fixture.environment,
    )["scan"]["usage"]
    assert replayed == resolved


def test_narrower_observations_preserve_other_thread_gaps(tmp_path: Path) -> None:
    fixture = _start_scan(tmp_path)
    counted = fixture.started_at + timedelta(microseconds=1)
    parent = _rollout(tmp_path, "scan-parent", [_token_event(counted, 21, 8)])
    _state_graph(fixture.environment, {"scan-parent": parent}, [])
    runtime = {
        "coverage": "partial",
        "coverageScope": ["thread:scan-parent", "thread:validation", "thread:validation-child"],
        "source": "codex_runtime",
        "threadCount": 2,
        "missingThreadCount": 1,
        "observedAt": counted.isoformat(),
        **_counts(37, 0, 8),
    }
    partial = fail_scan(
        fixture.state_dir,
        fixture.scan_id,
        "Fixture failure.",
        "--cost-json",
        json.dumps({"usage": runtime}),
        environment=fixture.environment,
    )["scan"]["usage"]
    assert partial["coverage"] == "partial"
    assert partial["totalTokens"] == 45
    assert partial["missingThreadCount"] == 1
    assert partial["coverageScope"] == runtime["coverageScope"]
    with sqlite3.connect(
        Path(fixture.environment["CODEX_SQLITE_HOME"]) / "state_5.sqlite"
    ) as connection:
        connection.execute(
            "INSERT INTO thread_spawn_edges (parent_thread_id, child_thread_id) VALUES (?, ?)",
            ("scan-parent", "late-worker"),
        )
    narrower_partial = fail_scan(
        fixture.state_dir, fixture.scan_id, "Fixture failure.", environment=fixture.environment
    )["scan"]["usage"]
    assert narrower_partial["coverage"] == "partial"
    assert narrower_partial["coverageScope"] == [
        "thread:late-worker",
        *runtime["coverageScope"],
    ]
    worker = _rollout(
        tmp_path,
        "late-worker",
        [_token_event(counted, 0, 0)],
        parent_thread_id="scan-parent",
    )
    with sqlite3.connect(
        Path(fixture.environment["CODEX_SQLITE_HOME"]) / "state_5.sqlite"
    ) as connection:
        connection.execute(
            "INSERT INTO threads (id, rollout_path) VALUES (?, ?)", ("late-worker", str(worker))
        )
    narrower_complete = fail_scan(
        fixture.state_dir, fixture.scan_id, "Fixture failure.", environment=fixture.environment
    )["scan"]["usage"]
    assert narrower_complete["coverage"] == "partial"
    assert narrower_complete["coverageScope"] == narrower_partial["coverageScope"]
    assert narrower_complete["totalTokens"] == 45

    # Complete evidence must include every retained branch before it can clear
    # the gap, even when its native subtotal is behind the SDK receipt.
    for thread in ["validation", "validation-child"]:
        path = _rollout(
            tmp_path,
            thread,
            [_token_event(counted, 0, 0)],
            parent_thread_id="scan-parent" if thread == "validation" else "validation",
        )
        with sqlite3.connect(
            Path(fixture.environment["CODEX_SQLITE_HOME"]) / "state_5.sqlite"
        ) as connection:
            connection.execute(
                "INSERT INTO threads (id, rollout_path) VALUES (?, ?)", (thread, str(path))
            )
            connection.execute(
                "INSERT INTO thread_spawn_edges (parent_thread_id, child_thread_id) VALUES (?, ?)",
                ("scan-parent" if thread == "validation" else "validation", thread),
            )
    complete = fail_scan(
        fixture.state_dir, fixture.scan_id, "Fixture failure.", environment=fixture.environment
    )["scan"]["usage"]
    assert complete["coverage"] == "complete"
    assert complete["totalTokens"] == 45
    assert complete["threadCount"] == 4
    assert "byRole" not in complete
    assert complete["coverageScope"] == narrower_partial["coverageScope"]
    assert not complete.get("missingThreadCount")
    assert not complete.get("warnings")
    parent.unlink()
    worker.unlink()
    # Entirely unavailable fresh reads and stale partial payloads cannot
    # resurrect a gap covered by the newer encompassing observation.
    replayed = fail_scan(
        fixture.state_dir,
        fixture.scan_id,
        "Fixture failure.",
        "--cost-json",
        json.dumps({"usage": narrower_partial}),
        environment=fixture.environment,
    )["scan"]["usage"]
    assert replayed == complete


def test_stopped_scan_preserves_incomparable_scope_uncertainty(tmp_path: Path) -> None:
    fixture = _start_scan(tmp_path)
    counted = fixture.started_at + timedelta(microseconds=1)
    _state_graph(
        fixture.environment,
        {
            "scan-parent": _rollout(tmp_path, "scan-parent", [_token_event(counted, 800, 0)]),
            "late-worker": _rollout(
                tmp_path,
                "late-worker",
                [_token_event(counted, 400, 0)],
                parent_thread_id="scan-parent",
            ),
        },
        [("scan-parent", "late-worker")],
    )
    # SDK usage includes 800 parent + 200 independent validation tokens, while
    # native collection sees 800 parent + 400 late-worker tokens. Neither
    # aggregate measures the full 1,400-token execution.
    runtime = {
        "coverage": "complete",
        "coverageScope": ["thread:scan-parent", "thread:validation"],
        "source": "codex_runtime",
        "threadCount": 2,
        "observedAt": counted.isoformat(),
        **_counts(1_000, 0, 0),
    }
    cost = {
        "model": "fixture-model",
        "inputTokens": 1_000,
        "cachedInputTokens": 0,
        "cacheWriteInputTokens": 0,
        "outputTokens": 0,
        "estimatedUsd": 0.01,
    }
    stopped = fail_scan(
        fixture.state_dir,
        fixture.scan_id,
        "Fixture failure.",
        "--cost-json",
        json.dumps({"usage": runtime, "cost": cost}),
        environment=fixture.environment,
    )["scan"]
    usage = stopped["usage"]
    assert usage["totalTokens"] == 1_200
    assert usage["coverage"] == "partial"
    assert usage["coverageScope"] == [
        "thread:late-worker",
        "thread:scan-parent",
        "thread:validation",
    ]
    assert usage["warnings"] == [
        "cost_estimate_covers_earlier_usage",
        "usage_scope_incomplete",
    ]
    assert (
        scan_command(
            fixture.state_dir, "get-scan", fixture.scan_id, environment=fixture.environment
        )["scan"]["usage"]
        == usage
    )
    # Refreshing the price of this lower bound must not restore complete usage.
    repriced = fail_scan(
        fixture.state_dir,
        fixture.scan_id,
        "Fixture failure.",
        "--cost-json",
        json.dumps({**cost, "inputTokens": 1_200, "estimatedUsd": 0.012}),
        environment=fixture.environment,
    )["scan"]["usage"]
    assert repriced["totalTokens"] == 1_200
    assert repriced["coverage"] == "partial"
    assert repriced["warnings"] == ["usage_scope_incomplete"]


def test_large_measured_scope_survives_saved_scan_round_trip(tmp_path: Path) -> None:
    fixture = _start_scan(tmp_path)
    runtime = {
        "coverage": "partial",
        "coverageScope": [f"thread:{uuid.UUID(int=index)}" for index in range(1, 401)],
        "source": "codex_runtime",
        "threadCount": 399,
        "missingThreadCount": 1,
        **_counts(400, 0, 5),
    }
    encoded = json.dumps({"usage": runtime})
    assert len(encoded.encode("utf-8")) > 8192
    stopped = fail_scan(
        fixture.state_dir,
        fixture.scan_id,
        "Fixture failure.",
        "--cost-json",
        encoded,
        environment=fixture.environment,
    )["scan"]["usage"]
    assert stopped == runtime
    assert (
        scan_command(
            fixture.state_dir, "get-scan", fixture.scan_id, environment=fixture.environment
        )["scan"]["usage"]
        == runtime
    )


def test_completed_scan_reconciles_late_runtime_usage_envelopes(
    tmp_path: Path, workbench_api: dict[str, Any]
) -> None:
    fixture = _start_scan(tmp_path)
    counted = fixture.started_at + timedelta(microseconds=1)
    _state_graph(
        fixture.environment,
        {"scan-parent": _rollout(tmp_path, "scan-parent", [_token_event(counted, 21, 8)])},
        [],
    )
    _complete_scan(fixture)
    runtime = {
        "coverage": "complete",
        "source": "codex_runtime",
        "threadCount": 1,
        **_counts(40, 0, 5),
    }
    for _ in range(2):
        with sqlite3.connect(fixture.state_dir / "workbench.sqlite3") as connection:
            connection.row_factory = sqlite3.Row
            context = workbench_api["_WORKBENCH_DB_CONTEXT"]
            scan = context.require_scan(connection, fixture.scan_id)
            context.scan_usage.reconcile_completed_scan_cost(
                connection, scan, json.dumps({"usage": runtime})
            )
        reconciled = scan_command(
            fixture.state_dir,
            "get-scan",
            fixture.scan_id,
            environment=fixture.environment,
        )["scan"]
        assert reconciled["usage"] == {
            **runtime,
            "coverageScope": ["thread:scan-parent"],
        }
        assert "cost" not in reconciled


@pytest.mark.parametrize("mode", ["standard", "deep"])
def test_model_artifact_worker_receipts_do_not_affect_saved_usage(
    tmp_path: Path, mode: str
) -> None:
    fixture = _start_scan(tmp_path, mode=mode)
    counted = fixture.started_at + timedelta(microseconds=1)
    directory = fixture.scan_dir / "artifacts" / "deep_discovery" / "usage"
    directory.mkdir(parents=True)
    for thread_id in ["scan-parent", "unrelated-worker"]:
        attempt_id = str(uuid.uuid4())
        (directory / f"{attempt_id}.json").write_text(
            json.dumps(
                {
                    "schemaVersion": 1,
                    "source": "codex_sdk",
                    "usageScope": "thread_cumulative",
                    "scanId": fixture.scan_id,
                    "kind": "discovery",
                    "attemptId": attempt_id,
                    "threadId": thread_id,
                    "startedAt": counted.isoformat(),
                    "observedAt": counted.isoformat(),
                    "usage": _token_event(counted, 1_000_000, 0)["payload"]["info"][
                        "total_token_usage"
                    ],
                }
            ),
            encoding="utf-8",
        )
    _state_graph(
        fixture.environment,
        {
            "scan-parent": _rollout(tmp_path, "scan-parent", [_token_event(counted, 10, 2)]),
            "unrelated-worker": _rollout(
                tmp_path, "unrelated-worker", [_token_event(counted, 1_000_000, 0)]
            ),
        },
        [],
    )
    measurement = fail_scan(
        fixture.state_dir, fixture.scan_id, "Fixture failure.", environment=fixture.environment
    )["scan"]["usage"]
    assert measurement["coverage"] == "complete"
    assert measurement["totalTokens"] == 12
    assert measurement["threadCount"] == 1
    assert measurement["coverageScope"] == ["thread:scan-parent"]


def test_deep_worker_receipt_storage_is_isolated_between_scans(tmp_path: Path) -> None:
    fixture = _start_scan(tmp_path, mode="deep")
    counted = fixture.started_at + timedelta(microseconds=1)
    directory = _worker_usage_directory(fixture)
    directory.mkdir(parents=True)
    another_scan = str(uuid.uuid4())
    unrelated_directory = directory.parent / another_scan
    unrelated_directory.mkdir()
    attempt_id = str(uuid.uuid4())
    receipt = {
        "schemaVersion": 1,
        "source": "codex_sdk",
        "usageScope": "thread_cumulative",
        "scanId": another_scan,
        "kind": "discovery",
        "attemptId": attempt_id,
        "threadId": "unrelated-worker",
        "startedAt": counted.isoformat(),
        "observedAt": counted.isoformat(),
        "usage": _token_event(counted, 1_000_000, 0)["payload"]["info"]["total_token_usage"],
    }
    (unrelated_directory / f"{attempt_id}.json").write_text(json.dumps(receipt), encoding="utf-8")
    _state_graph(
        fixture.environment,
        {"scan-parent": _rollout(tmp_path, "scan-parent", [_token_event(counted, 10, 2)])},
        [],
    )
    measurement = fail_scan(
        fixture.state_dir, fixture.scan_id, "Fixture failure.", environment=fixture.environment
    )["scan"]["usage"]
    assert measurement["coverage"] == "complete"
    assert measurement["totalTokens"] == 12
    assert measurement["coverageScope"] == ["thread:scan-parent"]
    # A misplaced host receipt also cannot attribute another scan's usage here.
    (directory / f"{attempt_id}.json").write_text(json.dumps(receipt), encoding="utf-8")
    measurement = fail_scan(
        fixture.state_dir, fixture.scan_id, "Fixture failure.", environment=fixture.environment
    )["scan"]["usage"]
    assert measurement["totalTokens"] == 12
    assert "thread:unrelated-worker" not in measurement["coverageScope"]


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


def test_cancel_scan_retains_runtime_usage_on_repeated_cancellation(tmp_path: Path) -> None:
    fixture = _start_scan(tmp_path)
    cost = {
        "model": "fixture-model",
        "inputTokens": 40,
        "cachedInputTokens": 0,
        "cacheWriteInputTokens": 0,
        "outputTokens": 5,
        "estimatedUsd": 0.01,
    }
    with sqlite3.connect(fixture.state_dir / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE scans SET cost_json = ? WHERE id = ?", (json.dumps(cost), fixture.scan_id)
        )
    runtime = {
        "coverage": "complete",
        "source": "codex_runtime",
        "threadCount": 1,
        **_counts(40, 0, 5),
    }
    for _ in range(2):
        scan_command(
            fixture.state_dir,
            "cancel-scan",
            fixture.scan_id,
            "--cost-json",
            json.dumps({"usage": runtime}),
            environment=fixture.environment,
        )
        saved = scan_command(
            fixture.state_dir, "get-scan", fixture.scan_id, environment=fixture.environment
        )["scan"]
        assert saved["progress"]["status"] == "canceled"
        assert saved["usage"] == runtime
        assert saved["cost"] == cost
