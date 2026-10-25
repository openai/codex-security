from __future__ import annotations

import json
import runpy
import sqlite3
import sys
import tempfile
import uuid
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from workbench_test_support import (
    begin_deep_scan,
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


@dataclass(frozen=True)
class ScanFixture:
    state_dir: Path
    target: Path
    scan_id: str
    scan_dir: Path
    started_at: datetime
    environment: dict[str, str]
    mode: str = "standard"
    diff_target: dict[str, Any] | None = None


def _start_scan(tmp_path: Path, *, mode: str = "standard") -> ScanFixture:
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

    started = start_delivered_scan(
        state_dir,
        "--workspace-id",
        workspace_id,
        "--scan-root",
        str(tmp_path / "scans"),
        environment=environment,
    )["results"]
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
    records: list[dict[str, Any]] = [
        {
            "type": "session_meta",
            "payload": {"id": recorded_thread_id or thread_id, "source": source},
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
            "payload": {"type": "task_started", "turn_id": f"turn-{thread_id}"},
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


def _counts(
    input_tokens: int,
    cached_input_tokens: int,
    output_tokens: int,
    *,
    cache_write_input_tokens: int = 0,
) -> dict[str, int]:
    return {
        "inputTokens": input_tokens,
        "cachedInputTokens": cached_input_tokens,
        "cacheWriteInputTokens": cache_write_input_tokens,
        "outputTokens": output_tokens,
        "reasoningOutputTokens": 0,
        "totalTokens": input_tokens + output_tokens,
    }


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
    return scan_command(
        fixture.state_dir,
        "complete-scan",
        fixture.scan_id,
        *arguments,
        environment=fixture.environment,
    )


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
    parent = _rollout(tmp_path, "scan-parent", [event, _token_event(counted, 20, 10)])
    _state_graph(fixture.environment, {"scan-parent": parent}, [])

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
    parent = _rollout(
        tmp_path,
        "scan-parent",
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
        ],
    )
    _state_graph(fixture.environment, {"scan-parent": parent}, [])

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
    tmp_path: Path, scope: str, native: bool, expected_warning: bool
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
    helper = runpy.run_path(
        str(Path(__file__).resolve().parents[1] / "scripts/workbench_scan_usage.py")
    )

    measurement = helper["_read_rollout_usage"](
        helper["RolloutSession"]("scan-parent", None, parent),
        started_at=started,
        completed_at=completed,
        completed_turn_id="turn-scan-parent" if scope == "completion_turn" else None,
    )
    usage = measurement.tokens
    warnings = measurement.warnings

    assert usage == _counts(10, 0, 1)
    assert warnings == ({"compaction_usage_unavailable"} if expected_warning else set())


def test_legacy_compaction_warning_survives_a_later_native_turn(tmp_path: Path) -> None:
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
    helper = runpy.run_path(
        str(Path(__file__).resolve().parents[1] / "scripts/workbench_scan_usage.py")
    )

    measurement = helper["_read_rollout_usage"](
        helper["RolloutSession"]("scan-parent", None, parent),
        started_at=started,
        completed_at=started,
    )
    usage = measurement.tokens
    warnings = measurement.warnings

    assert usage == _counts(30, 0, 3)
    assert warnings == {"compaction_usage_unavailable"}


def test_native_usage_respects_scan_window_and_preserves_cache_details(tmp_path: Path) -> None:
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
    helper = runpy.run_path(
        str(Path(__file__).resolve().parents[1] / "scripts/workbench_scan_usage.py")
    )

    measurement = helper["_read_rollout_usage"](
        helper["RolloutSession"]("scan-parent", None, parent),
        started_at=started,
        completed_at=completed,
    )
    usage = measurement.tokens
    warnings = measurement.warnings

    assert usage == _counts(20, 3, 2, cache_write_input_tokens=4)
    assert warnings == set()


def test_native_worker_usage_excludes_inherited_totals_and_survives_resume(tmp_path: Path) -> None:
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
    helper = runpy.run_path(
        str(Path(__file__).resolve().parents[1] / "scripts/workbench_scan_usage.py")
    )

    measurement = helper["_read_rollout_usage"](
        helper["RolloutSession"]("scan-worker", "scan-parent", worker),
        started_at=started,
        completed_at=started,
    )
    usage = measurement.tokens
    warnings = measurement.warnings

    assert usage == _counts(60, 0, 6)
    assert warnings == set()


@pytest.mark.parametrize("gap", ["before", "after", "inside"])
def test_native_usage_only_marks_receipt_gaps_inside_scan_window(tmp_path: Path, gap: str) -> None:
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
    helper = runpy.run_path(
        str(Path(__file__).resolve().parents[1] / "scripts/workbench_scan_usage.py")
    )

    measurement = helper["_read_rollout_usage"](
        helper["RolloutSession"]("scan-parent", None, parent),
        started_at=started,
        completed_at=started,
    )
    usage = measurement.tokens
    warnings = measurement.warnings

    assert usage == _counts(30, 0, 0)
    assert warnings == ({"token_record_incomplete"} if gap == "inside" else set())


def test_native_usage_continues_cumulative_baseline_when_recovering_same_turn(
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
    helper = runpy.run_path(
        str(Path(__file__).resolve().parents[1] / "scripts/workbench_scan_usage.py")
    )

    measurement = helper["_read_rollout_usage"](
        helper["RolloutSession"]("scan-parent", None, parent),
        started_at=started,
        completed_at=started,
    )
    usage = measurement.tokens
    warnings = measurement.warnings

    assert usage == _counts(30, 0, 3)
    assert warnings == set()


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
def test_native_usage_preserves_partial_measurement_warnings(tmp_path: Path, failure: str) -> None:
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
    helper = runpy.run_path(
        str(Path(__file__).resolve().parents[1] / "scripts/workbench_scan_usage.py")
    )

    measurement = helper["_read_rollout_usage"](
        helper["RolloutSession"]("scan-parent", None, parent),
        started_at=started,
        completed_at=started,
    )
    usage = measurement.tokens
    warnings = measurement.warnings

    assert usage == (_counts(20, 0, 2) if failure == "missing_receipt" else _counts(10, 0, 1))
    assert warnings == {
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
    cache_write_field: str,
) -> None:
    helper = Path(__file__).resolve().parents[1] / "scripts" / "workbench_scan_usage.py"
    snapshot = runpy.run_path(str(helper))["_token_snapshot"]
    usage = {
        "input_tokens": 120,
        "cached_input_tokens": 30,
        cache_write_field: 12,
        "output_tokens": 15,
        "reasoning_output_tokens": 0,
        "total_tokens": 135,
    }

    assert snapshot({"info": {"total_token_usage": usage}}) == _counts(
        120, 30, 15, cache_write_input_tokens=12
    )


@pytest.mark.parametrize(
    ("canonical", "legacy", "expected"),
    [(0, 12, 12), (0, 0, 0), (5, 12, 5), (False, 12, None), (0.0, 12, None)],
)
def test_scan_usage_helper_requires_integer_cache_write_placeholder(
    canonical: object, legacy: int, expected: int | None
) -> None:
    helper = runpy.run_path(
        str(Path(__file__).resolve().parents[1] / "scripts/workbench_scan_usage.py")
    )
    usage = {
        "input_tokens": 120,
        "cached_input_tokens": 30,
        "cache_write_input_tokens": canonical,
        "cache_write_tokens": legacy,
        "output_tokens": 15,
        "total_tokens": 135,
    }

    assert helper["_usage_counts"](usage) == (
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
def test_scan_usage_timestamp_handles_utc_boundaries(value: str, expected: str | None) -> None:
    helper = runpy.run_path(
        str(Path(__file__).resolve().parents[1] / "scripts/workbench_scan_usage.py")
    )
    assert helper["_timestamp"](value) == (
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


@pytest.mark.parametrize("coverage", [[], {}])
def test_scan_cost_preserves_diagnostics_for_non_scalar_coverage(workbench_api, coverage) -> None:
    value = {"usage": {"coverage": coverage, "source": "codex_rollout", "threadCount": 0}}
    with pytest.raises(SystemExit) as error:
        workbench_api["parse_scan_cost"](json.dumps(value))
    assert str(error.value) == "Scan cost includes invalid measured token usage."


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
    parent = _rollout(tmp_path, "scan-parent", [event])
    _state_graph(fixture.environment, {"scan-parent": parent}, [])

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
    workbench_api,
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

    assert workbench_api["scan_usage"]._codex_state_database() == database.resolve()


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
    _state_graph(
        fixture.environment,
        {"scan-parent": _rollout(tmp_path, "scan-parent", events)},
        [],
    )

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


@pytest.mark.parametrize("owner_first", [True, False])
def test_usage_counts_registered_worker_when_its_parent_rollout_is_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, owner_first: bool
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
    helper = Path(__file__).resolve().parents[1] / "scripts" / "workbench_scan_usage.py"
    collect_usage = runpy.run_path(str(helper))["collect_scan_usage"]
    with sqlite3.connect(fixture.state_dir / "workbench.sqlite3") as connection:
        connection.row_factory = sqlite3.Row
        connection.execute(
            "UPDATE scans SET continuation_thread_id = ? WHERE id = ?",
            ("registered-worker", fixture.scan_id),
        )
        scan = connection.execute("SELECT * FROM scans WHERE id = ?", (fixture.scan_id,)).fetchone()
        usage = collect_usage(
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
def test_completion_preserves_explicit_legacy_cost(
    tmp_path: Path, delayed_cache_counts: bool
) -> None:
    fixture = _start_scan(tmp_path)
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
    write_completed_contract(
        fixture.scan_dir, fixture.scan_id, fixture.target, relative_path="app.py"
    )
    completed = scan_command(
        fixture.state_dir,
        "complete-scan",
        fixture.scan_id,
        "--cost-json",
        json.dumps(cost),
        environment=fixture.environment,
    )["scan"]
    assert completed["cost"] == cost
    assert completed["usage"]["accountRateLimits"][0]["primary"]["usedPercent"] == 6
    if delayed_cache_counts:
        assert completed["usage"]["coverage"] == "unavailable"
        assert completed["usage"]["warnings"] == ["token_breakdown_unavailable"]
        assert "totalTokens" not in completed["usage"]
    else:
        assert completed["usage"]["totalTokens"] == 21


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
    repeated = scan_command(
        fixture.state_dir, "complete-scan", fixture.scan_id, environment=fixture.environment
    )["scan"]
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
    _state_graph(
        fixture.environment,
        {"scan-parent": _rollout(tmp_path, "scan-parent", [], originator=originator)},
        [],
    )

    assert _complete_scan(fixture)["scan"]["usage"] == {
        "coverage": "unavailable",
        "source": "codex_rollout",
        "threadCount": 0,
        "warnings": ["token_record_missing", "token_usage_unavailable"],
    }


def test_usage_has_no_separate_workbench_command(workbench_api, monkeypatch, capsys) -> None:
    monkeypatch.setattr(sys, "argv", ["workbench_db.py", "get-scan-usage"])
    with pytest.raises(SystemExit) as rejected:
        workbench_api["parse_args"]("workbench")
    assert rejected.value.code == 2
    assert "invalid choice: 'get-scan-usage'" in capsys.readouterr().err


@pytest.mark.parametrize("native", [False, True])
def test_host_finalizes_exact_completion_turn_without_changing_artifacts(
    tmp_path: Path, native: bool
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
    initial = _complete_scan(fixture, "--thread-id", "scan-parent", "--turn-id", turn_id)["scan"]
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
    mismatched = scan_command(
        fixture.state_dir,
        "finalize-scan-usage",
        fixture.scan_id,
        "--thread-id",
        "scan-parent",
        "--turn-id",
        "another-turn",
        environment=fixture.environment,
        check=False,
    )
    assert mismatched["returncode"] != 0
    assert (
        scan_command(
            fixture.state_dir, "get-scan", fixture.scan_id, environment=fixture.environment
        )["scan"]["usage"]
        == initial["usage"]
    )
    arguments = ("--thread-id", "scan-parent", "--turn-id", turn_id)
    finalized = scan_command(
        fixture.state_dir,
        "finalize-scan-usage",
        fixture.scan_id,
        *arguments,
        environment=fixture.environment,
    )["scan"]
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
    helper = runpy.run_path(
        str(Path(__file__).resolve().parents[1] / "scripts/workbench_scan_usage.py")
    )
    measurement = helper["_read_rollout_usage"](
        helper["RolloutSession"]("scan-parent", None, parent),
        started_at=fixture.started_at,
        completed_at=datetime.fromisoformat(stopped_at.replace("Z", "+00:00")),
        completed_turn_id=turn_id,
    )
    measured = measurement.tokens
    warnings = measurement.warnings
    assert measured == _counts(90, 0, 11)
    assert warnings == set()
    assert (
        scan_command(
            fixture.state_dir,
            "finalize-scan-usage",
            fixture.scan_id,
            *arguments,
            environment=fixture.environment,
        )["scan"]["usage"]
        == finalized["usage"]
    )
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
    usage = scan_command(
        fixture.state_dir,
        "finalize-scan-usage",
        fixture.scan_id,
        "--thread-id",
        "scan-parent",
        "--turn-id",
        turn_id,
        "--turn-status",
        turn_status,
        environment=fixture.environment,
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
    parent = _rollout(
        tmp_path,
        "scan-parent",
        [_response_event(counted, "scan-parent", "first", 10, 2)],
    )
    _state_graph(fixture.environment, {"scan-parent": parent}, [])
    arguments = ("--thread-id", "scan-parent", "--turn-id", "turn-scan-parent")
    initial = _complete_scan(fixture, *arguments)["scan"]["usage"]
    with parent.open("a", encoding="utf-8") as output:
        final_response = _response_event(counted, "scan-parent", "final", 20, 3, turn_usage=(30, 5))
        output.write(f"{json.dumps(final_response)}\n")
    with sqlite3.connect(
        Path(fixture.environment["CODEX_SQLITE_HOME"]) / "state_5.sqlite"
    ) as native_database:
        native_database.execute("BEGIN EXCLUSIVE")
        pending = scan_command(
            fixture.state_dir,
            "finalize-scan-usage",
            fixture.scan_id,
            *arguments,
            environment=fixture.environment,
        )["scan"]["usage"]
        assert pending == initial
        assert pending["totalTokens"] == 12
        assert pending["completion"]["finalized"] is False

    finalized = scan_command(
        fixture.state_dir,
        "finalize-scan-usage",
        fixture.scan_id,
        *arguments,
        environment=fixture.environment,
    )["scan"]["usage"]
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
    assert (
        scan_command(
            fixture.state_dir,
            "finalize-scan-usage",
            fixture.scan_id,
            *arguments,
            environment=fixture.environment,
        )["scan"]["usage"]
        == initial
    )
    _state_graph(
        fixture.environment,
        {
            "scan-parent": _rollout(
                tmp_path,
                "scan-parent",
                [_response_event(fixture.started_at, "scan-parent", "final-response", 10, 2)],
            )
        },
        [],
    )
    finalized = scan_command(
        fixture.state_dir,
        "finalize-scan-usage",
        fixture.scan_id,
        *arguments,
        environment=fixture.environment,
    )["scan"]["usage"]
    assert finalized["coverage"] == "complete"
    assert finalized["totalTokens"] == 12
    assert finalized["completion"]["finalized"] is True


def test_host_final_usage_does_not_invent_an_unrecorded_completion_turn(tmp_path: Path) -> None:
    fixture = _start_scan(tmp_path)
    arguments = ("--thread-id", "scan-parent", "--turn-id", "unrecorded-turn")
    _state_graph(
        fixture.environment,
        {
            "scan-parent": _rollout(
                tmp_path,
                "scan-parent",
                [
                    _response_event(fixture.started_at, "scan-parent", "earlier-response", 10, 2),
                    _event(fixture.started_at, "event_msg", {"type": "task_complete"}),
                ],
            )
        },
        [],
    )
    _complete_scan(fixture, *arguments)
    finalized = scan_command(
        fixture.state_dir,
        "finalize-scan-usage",
        fixture.scan_id,
        *arguments,
        environment=fixture.environment,
    )["scan"]["usage"]
    assert finalized["coverage"] == "partial"
    assert finalized["totalTokens"] == 12
    assert finalized["warnings"] == ["completion_turn_unavailable"]
    assert finalized["completion"]["finalized"] is True


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
    assert "usage" not in failed


@pytest.mark.parametrize("worker_kind", ["discovery", "dedup"])
def test_completion_recovers_replaced_deep_worker_threads(tmp_path: Path, worker_kind: str) -> None:
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
    artifact.mkdir(parents=True)
    prompt = artifact / "prompt.md"
    prompt.write_text("Review the fixture target.\n", encoding="utf-8")
    worker_id = str(uuid.uuid4())
    if worker_kind == "dedup":
        with sqlite3.connect(fixture.state_dir / "workbench.sqlite3") as connection:
            connection.execute(
                "INSERT INTO deep_scan_workers "
                "(id, scan_id, kind, status, prompt_path, artifact_dir, created_at, updated_at) "
                "VALUES (?, ?, 'dedup', 'queued', ?, ?, ?, ?)",
                (
                    worker_id,
                    fixture.scan_id,
                    str(prompt),
                    str(artifact),
                    fixture.started_at.isoformat(),
                    fixture.started_at.isoformat(),
                ),
            )
    for attempt, thread_id in enumerate(
        ["sdk-first-attempt", "sdk-current-attempt", "sdk-current-attempt"], start=1
    ):
        upsert_deep_worker(
            fixture.state_dir,
            fixture.scan_id,
            worker_id,
            worker_kind,
            "running",
            str(prompt),
            str(artifact),
            "--attempt",
            str(attempt),
            "--sdk-thread-id",
            thread_id,
            environment=fixture.environment,
        )
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
    working_directory = artifact if worker_kind == "discovery" else fixture.scan_dir / "artifacts"
    with sqlite3.connect(
        Path(fixture.environment["CODEX_SQLITE_HOME"]) / "state_5.sqlite"
    ) as connection:
        connection.executemany(
            "UPDATE threads SET cwd = ?, created_at = ? WHERE id = ?",
            [
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
    usage = _complete_scan(fixture)["scan"]["usage"]
    assert (
        usage.items()
        >= {
            "coverage": "complete",
            "source": "codex_rollout",
            **_counts(67, 0, 18),
            "threadCount": 4,
        }.items()
    )


@pytest.mark.cross_platform
@pytest.mark.parametrize(
    ("platform_name", "directory", "recorded_cwd", "matches"),
    [
        ("nt", r"C:\Scans\Job\output", "\\\\?\\c:\\scans\\job\\OUTPUT\\", True),
        ("nt", r"C:\Scans\Job\output", "C:/scans/job/output/", True),
        (
            "nt",
            r"\\server\share\Scans\Job\output",
            "\\\\?\\UNC\\SERVER\\share\\scans\\job\\output\\",
            True,
        ),
        ("nt", r"C:\Scans\Job\output", r"\\?\C:\Scans\Job\other-output", False),
        ("posix", "/scans/Job/output", "/scans/Job/output", True),
        ("posix", "/scans/Job/output", "/scans/job/output", False),
    ],
)
def test_worker_discovery_matches_platform_path_spelling(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    platform_name: str,
    directory: str,
    recorded_cwd: str,
    matches: bool,
) -> None:
    started = datetime.fromisoformat("2026-01-01T00:00:00+00:00")
    environment = {"CODEX_SQLITE_HOME": str(tmp_path / "codex-sqlite")}
    _state_graph(
        environment,
        {
            "current-worker": _rollout(tmp_path, "current-worker", []),
            "replaced-worker": _rollout(tmp_path, "replaced-worker", []),
        },
        [],
    )
    state_database = Path(environment["CODEX_SQLITE_HOME"]) / "state_5.sqlite"
    with sqlite3.connect(state_database) as connection:
        connection.execute(
            "UPDATE threads SET cwd = ?, created_at = ? WHERE id = ?",
            (recorded_cwd, int(started.timestamp()), "replaced-worker"),
        )
    scripts = Path(__file__).resolve().parents[1] / "scripts"
    monkeypatch.syspath_prepend(str(scripts))
    helper = runpy.run_path(str(scripts / "workbench_scan_usage.py"))
    discover = helper["_discover_rollout_sessions"]
    monkeypatch.setitem(discover.__globals__, "os", SimpleNamespace(name=platform_name))
    warnings: set[str] = set()

    sessions, missing = discover(
        state_database,
        ["current-worker"],
        warnings,
        worker_directories={directory},
        started_at=started,
        completed_at=started + timedelta(seconds=1),
    )

    expected_threads = {"current-worker", "replaced-worker"} if matches else {"current-worker"}
    assert {session.thread_id for session in sessions} == expected_threads
    assert missing == set()
    assert warnings == set()


@pytest.mark.parametrize("parent_measured", [False, True])
@pytest.mark.parametrize("worker_measured", [False, True])
def test_completion_uses_latest_account_snapshot_across_owned_sessions(
    tmp_path: Path, parent_measured: bool, worker_measured: bool
) -> None:
    fixture = _start_scan(tmp_path)
    first = fixture.started_at + timedelta(microseconds=1)
    latest = first + timedelta(microseconds=1)

    parent = _rollout(
        tmp_path,
        "scan-parent",
        [
            *([_token_event(first, 10, 3)] if parent_measured else []),
            _allowance_event(first, 6),
            _allowance_event(first, 2, "another-limit"),
            _allowance_event(first + timedelta(days=1), 99),
        ],
    )
    worker = _rollout(
        tmp_path,
        "worker",
        [
            *([_token_event(first, 20, 5)] if worker_measured else []),
            _allowance_event(latest, 69),
            _allowance_event(first, 6),
        ],
        parent_thread_id="scan-parent",
    )
    unrelated = _rollout(tmp_path, "unrelated", [_allowance_event(latest, 100)])
    _state_graph(
        fixture.environment,
        {
            "scan-parent": parent,
            "worker": worker,
            "unrelated": unrelated,
        },
        [("scan-parent", "worker")],
    )

    completed = _complete_scan(fixture)
    usage = completed["scan"]["usage"]
    measured = int(parent_measured) + int(worker_measured)
    assert usage["coverage"] == (
        "complete" if measured == 2 else "partial" if measured else "unavailable"
    )
    assert usage["threadCount"] == measured
    if measured:
        assert usage["totalTokens"] == 13 * parent_measured + 25 * worker_measured
        assert usage["byRole"]["parent"]["threadCount"] == int(parent_measured)
        assert usage["byRole"]["workers"]["threadCount"] == int(worker_measured)
        assert datetime.fromisoformat(usage["tokensUpdatedAt"]) == first
        if measured == 1:
            assert usage["missingThreadCount"] == 1
    else:
        assert not set(_counts(0, 0, 0)).intersection(usage)
        assert "byRole" not in usage
        assert "tokensUpdatedAt" not in usage
    if measured < 2:
        assert usage["warnings"] == ["token_record_missing", "token_usage_unavailable"]
    limits = {item["limitId"]: item for item in usage["accountRateLimits"]}
    assert limits["codex"] == {
        "limitId": "codex",
        "observedAt": latest.isoformat(),
        "primary": {"usedPercent": 69, "windowMinutes": 10080, "resetsAt": 1800000000},
        "secondary": None,
    }
    assert limits["another-limit"]["primary"]["usedPercent"] == 2
    assert (
        scan_command(
            fixture.state_dir, "get-scan", fixture.scan_id, environment=fixture.environment
        )["scan"]["usage"]
        == usage
    )


@pytest.mark.parametrize("terminal_status", ["complete", "failed"])
def test_large_usage_persists_with_terminal_scan_state(
    tmp_path: Path, terminal_status: str
) -> None:
    fixture = _start_scan(tmp_path)
    usage = {
        "coverage": "complete",
        "source": "codex_rollout",
        "threadCount": 1,
        **_counts(120, 30, 15),
        "accountRateLimits": [
            {
                "limitId": f"fixture-limit-{index}",
                "observedAt": fixture.started_at.isoformat(),
                "primary": {"usedPercent": 6, "windowMinutes": 10080, "resetsAt": 1800000000},
                "secondary": None,
            }
            for index in range(60)
        ],
    }
    cost_json = json.dumps({"usage": usage}, separators=(",", ":"))
    assert len(cost_json.encode("utf-8")) > 8192

    if terminal_status == "complete":
        terminal = _complete_scan(fixture, "--cost-json", cost_json)["scan"]
    else:
        terminal = fail_scan(
            fixture.state_dir,
            fixture.scan_id,
            "Fixture failure.",
            "--cost-json",
            cost_json,
            environment=fixture.environment,
        )["scan"]

    assert terminal["progress"]["status"] == terminal_status
    assert terminal["usage"] == usage
    stored = scan_command(
        fixture.state_dir, "get-scan", fixture.scan_id, environment=fixture.environment
    )["scan"]
    assert stored["progress"]["status"] == terminal_status
    assert stored["usage"] == usage


def test_completion_collects_large_usage_from_owned_rollouts(tmp_path: Path) -> None:
    fixture = _start_scan(tmp_path)
    counted = fixture.started_at + timedelta(microseconds=1)
    limit_ids = {f"fixture-limit-{index}" for index in range(60)}
    parent = _rollout(
        tmp_path,
        "scan-parent",
        [
            _token_event(counted, 120, 15, cached_input_tokens=30),
            *[_allowance_event(counted, 6, limit_id) for limit_id in sorted(limit_ids)],
        ],
    )
    _state_graph(fixture.environment, {"scan-parent": parent}, [])

    completed = _complete_scan(fixture)["scan"]

    assert completed["progress"]["status"] == "complete"
    usage = completed["usage"]
    assert len(json.dumps({"usage": usage}, separators=(",", ":")).encode("utf-8")) > 8192
    assert usage["coverage"] == "complete"
    assert usage["threadCount"] == 1
    assert usage.items() >= _counts(120, 30, 15).items()
    assert {limit["limitId"] for limit in usage["accountRateLimits"]} == limit_ids
    assert (
        scan_command(
            fixture.state_dir, "get-scan", fixture.scan_id, environment=fixture.environment
        )["scan"]["usage"]
        == usage
    )


def test_host_final_usage_saves_allowances_before_token_receipts(tmp_path: Path) -> None:
    fixture = _start_scan(tmp_path)
    arguments = ("--thread-id", "scan-parent", "--turn-id", "turn-scan-parent")
    initial = _complete_scan(fixture, *arguments)["scan"]["usage"]
    parent = _rollout(
        tmp_path,
        "scan-parent",
        [_allowance_event(fixture.started_at, 6)],
    )
    _state_graph(fixture.environment, {"scan-parent": parent}, [])

    pending = scan_command(
        fixture.state_dir,
        "finalize-scan-usage",
        fixture.scan_id,
        *arguments,
        environment=fixture.environment,
    )["scan"]["usage"]
    assert pending["coverage"] == "unavailable"
    assert pending["completion"] == initial["completion"]
    assert not set(_counts(0, 0, 0)).intersection(pending)
    assert pending["accountRateLimits"][0]["primary"]["usedPercent"] == 6
    assert (
        scan_command(
            fixture.state_dir, "get-scan", fixture.scan_id, environment=fixture.environment
        )["scan"]["usage"]
        == pending
    )

    with parent.open("a", encoding="utf-8") as output:
        receipt = _response_event(fixture.started_at, "scan-parent", "final-response", 10, 2)
        output.write(f"{json.dumps(receipt)}\n")
    finalized = scan_command(
        fixture.state_dir,
        "finalize-scan-usage",
        fixture.scan_id,
        *arguments,
        environment=fixture.environment,
    )["scan"]["usage"]
    assert finalized["totalTokens"] == 12
    assert finalized["completion"]["finalized"] is True
    assert finalized["accountRateLimits"] == pending["accountRateLimits"]


@pytest.mark.parametrize("limits", [{"limitId": "codex"}, [{"limitId": "codex"}]])
def test_completion_validates_account_snapshots_without_token_usage(
    tmp_path: Path, limits: object
) -> None:
    fixture = _start_scan(tmp_path)
    usage = {
        "coverage": "unavailable",
        "source": "codex_rollout",
        "threadCount": 0,
        "accountRateLimits": limits,
    }
    rejected = scan_command(
        fixture.state_dir,
        "complete-scan",
        fixture.scan_id,
        "--cost-json",
        json.dumps({"usage": usage}),
        environment=fixture.environment,
        check=False,
    )
    assert rejected["returncode"] != 0
    assert "invalid measured token usage" in rejected["stderr"]


@pytest.mark.parametrize("terminal", [None, "task_complete", "turn_aborted"])
def test_completion_marks_worker_without_token_receipt_partial(
    tmp_path: Path, terminal: str | None
) -> None:
    fixture = _start_scan(tmp_path)
    counted = fixture.started_at + timedelta(microseconds=1)
    parent = _rollout(tmp_path, "scan-parent", [_token_event(counted, 12, 3)])
    worker = _rollout(
        tmp_path,
        "worker",
        [_event(counted, "event_msg", {"type": terminal})] if terminal else [],
        parent_thread_id="scan-parent",
        task_started_at=counted,
        include_task_complete=False,
    )
    _state_graph(
        fixture.environment, {"scan-parent": parent, "worker": worker}, [("scan-parent", "worker")]
    )

    usage = _complete_scan(fixture)["scan"]["usage"]
    assert usage["coverage"] == "partial"
    expected_warnings = {"token_record_missing", "token_usage_unavailable"}
    if terminal is None:
        expected_warnings.add("turn_in_progress")
    elif terminal == "turn_aborted":
        expected_warnings.add("turn_interrupted")
    assert set(usage["warnings"]) == expected_warnings
    assert usage["totalTokens"] == 15
    assert usage["threadCount"] == 1
    assert usage["missingThreadCount"] == 1
    assert usage["byRole"]["workers"] == {**_counts(0, 0, 0), "threadCount": 0}
    assert usage["accountRateLimits"] == []


def test_completion_marks_in_flight_usage_partial_even_with_earlier_receipts(
    tmp_path: Path,
) -> None:
    fixture = _start_scan(tmp_path)
    counted = fixture.started_at + timedelta(microseconds=1)
    parent = _rollout(
        tmp_path,
        "scan-parent",
        [
            _event(counted, "event_msg", {"type": "task_started", "turn_id": "scan-turn"}),
            _token_event(counted, 12, 3),
            _event(counted + timedelta(days=1), "event_msg", {"type": "task_complete"}),
        ],
    )
    _state_graph(fixture.environment, {"scan-parent": parent}, [])
    usage = _complete_scan(fixture)["scan"]["usage"]
    assert usage["coverage"] == "partial"
    assert usage["totalTokens"] == 15
    assert usage["warnings"] == ["turn_in_progress"]


@pytest.mark.parametrize("gap", ["aborted", "in_progress", "completed_without_receipt"])
def test_completion_preserves_receipts_when_later_worker_usage_is_missing(
    tmp_path: Path, gap: str
) -> None:
    fixture = _start_scan(tmp_path)
    counted = fixture.started_at + timedelta(microseconds=1)
    parent = _rollout(tmp_path, "scan-parent", [_token_event(counted, 12, 3)])
    events = [_response_event(counted, "worker", "measured-response", 20, 5)]
    if gap == "aborted":
        events.append(_event(counted, "event_msg", {"type": "turn_aborted"}))
        expected_warning = "turn_interrupted"
    elif gap == "completed_without_receipt":
        events.extend(
            [
                _event(counted, "event_msg", {"type": "task_complete"}),
                _event(counted, "event_msg", {"type": "task_started", "turn_id": "later-turn"}),
                _event(counted, "event_msg", {"type": "task_complete", "turn_id": "later-turn"}),
            ]
        )
        expected_warning = "token_record_missing"
    else:
        expected_warning = "turn_in_progress"
    worker = _rollout(
        tmp_path,
        "worker",
        events,
        parent_thread_id="scan-parent",
        include_task_complete=False,
    )
    _state_graph(
        fixture.environment, {"scan-parent": parent, "worker": worker}, [("scan-parent", "worker")]
    )

    usage = _complete_scan(fixture)["scan"]["usage"]
    assert usage["coverage"] == "partial"
    assert usage["warnings"] == [expected_warning]
    assert usage["totalTokens"] == 40
    assert usage["byRole"]["workers"]["totalTokens"] == 25


@pytest.mark.parametrize("worker", [False, True])
@pytest.mark.parametrize("terminal", ["task_complete", "turn_aborted"])
@pytest.mark.parametrize("receipt", ["none", "native", "legacy", "zero"])
def test_closed_turn_coverage_survives_later_success(
    tmp_path: Path, worker: bool, terminal: str, receipt: str
) -> None:
    started = datetime.fromisoformat("2026-01-01T00:00:00+00:00")
    thread_id = "worker" if worker else "scan-parent"
    parent_id = "scan-parent" if worker else None
    events = [_event(started, "event_msg", {"type": "task_started", "turn_id": "first"})]
    if receipt in {"native", "zero"}:
        events.append(
            _response_event(
                started,
                thread_id,
                "first-response",
                20 if receipt == "native" else 0,
                3 if receipt == "native" else 0,
                turn_id="first",
            )
        )
    elif receipt == "legacy":
        events.append(_token_event(started, 20, 3))
    events.extend(
        [
            _event(started, "event_msg", {"type": terminal, "turn_id": "first"}),
            _event(started, "event_msg", {"type": "task_started", "turn_id": "second"}),
            _response_event(started, thread_id, "second-response", 10, 2, turn_id="second"),
            _event(started, "event_msg", {"type": "task_complete", "turn_id": "second"}),
        ]
    )
    rollout = _rollout(
        tmp_path, thread_id, events, parent_thread_id=parent_id, include_task_start=False
    )
    helper = runpy.run_path(
        str(Path(__file__).resolve().parents[1] / "scripts/workbench_scan_usage.py")
    )
    measurement = helper["_read_rollout_usage"](
        helper["RolloutSession"](thread_id, parent_id, rollout),
        started_at=started,
        completed_at=started,
    )
    usage, warnings = measurement.tokens, measurement.warnings
    assert usage == (_counts(30, 0, 5) if receipt in {"native", "legacy"} else _counts(10, 0, 2))
    assert warnings == ({"token_record_missing"} if receipt == "none" else set()) | (
        {"turn_interrupted"} if terminal == "turn_aborted" else set()
    )


@pytest.mark.parametrize("receipt", [None, "legacy", "native"])
def test_closed_turn_coverage_retains_before_window_receipt_evidence(
    tmp_path: Path, receipt: str | None
) -> None:
    started = datetime.fromisoformat("2026-01-01T00:00:01+00:00")
    before = started - timedelta(seconds=1)
    events = [_event(before, "event_msg", {"type": "task_started", "turn_id": "first"})]
    if receipt:
        events.append(
            _response_event(before, "scan-parent", "before", 20, 3, turn_id="first")
            if receipt == "native"
            else _token_event(before, 20, 3)
        )
    events.extend(
        [
            _event(started, "event_msg", {"type": "task_complete", "turn_id": "first"}),
            _event(started, "event_msg", {"type": "task_started", "turn_id": "second"}),
            _response_event(started, "scan-parent", "counted", 10, 2, turn_id="second"),
            _event(started, "event_msg", {"type": "task_complete", "turn_id": "second"}),
        ]
    )
    rollout = _rollout(tmp_path, "scan-parent", events)
    helper = runpy.run_path(
        str(Path(__file__).resolve().parents[1] / "scripts/workbench_scan_usage.py")
    )
    measurement = helper["_read_rollout_usage"](
        helper["RolloutSession"]("scan-parent", None, rollout),
        started_at=started,
        completed_at=started,
    )
    usage, warnings = measurement.tokens, measurement.warnings
    assert usage == _counts(10, 0, 2)
    assert warnings == (set() if receipt else {"token_record_missing"})


def test_closed_turn_coverage_accepts_delayed_receipt_for_same_turn(tmp_path: Path) -> None:
    started = datetime.fromisoformat("2026-01-01T00:00:00+00:00")
    rollout = _rollout(
        tmp_path,
        "scan-parent",
        [
            _event(started, "event_msg", {"type": "task_started", "turn_id": "first"}),
            _event(started, "event_msg", {"type": "task_complete", "turn_id": "first"}),
            _response_event(started, "scan-parent", "late", 10, 2, turn_id="first"),
        ],
    )
    helper = runpy.run_path(
        str(Path(__file__).resolve().parents[1] / "scripts/workbench_scan_usage.py")
    )
    measurement = helper["_read_rollout_usage"](
        helper["RolloutSession"]("scan-parent", None, rollout),
        started_at=started,
        completed_at=started,
    )
    usage, warnings = measurement.tokens, measurement.warnings
    assert usage == _counts(10, 0, 2)
    assert warnings == set()


def test_closed_turn_coverage_preserves_interruption_after_same_turn_resumes(
    tmp_path: Path,
) -> None:
    started = datetime.fromisoformat("2026-01-01T00:00:00+00:00")
    rollout = _rollout(
        tmp_path,
        "scan-parent",
        [
            _event(started, "event_msg", {"type": "task_started", "turn_id": "same-turn"}),
            _event(started, "event_msg", {"type": "turn_aborted", "turn_id": "same-turn"}),
            _event(started, "event_msg", {"type": "task_started", "turn_id": "same-turn"}),
            _response_event(started, "scan-parent", "recovered", 10, 2, turn_id="same-turn"),
            _event(started, "event_msg", {"type": "task_complete", "turn_id": "same-turn"}),
        ],
    )
    helper = runpy.run_path(
        str(Path(__file__).resolve().parents[1] / "scripts/workbench_scan_usage.py")
    )
    measurement = helper["_read_rollout_usage"](
        helper["RolloutSession"]("scan-parent", None, rollout),
        started_at=started,
        completed_at=started,
    )
    usage, warnings = measurement.tokens, measurement.warnings
    assert usage == _counts(10, 0, 2)
    assert warnings == {"turn_interrupted"}


def test_closed_turn_coverage_ignores_inherited_and_outside_window_interruptions(
    tmp_path: Path,
) -> None:
    started = datetime.fromisoformat("2026-01-01T00:00:00+00:00")
    before = started - timedelta(seconds=1)
    after = started + timedelta(seconds=1)
    rollout = _rollout(
        tmp_path,
        "worker",
        [
            _response_event(started, "worker", "counted", 10, 2),
            _event(started, "event_msg", {"type": "task_complete", "turn_id": "turn-worker"}),
            _event(after, "event_msg", {"type": "task_started", "turn_id": "later"}),
            _event(after, "event_msg", {"type": "turn_aborted", "turn_id": "later"}),
        ],
        parent_thread_id="scan-parent",
        copied_events=[
            _event(before, "event_msg", {"type": "turn_aborted", "turn_id": "inherited"}),
        ],
    )
    helper = runpy.run_path(
        str(Path(__file__).resolve().parents[1] / "scripts/workbench_scan_usage.py")
    )
    measurement = helper["_read_rollout_usage"](
        helper["RolloutSession"]("worker", "scan-parent", rollout),
        started_at=started,
        completed_at=started,
    )
    usage, warnings = measurement.tokens, measurement.warnings
    assert usage == _counts(10, 0, 2)
    assert warnings == set()


def test_completion_marks_closed_turn_without_receipt_partial(tmp_path: Path) -> None:
    fixture = _start_scan(tmp_path)
    counted = fixture.started_at + timedelta(microseconds=1)
    parent = _rollout(
        tmp_path,
        "scan-parent",
        [
            _event(counted, "event_msg", {"type": "task_started", "turn_id": "empty"}),
            _event(counted, "event_msg", {"type": "task_complete", "turn_id": "empty"}),
            _event(counted, "event_msg", {"type": "task_started", "turn_id": "measured"}),
            _response_event(counted, "scan-parent", "response", 10, 2, turn_id="measured"),
            _event(counted, "event_msg", {"type": "task_complete", "turn_id": "measured"}),
        ],
    )
    _state_graph(fixture.environment, {"scan-parent": parent}, [])
    assert (
        _complete_scan(fixture)["scan"]["usage"].items()
        >= {
            "coverage": "partial",
            "source": "codex_rollout",
            **_counts(10, 0, 2),
            "threadCount": 1,
            "warnings": ["token_record_missing"],
        }.items()
    )
