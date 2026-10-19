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

pytestmark = pytest.mark.native_macos


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
    include_task_start_timestamp: bool = True,
    task_started_at: datetime | None = None,
    session_started_at: datetime | None = None,
    copied_events: list[dict[str, Any]] | None = None,
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
    rollout.write_text(
        "".join(f"{json.dumps(item, separators=(',', ':'))}\n" for item in records),
        encoding="utf-8",
    )
    return rollout.resolve()


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
        ],
    )
    _state_graph(fixture.environment, {"scan-parent": parent}, [])

    assert _complete_scan(fixture)["scan"]["usage"] == {
        "coverage": "complete",
        "source": "codex_rollout",
        **_counts(140, 0, 14),
        "threadCount": 1,
    }


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
    parent = _rollout(tmp_path, "scan-parent", events)
    helper = runpy.run_path(
        str(Path(__file__).resolve().parents[1] / "scripts/workbench_scan_usage.py")
    )

    usage, warnings = helper["_read_rollout_usage"](
        helper["RolloutSession"]("scan-parent", None, parent),
        started_at=started,
        completed_at=completed,
        completed_turn_id="turn-scan-parent" if scope == "completion_turn" else None,
    )

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
        ],
    )
    helper = runpy.run_path(
        str(Path(__file__).resolve().parents[1] / "scripts/workbench_scan_usage.py")
    )

    usage, warnings = helper["_read_rollout_usage"](
        helper["RolloutSession"]("scan-parent", None, parent),
        started_at=started,
        completed_at=started,
    )

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

    usage, warnings = helper["_read_rollout_usage"](
        helper["RolloutSession"]("scan-parent", None, parent),
        started_at=started,
        completed_at=completed,
    )

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
            _event(started, "event_msg", {"type": "task_started", "turn_id": "resumed-turn"}),
            _response_event(
                started, "scan-worker", "resumed-response", 30, 3, turn_id="resumed-turn"
            ),
            _token_event(started, 1_050, 105),
            _event(started, "event_msg", {"type": "task_started", "turn_id": "legacy-turn"}),
            _token_event(started, 1_060, 106),
        ],
        parent_thread_id="scan-parent",
        copied_events=[inherited, _token_event(started, 1_000, 100)],
    )
    helper = runpy.run_path(
        str(Path(__file__).resolve().parents[1] / "scripts/workbench_scan_usage.py")
    )

    usage, warnings = helper["_read_rollout_usage"](
        helper["RolloutSession"]("scan-worker", "scan-parent", worker),
        started_at=started,
        completed_at=started,
    )

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

    usage, warnings = helper["_read_rollout_usage"](
        helper["RolloutSession"]("scan-parent", None, parent),
        started_at=started,
        completed_at=started,
    )

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
        ],
    )
    helper = runpy.run_path(
        str(Path(__file__).resolve().parents[1] / "scripts/workbench_scan_usage.py")
    )

    usage, warnings = helper["_read_rollout_usage"](
        helper["RolloutSession"]("scan-parent", None, parent),
        started_at=started,
        completed_at=started,
    )

    assert usage == _counts(30, 0, 3)
    assert warnings == set()


@pytest.mark.parametrize(
    "failure", ["invalid_usage", "invalid_timestamp", "missing_receipt", "truncated"]
)
def test_native_usage_preserves_partial_measurement_warnings(tmp_path: Path, failure: str) -> None:
    started = datetime.fromisoformat("2026-01-01T00:00:00+00:00")
    first = _response_event(started, "scan-parent", "first", 10, 1)
    second = _response_event(started, "scan-parent", "second", 20, 2, turn_usage=(30, 3))
    if failure == "invalid_usage":
        second["payload"]["usage"] = {}
    elif failure == "invalid_timestamp":
        del second["timestamp"]
    events = [second] if failure == "missing_receipt" else [first, second]
    parent = _rollout(tmp_path, "scan-parent", events)
    if failure == "truncated":
        parent.write_bytes(parent.read_bytes().removesuffix(b"\n"))
    helper = runpy.run_path(
        str(Path(__file__).resolve().parents[1] / "scripts/workbench_scan_usage.py")
    )

    usage, warnings = helper["_read_rollout_usage"](
        helper["RolloutSession"]("scan-parent", None, parent),
        started_at=started,
        completed_at=started,
    )

    assert usage == (_counts(20, 0, 2) if failure == "missing_receipt" else _counts(10, 0, 1))
    assert warnings == {
        "token_record_incomplete"
        if failure == "missing_receipt"
        else "rollout_record_incomplete"
        if failure == "truncated"
        else "token_record_invalid"
    }


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
    _state_graph(
        fixture.environment,
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
    assert completed["scan"]["usage"] == expected
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

    assert usage == {
        "coverage": "complete",
        "source": "codex_rollout",
        **_counts(120, 30, 15, cache_write_input_tokens=12),
        "threadCount": 1,
    }


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
    assert usage == {
        "coverage": "complete",
        "source": "codex_rollout",
        **_counts(240, 65, 42),
        "threadCount": 3,
    }


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
    assert _complete_scan(fixture)["scan"]["usage"] == {
        "coverage": "complete",
        "source": "codex_rollout",
        **_counts(10, 0, 0),
        "threadCount": 1,
    }


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


def test_completion_reports_unavailable_without_fabricating_zero(tmp_path: Path) -> None:
    fixture = _start_scan(tmp_path)
    usage = _complete_scan(fixture)["scan"]["usage"]
    assert usage == {
        "coverage": "unavailable",
        "source": "codex_rollout",
        "threadCount": 0,
        "warnings": ["codex_state_unavailable"],
    }
    assert "totalTokens" not in usage


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


def test_completion_rejects_non_system_rollout_symlink(tmp_path: Path) -> None:
    fixture = _start_scan(tmp_path)
    counted = fixture.started_at + timedelta(microseconds=1)
    canonical = _rollout(tmp_path, "scan-parent", [_token_event(counted, 10, 3)])
    symlink = canonical.with_name("linked-rollout.jsonl")
    symlink.symlink_to(canonical)
    _state_graph(fixture.environment, {"scan-parent": symlink}, [])
    assert _complete_scan(fixture)["scan"]["usage"] == {
        "coverage": "unavailable",
        "source": "codex_rollout",
        "threadCount": 0,
        "warnings": ["rollout_unavailable", "scan_thread_unavailable"],
    }


def test_completion_counts_deep_sdk_workers_and_descendants(tmp_path: Path) -> None:
    fixture = _start_scan(tmp_path, mode="deep")
    counted = fixture.started_at + timedelta(microseconds=1)
    artifact = fixture.scan_dir / "artifacts" / "usage-worker"
    artifact.mkdir(parents=True)
    prompt = artifact / "prompt.md"
    prompt.write_text("Review the fixture target.\n", encoding="utf-8")
    upsert_deep_worker(
        fixture.state_dir,
        fixture.scan_id,
        str(uuid.uuid4()),
        "discovery",
        "running",
        str(prompt),
        str(artifact),
        "--sdk-thread-id",
        "sdk-worker",
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
        },
        [("sdk-worker", "sdk-child")],
    )
    usage = _complete_scan(fixture)["scan"]["usage"]
    assert usage == {
        "coverage": "complete",
        "source": "codex_rollout",
        **_counts(37, 0, 10),
        "threadCount": 3,
    }


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

    assert usage == {
        "coverage": "partial",
        "source": "codex_rollout",
        **_counts(37, 0, 10),
        "threadCount": 3,
        "missingThreadCount": 1,
        "warnings": ["rollout_unavailable"],
    }


def test_completion_preserves_explicit_legacy_cost(tmp_path: Path) -> None:
    fixture = _start_scan(tmp_path)
    counted = fixture.started_at + timedelta(microseconds=1)
    _state_graph(
        fixture.environment,
        {"scan-parent": _rollout(tmp_path, "scan-parent", [_token_event(counted, 15, 6)])},
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
    assert "usage" not in completed


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
    assert initial["usage"] == {
        "coverage": "partial",
        "source": "codex_rollout",
        **_counts(30, 0, 5),
        "threadCount": 2,
        "warnings": ["turn_in_progress"],
        "completion": completion,
    }
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
    assert finalized["usage"] == {
        "coverage": "complete",
        "source": "codex_rollout",
        **_counts(110, 0, 14),
        "threadCount": 2,
        "completion": {**completion, "finalized": True},
    }
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
    measured, warnings = helper["_read_rollout_usage"](
        helper["RolloutSession"]("scan-parent", None, parent),
        started_at=fixture.started_at,
        completed_at=datetime.fromisoformat(stopped_at.replace("Z", "+00:00")),
        completed_turn_id=turn_id,
    )
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
    assert usage == {
        "coverage": "partial",
        "source": "codex_rollout",
        **_counts(10, 0, 2),
        "threadCount": 1,
        "missingThreadCount": 1,
        "warnings": ["rollout_unavailable"]
        + ([] if turn_status == "completed" else [f"scan_turn_{turn_status}"]),
        "completion": {"threadId": "scan-parent", "turnId": turn_id, "finalized": True},
    }


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
    assert finalized == {
        "coverage": "complete",
        "source": "codex_rollout",
        **_counts(30, 0, 5),
        "threadCount": 1,
        "completion": {**initial["completion"], "finalized": True},
    }


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
                [_response_event(fixture.started_at, "scan-parent", "earlier-response", 10, 2)],
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
    assert usage == {
        "coverage": "complete",
        "source": "codex_rollout",
        **_counts(67, 0, 18),
        "threadCount": 4,
    }


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
