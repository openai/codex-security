from __future__ import annotations

import json
import os
import runpy
import sqlite3
import sys
import tempfile
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from workbench_test_support import (
    create_saved_workspace,
    fail_scan,
    initialize_git_repository,
    mark_deep_aggregate_ready,
    private_directory,
    run_workbench,
    scan_command,
    start_delivered_scan,
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
    reasoning_output_tokens: int = 0,
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
                    "reasoning_output_tokens": reasoning_output_tokens,
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


def _state_graph(
    environment: dict[str, str],
    threads: dict[str, Path],
    edges: list[tuple[str, str]],
) -> None:
    sqlite_home = Path(environment["CODEX_SQLITE_HOME"])
    sqlite_home.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(sqlite_home / "state_5.sqlite") as connection:
        connection.execute("CREATE TABLE threads (id TEXT PRIMARY KEY, rollout_path TEXT NOT NULL)")
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
    reasoning_output_tokens: int = 0,
    *,
    cache_write_input_tokens: int = 0,
) -> dict[str, int]:
    return {
        "inputTokens": input_tokens,
        "cachedInputTokens": cached_input_tokens,
        "cacheWriteInputTokens": cache_write_input_tokens,
        "outputTokens": output_tokens,
        "reasoningOutputTokens": reasoning_output_tokens,
        "totalTokens": input_tokens + output_tokens,
    }


def _complete_scan(fixture: ScanFixture, *, cost: dict[str, Any] | None = None) -> dict[str, Any]:
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
        mark_deep_aggregate_ready(fixture.state_dir, fixture.scan_id, fixture.scan_dir)
    write_completed_contract(
        fixture.scan_dir,
        fixture.scan_id,
        fixture.target,
        **options,
    )
    return run_workbench(
        fixture.state_dir,
        "complete-scan",
        "--scan-id",
        fixture.scan_id,
        *(["--cost-json", json.dumps(cost)] if cost is not None else []),
        environment=fixture.environment,
    )


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
    incomplete = prior_session_unavailable or not child_session_saved or merge_kind == "missing"
    assert usage == {
        "coverage": "partial" if incomplete else "complete",
        "source": "codex_rollout",
        **(_counts(37, 0, 10) if child_session_saved else _counts(10, 0, 3)),
        "threadCount": 3 if child_session_saved else 1,
        **({"warnings": ["scan_thread_unavailable"]} if incomplete else {}),
    }


@pytest.mark.parametrize("mode", ["standard", "deep"])
def test_completion_preserves_explicit_legacy_cost(tmp_path: Path, mode: str) -> None:
    fixture = _start_scan(tmp_path, mode=mode)
    # Ordinary SDK registration has no native execution owner.
    with sqlite3.connect(fixture.state_dir / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE scans SET deep_scan_owner_thread_id = NULL WHERE id = ?", (fixture.scan_id,)
        )
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
    completed = _complete_scan(fixture, cost=cost)["scan"]
    assert completed["cost"] == cost
    assert "usage" not in completed


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
    assert completed["usage"] == expected_usage
    assert completed["progress"]["status"] == "complete"
    repeated = run_workbench(
        fixture.state_dir,
        "complete-scan",
        "--scan-id",
        fixture.scan_id,
        environment=fixture.environment,
    )["scan"]
    assert repeated["cost"] == cost
    assert repeated["usage"] == expected_usage


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
    scan = start_delivered_scan(
        state, "--workspace-id", workspace["id"], "--scan-root", str(tmp_path / "scans")
    )["results"]
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
    assert "usage" not in failed


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
        connection.execute("DELETE FROM schema_migrations WHERE version = 53")
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
    assert completed["usage"] == {
        "coverage": "complete",
        "source": "codex_rollout",
        **_counts(110, 0, 0),
        "threadCount": 2,
    }
    assert "historical-worker" in completed["executionThreadIds"]
    assert "historical-worker" in completed["threadIds"]


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
    assert completed["usage"] == {
        **prior_usage,
        **_counts(15, 0, 6),
    }


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
    assert completed["usage"] == expected_usage
    assert completed["cost"] == current_cost
    documents = {
        name: (fixture.scan_dir / name).read_bytes()
        for name in ("scan-manifest.json", "findings.json", "coverage.json")
    }
    for command in ("get-scan", "complete-scan"):
        repeated = run_workbench(
            fixture.state_dir,
            command,
            "--scan-id",
            fixture.scan_id,
            environment=fixture.environment,
        )["scan"]
        assert repeated["usage"] == expected_usage
        assert repeated["cost"] == current_cost
    with sqlite3.connect(fixture.state_dir / "workbench.sqlite3") as connection:
        stored = connection.execute(
            "SELECT cost_json FROM scans WHERE id = ?", (fixture.scan_id,)
        ).fetchone()[0]
    assert json.loads(stored) == {"cost": current_cost, "usage": expected_usage}
    assert documents == {name: (fixture.scan_dir / name).read_bytes() for name in documents}


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
    assert earlier_usage == {
        "coverage": "complete",
        "source": "codex_rollout",
        **_counts(1100, 110, 220, 44),
        "threadCount": 2,
    }
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
    assert completed["usage"] == expected
    assert completed["cost"] == current_cost
    documents = {
        name: (fixture.scan_dir / name).read_bytes()
        for name in ("scan-manifest.json", "findings.json", "coverage.json")
    }
    repeated = run_workbench(
        fixture.state_dir,
        "complete-scan",
        "--scan-id",
        fixture.scan_id,
        environment=fixture.environment,
    )["scan"]
    assert repeated["usage"] == expected
    assert repeated["cost"] == current_cost
    assert documents == {name: (fixture.scan_dir / name).read_bytes() for name in documents}


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
