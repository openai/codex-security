from __future__ import annotations

import json
import os
import runpy
import sqlite3
import subprocess
import sys
import tempfile
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from workbench_test_support import (
    SCRIPT,
    create_saved_workspace,
    initialize_git_repository,
    mark_deep_coordinator_succeeded,
    run_workbench,
    start_delivered_scan,
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
        workspace = create_saved_workspace(state_dir, target, thread_id="scan-parent")
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
        datetime.fromisoformat(row[0]),
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


def _complete_scan(fixture: ScanFixture) -> dict[str, Any]:
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
    return run_workbench(
        fixture.state_dir,
        "complete-scan",
        "--scan-id",
        fixture.scan_id,
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
    state_dir = tmp_path / "workbench-state"
    target = tmp_path / "target"
    target.mkdir()
    environment = {
        "CODEX_HOME": str(tmp_path / "codex-home"),
        "CODEX_SQLITE_HOME": str(tmp_path / "codex-sqlite"),
        "CODEX_STATE_DB": "",
    }
    deep = run_workbench(
        state_dir,
        "begin-deep-scan",
        "--thread-id",
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
        datetime.fromisoformat(row[0]),
        environment,
        "deep",
    )
    counted = fixture.started_at + timedelta(microseconds=1)
    artifact = scan_dir / "artifacts" / "usage-worker"
    artifact.mkdir(parents=True)
    prompt = artifact / "prompt.md"
    prompt.write_text("Review the fixture target.\n", encoding="utf-8")
    run_workbench(
        state_dir,
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
    assert usage == {
        "coverage": "partial",
        "source": "codex_rollout",
        **_counts(27, 0, 7),
        "threadCount": 2,
        "missingThreadCount": 1,
        "warnings": ["scan_owner_turn_unavailable"],
        "modelUsage": [{"model": None, **_counts(27, 0, 7)}],
    }


@pytest.mark.parametrize(
    "worker_home",
    [
        "recorded",
        "current",
        "inherited-sqlite",
        "current-prefix",
        "recorded-prefix",
        "current-unreadable",
        "current-mismatched",
        "external-sqlite",
        "external-shared-home",
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
        target = root / "target"
        target.mkdir(parents=True)
        selected_home = current_home if worker_home == "current" else root / "original-home"
        if worker_home == "external-shared-home":
            selected_home = tmp_path / "shared-original-home"
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
            datetime.fromisoformat(deep["createdAt"]),
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
                    "INSERT INTO threads VALUES (?, ?)",
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
            "current-unreadable",
            "current-mismatched",
        }:
            recorded_threads = dict(worker_threads)
            if worker_home != "recorded":
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
                        "INSERT INTO threads VALUES (?, ?)", (thread_id, str(current_copy))
                    )
            _state_graph(
                {"CODEX_SQLITE_HOME": str(selected_home)},
                recorded_threads,
                [(f"discovery-{index}", child_id)],
            )
        elif worker_home in {"external-sqlite", "external-shared-home"}:
            # Native keeps rollouts in its Codex home even when its SQLite
            # index lives elsewhere and recovery chooses a different index.
            sessions = selected_home / "sessions" / "2026" / "01" / "01"
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
        else:
            assert usage == {
                "coverage": "complete",
                "source": "codex_rollout",
                **_counts(index * 77, 0, 13),
                "threadCount": 4,
                "modelUsage": (
                    [
                        {"model": None, **_counts(index * 47, 0, 8)},
                        {"model": "model-alpha", **_counts(index * 20, 0, 3)},
                        {"model": "model-beta", **_counts(index * 10, 0, 2)},
                    ]
                    if copied_rollout
                    else [{"model": None, **_counts(index * 77, 0, 13)}]
                ),
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
    completed = run_workbench(
        fixture.state_dir,
        "complete-scan",
        "--scan-id",
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
    extra_command = run_workbench(
        fixture.state_dir,
        "get-scan-usage",
        "--scan-id",
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
    failed = run_workbench(
        fixture.state_dir,
        "fail-scan",
        "--scan-id",
        fixture.scan_id,
        "--message",
        "Fixture failure.",
        environment=fixture.environment,
    )["scan"]
    assert failed["progress"]["status"] == "failed"
    assert "usage" not in failed


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
    counts, warnings = usage_reader._read_rollout_usage(
        usage_reader.RolloutSession("worker", None, rollout),
        started_at=start,
        completed_at=None,
    )
    assert counts == _counts(200, 0, 20)
    assert warnings == {"token_counter_regressed"}
    models = {}
    counts, warnings = usage_reader._read_rollout_usage(
        usage_reader.RolloutSession("worker", None, rollout),
        started_at=start,
        completed_at=None,
        model_usage=models,
    )
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
    counts, warnings = usage_reader._read_rollout_usage(
        usage_reader.RolloutSession("parent", None, _rollout(tmp_path, "parent", events)),
        started_at=start,
        completed_at=end,
        owner_turn_id="scan-turn",
        model_usage=models,
    )
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
    tokens = dict(input_tokens=100, cached_input_tokens=20, output_tokens=10, total_tokens=110)
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
    total, warnings = reader._read_rollout_usage(
        reader.RolloutSession("parent", None, _rollout(tmp_path, "parent", events)),
        started_at=start,
        completed_at=start + timedelta(seconds=10),
        owner_turn_id="scan-turn",
        model_usage=models,
    )
    assert total == _counts(270, 210, 27)
    assert warnings == set()
    assert models == {"gpt-5.6-sol": _counts(220, 170, 22), "gpt-6-astra": _counts(50, 40, 5)}


def test_delayed_response_receipt_resolves_missing_cumulative_usage(
    tmp_path: Path, workbench_api
) -> None:
    reader = sys.modules["workbench_scan_usage"]
    start = datetime.fromisoformat("2026-01-01T00:00:00+00:00")

    def receipt(response, tokens, cumulative):
        def usage(value):
            return dict(input_tokens=value, output_tokens=0, total_tokens=value)

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
    total, warnings = reader._read_rollout_usage(session, started_at=start, completed_at=None)
    assert total == _counts(150, 0, 0)
    assert warnings == {"token_receipts_incomplete"}
    with rollout.open("a") as source:
        source.write(json.dumps(receipt("second", 30, 130)) + "\n")
    total, warnings = reader._read_rollout_usage(session, started_at=start, completed_at=None)
    assert total == _counts(180, 0, 0)
    assert warnings == set()


def test_exact_receipts_replace_overlapping_legacy_counter(tmp_path: Path, workbench_api) -> None:
    reader = sys.modules["workbench_scan_usage"]
    start = datetime.fromisoformat("2026-01-01T00:00:00+00:00")

    def receipt(response, tokens, cumulative):
        def usage(value):
            return dict(input_tokens=value, output_tokens=0, total_tokens=value)

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
    total, warnings = reader._read_rollout_usage(
        reader.RolloutSession("parent", None, rollout),
        started_at=start,
        completed_at=None,
        model_usage=models,
    )
    assert total == _counts(110, 0, 0)
    assert warnings == set()
    assert models == {"gpt-5.6-sol": _counts(110, 0, 0)}
