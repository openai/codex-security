"""Terminal scan usage from worker and owner rollout receipts."""

import hashlib
import json
import sqlite3
import sys
import uuid
from dataclasses import replace
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from test_workbench_scan_usage import (
    _complete_scan,
    _counts,
    _event,
    _measure_rollout,
    _response_event,
    _rollout,
    _start_scan,
    _state_graph,
    _token_event,
)
from test_workbench_scan_usage import scan_usage as scan_usage
from workbench_test_support import run_workbench, upsert_deep_worker


@pytest.mark.parametrize(
    ("worker_kind", "legacy_archive", "short_archive"),
    [
        ("discovery", False, False),
        ("discovery", True, False),
        ("dedup", False, False),
        pytest.param(
            "discovery",
            True,
            True,
            marks=pytest.mark.skipif(sys.platform == "win32", reason="POSIX archive naming"),
        ),
    ],
)
def test_completion_recovers_replaced_deep_worker_threads(
    tmp_path: Path, worker_kind: str, legacy_archive: bool, short_archive: bool
) -> None:
    # Compressed variants exercise the bundled Node decoder in the SDK runtime lane.
    fixture = _start_scan(tmp_path, mode="deep", dedicated=True)
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
    working_directory = artifact if worker_kind == "discovery" else fixture.scan_dir / "artifacts"
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
    archived_arguments = []
    if short_archive:
        digest = hashlib.sha256(fixture.scan_dir.name.encode()).hexdigest()
        archived = fixture.scan_dir.with_name(f".previous-{digest}-fixture")
        fixture.scan_dir.rename(archived)
        fixture.scan_dir.mkdir(mode=0o700)
        archived_arguments = ["--archived-scan-dir", str(archived)]
    run_workbench(
        fixture.state_dir,
        "register-cli-scan",
        "--repository",
        str(fixture.target),
        "--scan-dir",
        str(fixture.scan_dir),
        "--archive-existing",
        *archived_arguments,
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
    if legacy_archive:
        with sqlite3.connect(fixture.state_dir / "workbench.sqlite3") as db:
            db.execute(
                "UPDATE deep_scan_workers SET artifact_dir = ? WHERE id = ?",
                (str(artifact), worker_id),
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


@pytest.mark.parametrize("worker", [False, True])
@pytest.mark.parametrize("terminal", ["task_complete", "turn_aborted"])
@pytest.mark.parametrize("receipt", ["none", "native", "legacy", "zero"])
def test_closed_turn_coverage_survives_later_success(
    scan_usage, tmp_path: Path, worker: bool, terminal: str, receipt: str
) -> None:
    started = datetime.fromisoformat("2026-01-01T00:00:00+00:00")
    thread_id = "worker" if worker else "scan-parent"
    parent_id = "scan-parent" if worker else None

    def start_turn(turn_id):
        return _event(
            started,
            "event_msg",
            {"type": "task_started", "turn_id": turn_id, "started_at": int(started.timestamp())},
        )

    events = [start_turn("first")]
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
            start_turn("second"),
            _response_event(started, thread_id, "second-response", 10, 2, turn_id="second"),
            _event(started, "event_msg", {"type": "task_complete", "turn_id": "second"}),
        ]
    )
    rollout = _rollout(
        tmp_path, thread_id, events, parent_thread_id=parent_id, include_task_start=False
    )
    usage = _measure_rollout(
        scan_usage, rollout, started, started, thread_id=thread_id, parent_id=parent_id
    )
    assert usage.tokens == (
        _counts(30, 0, 5) if receipt in {"native", "legacy"} else _counts(10, 0, 2)
    )
    assert usage.warnings == ({"token_record_missing"} if receipt == "none" else set()) | (
        {"turn_interrupted"} if terminal == "turn_aborted" else set()
    )
