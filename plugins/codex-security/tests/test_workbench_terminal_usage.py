"""Terminal scan usage from worker and owner rollout receipts."""

import hashlib
import json
import sqlite3
import sys
import uuid
from dataclasses import replace
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from test_workbench_scan_usage import (
    _allowance_event,
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
from workbench_test_support import fail_scan, run_workbench, upsert_deep_worker


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


@pytest.mark.parametrize("missing", ["cwd", "created_at"])
def test_deep_usage_retains_bound_sessions_without_directory_metadata(
    tmp_path: Path, missing: str
) -> None:
    fixture = _start_scan(tmp_path, mode="deep")
    fixture.write_parent_rollout([_token_event(fixture.started_at, 10, 3)])
    with sqlite3.connect(Path(fixture.environment["CODEX_SQLITE_HOME"]) / "state_5.sqlite") as db:
        db.execute(f"ALTER TABLE threads DROP COLUMN {missing}")
    usage = _complete_scan(fixture)["scan"]["usage"]
    assert usage["coverage"] == "partial"
    assert usage["warnings"] == ["worker_directories_unavailable"]
    assert (usage["totalTokens"], usage["threadCount"]) == (13, 1)


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
    scan_usage,
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
    monkeypatch.setattr(scan_usage, "os", SimpleNamespace(name=platform_name))
    warnings: set[str] = set()

    sessions, missing = scan_usage._discover_rollout_sessions(
        state_database,
        ["current-worker"],
        warnings,
        worker_directories={directory: False},
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
    assert fixture.command("get-scan")["scan"]["usage"] == usage


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
    stored = fixture.command("get-scan")["scan"]
    assert stored["progress"]["status"] == terminal_status
    assert stored["usage"] == usage


def test_completion_collects_large_usage_from_owned_rollouts(tmp_path: Path) -> None:
    fixture = _start_scan(tmp_path)
    counted = fixture.started_at + timedelta(microseconds=1)
    limit_ids = {f"fixture-limit-{index}" for index in range(60)}
    fixture.write_parent_rollout(
        [
            _token_event(counted, 120, 15, cached_input_tokens=30),
            *[_allowance_event(counted, 6, limit_id) for limit_id in sorted(limit_ids)],
        ]
    )

    completed = _complete_scan(fixture)["scan"]

    assert completed["progress"]["status"] == "complete"
    usage = completed["usage"]
    assert len(json.dumps({"usage": usage}, separators=(",", ":")).encode("utf-8")) > 8192
    assert usage["coverage"] == "complete"
    assert usage["threadCount"] == 1
    assert usage.items() >= _counts(120, 30, 15).items()
    assert {limit["limitId"] for limit in usage["accountRateLimits"]} == limit_ids
    assert fixture.command("get-scan")["scan"]["usage"] == usage


def test_host_final_usage_saves_allowances_before_token_receipts(tmp_path: Path) -> None:
    fixture = _start_scan(tmp_path)
    arguments = ("--thread-id", "scan-parent", "--turn-id", "turn-scan-parent")
    initial = _complete_scan(fixture, *arguments)["scan"]["usage"]
    parent = fixture.write_parent_rollout([_allowance_event(fixture.started_at, 6)])

    pending = fixture.command("finalize-scan-usage", *arguments)["scan"]["usage"]
    assert pending["coverage"] == "unavailable"
    assert pending["completion"] == initial["completion"]
    assert not set(_counts(0, 0, 0)).intersection(pending)
    assert pending["accountRateLimits"][0]["primary"]["usedPercent"] == 6
    assert fixture.command("get-scan")["scan"]["usage"] == pending

    with parent.open("a", encoding="utf-8") as output:
        receipt = _response_event(fixture.started_at, "scan-parent", "final-response", 10, 2)
        output.write(f"{json.dumps(receipt)}\n")
    finalized = fixture.command("finalize-scan-usage", *arguments)["scan"]["usage"]
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
    rejected = fixture.command(
        "complete-scan", "--cost-json", json.dumps({"usage": usage}), check=False
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
    fixture.write_parent_rollout(
        [
            _event(counted, "event_msg", {"type": "task_started", "turn_id": "scan-turn"}),
            _token_event(counted, 12, 3),
            _event(counted + timedelta(days=1), "event_msg", {"type": "task_complete"}),
        ]
    )
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
    scan_usage, tmp_path: Path, worker: bool, terminal: str, receipt: str
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
    usage = _measure_rollout(
        scan_usage, rollout, started, started, thread_id=thread_id, parent_id=parent_id
    )
    assert usage.tokens == (
        _counts(30, 0, 5) if receipt in {"native", "legacy"} else _counts(10, 0, 2)
    )
    assert usage.warnings == ({"token_record_missing"} if receipt == "none" else set()) | (
        {"turn_interrupted"} if terminal == "turn_aborted" else set()
    )


@pytest.mark.parametrize("receipt", [None, "legacy", "native"])
def test_closed_turn_coverage_retains_before_window_receipt_evidence(
    scan_usage, tmp_path: Path, receipt: str | None
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
    usage = _measure_rollout(scan_usage, rollout, started, started)
    assert usage.tokens == _counts(10, 0, 2)
    assert usage.warnings == (set() if receipt else {"token_record_missing"})


def test_closed_turn_coverage_accepts_delayed_receipt_for_same_turn(
    scan_usage, tmp_path: Path
) -> None:
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
    usage = _measure_rollout(scan_usage, rollout, started, started)
    assert usage.tokens == _counts(10, 0, 2)
    assert usage.warnings == set()


def test_closed_turn_coverage_preserves_interruption_after_same_turn_resumes(
    scan_usage,
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
    usage = _measure_rollout(scan_usage, rollout, started, started)
    assert usage.tokens == _counts(10, 0, 2)
    assert usage.warnings == {"turn_interrupted"}


def test_closed_turn_coverage_ignores_inherited_and_outside_window_interruptions(
    scan_usage,
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
    usage = _measure_rollout(
        scan_usage, rollout, started, started, thread_id="worker", parent_id="scan-parent"
    )
    assert usage.tokens == _counts(10, 0, 2)
    assert usage.warnings == set()


def test_completion_marks_closed_turn_without_receipt_partial(tmp_path: Path) -> None:
    fixture = _start_scan(tmp_path)
    counted = fixture.started_at + timedelta(microseconds=1)
    fixture.write_parent_rollout(
        [
            _event(counted, "event_msg", {"type": "task_started", "turn_id": "empty"}),
            _event(counted, "event_msg", {"type": "task_complete", "turn_id": "empty"}),
            _event(counted, "event_msg", {"type": "task_started", "turn_id": "measured"}),
            _response_event(counted, "scan-parent", "response", 10, 2, turn_id="measured"),
            _event(counted, "event_msg", {"type": "task_complete", "turn_id": "measured"}),
        ]
    )
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
