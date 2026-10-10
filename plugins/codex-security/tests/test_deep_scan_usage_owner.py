from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

from test_workbench_scan_usage import _event, _rollout, _state_graph, _token_event
from workbench_test_support import run_workbench


def test_original_usage_turn_survives_join_and_coordinator_recovery(tmp_path: Path) -> None:
    state = tmp_path / "state"
    environment = {
        "CODEX_HOME": str(tmp_path / "codex"),
        "CODEX_SQLITE_HOME": str(tmp_path / "native"),
        "CODEX_STATE_DB": "",
    }
    timestamp = datetime.now(timezone.utc)
    rollout = _rollout(
        tmp_path,
        "shared-parent",
        [
            _event(timestamp, "turn_context", {"turn_id": "original-turn", "model": "gpt-5.6-sol"}),
        ],
    )
    _state_graph(environment, {"shared-parent": rollout}, [])
    target = tmp_path / "target"
    target.mkdir()
    begun = run_workbench(
        state,
        "begin-deep-scan",
        "--thread-id",
        "shared-parent",
        "--target-path",
        str(target),
        "--scope",
        ".",
        "--scan-root",
        str(tmp_path / "scans"),
        environment=environment,
    )["deepScan"]
    # A writer recorded the original turn; joining and recovery only read it.
    owner = {
        "threadId": "shared-parent",
        "turnId": "original-turn",
        "startedAt": begun["createdAt"],
        "dedicated": False,
    }
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE deep_scan_runs SET usage_owner_json = ? WHERE scan_id = ?",
            (json.dumps(owner), begun["scanId"]),
        )
    observed = run_workbench(
        state,
        "get-deep-scan",
        "--scan-id",
        begun["scanId"],
        "--thread-id",
        "shared-parent",
        environment=environment,
    )["deepScan"]
    assert observed["usageOwner"] == owner
    assert owner["threadId"] == "shared-parent"
    assert owner["turnId"] == "original-turn"
    assert owner["dedicated"] is False
    rollout.write_text(
        rollout.read_text()
        + json.dumps(
            _event(timestamp, "turn_context", {"turn_id": "later-turn", "model": "gpt-6-astra"})
        )
        + "\n"
    )
    joined = run_workbench(
        state,
        "begin-deep-scan",
        "--scan-id",
        begun["scanId"],
        "--thread-id",
        "shared-parent",
        environment=environment,
    )["deepScan"]
    assert joined["usageOwner"] == owner
    claim_args = [
        "claim-deep-scan-coordinator",
        "--scan-id",
        begun["scanId"],
        "--thread-id",
        "shared-parent",
    ]
    claimed = run_workbench(state, *claim_args, environment=environment)["deepScan"]
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE deep_scan_runs SET updated_at = '2000-01-01T00:00:00+00:00' WHERE scan_id = ?",
            (begun["scanId"],),
        )
    recovered = run_workbench(state, *claim_args, environment=environment)["deepScan"]
    assert recovered["coordinatorGeneration"] == claimed["coordinatorGeneration"] + 1
    assert recovered["usageOwner"] == owner
    other_target = tmp_path / "other-target"
    other_target.mkdir()
    other = run_workbench(
        state,
        "begin-deep-scan",
        "--thread-id",
        "shared-parent",
        "--target-path",
        str(other_target),
        "--scope",
        ".",
        "--scan-root",
        str(tmp_path / "scans"),
        environment=environment,
    )["deepScan"]
    other_owner = {**owner, "turnId": "later-turn", "startedAt": other["createdAt"]}
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE deep_scan_runs SET usage_owner_json = ? WHERE scan_id = ?",
            (json.dumps(other_owner), other["scanId"]),
        )
    other = run_workbench(
        state,
        "get-deep-scan",
        "--scan-id",
        other["scanId"],
        "--thread-id",
        "shared-parent",
        environment=environment,
    )["deepScan"]
    assert other["usageOwner"]["turnId"] == "later-turn"
    original = run_workbench(
        state, "get-scan", "--scan-id", begun["scanId"], environment=environment
    )["scan"]
    assert original["executionAttribution"]["owner"] == owner


def test_registered_cli_parent_usage_precedes_coordinator_registration(
    tmp_path: Path, workbench_api, monkeypatch
) -> None:
    state = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    (target / "app.py").write_text("# Synthetic target\n")
    scan_dir = tmp_path / "scan"
    scan_dir.mkdir(mode=0o700)
    environment = {
        "CODEX_HOME": str(tmp_path / "codex"),
        "CODEX_SQLITE_HOME": str(tmp_path / "native"),
        "CODEX_STATE_DB": "",
    }
    registered = run_workbench(
        state,
        "register-cli-scan",
        "--repository",
        str(target),
        "--scan-dir",
        str(scan_dir),
        "--recipe-json",
        json.dumps(
            {
                "config": {},
                "mode": "deep",
                "repository": str(target),
                "target": {"kind": "repository", "paths": []},
            }
        ),
        environment=environment,
    )
    scan_id = registered["scanId"]
    before = run_workbench(state, "get-scan", "--scan-id", scan_id, environment=environment)["scan"]
    assert before["executionAttribution"] is None
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        started = datetime.fromisoformat(
            connection.execute("SELECT started_at FROM scans WHERE id = ?", (scan_id,))
            .fetchone()[0]
            .replace("Z", "+00:00")
        )
        assert connection.execute("SELECT COUNT(*) FROM deep_scan_runs").fetchone()[0] == 0
    parent = _rollout(
        tmp_path,
        "cli-parent",
        [
            _event(
                started - timedelta(seconds=2),
                "turn_context",
                {"turn_id": "scan-turn", "model": "gpt-5.6-sol"},
            ),
            _token_event(started - timedelta(seconds=1), 900, 0),
            _token_event(started + timedelta(seconds=1), 1000, 0),
        ],
    )
    unrelated = _rollout(
        tmp_path,
        "other-parent",
        [
            _token_event(started + timedelta(seconds=1), 5000, 0),
        ],
    )
    _state_graph(environment, {"cli-parent": parent, "other-parent": unrelated}, [])
    run_workbench(
        state,
        "set-scan-thread",
        "--scan-id",
        scan_id,
        "--thread-id",
        "cli-parent",
        environment=environment,
    )
    scan = run_workbench(state, "get-scan", "--scan-id", scan_id, environment=environment)["scan"]
    attribution = scan["executionAttribution"]
    assert attribution["owner"]["threadId"] == "cli-parent"
    assert attribution["executionThreadIds"] == ["cli-parent"]
    for name, value in environment.items():
        monkeypatch.setenv(name, value)
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.row_factory = sqlite3.Row
        row = connection.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        private = {"scan": scan}
        workbench_api["deep_scan"].include_execution_settings(connection, private)
        assert "codexHome" not in private["scan"]["executionAttribution"]
        usage = workbench_api["scan_usage"].collect_scan_usage(connection, row)
    assert usage["inputTokens"] == 100
    assert usage["totalTokens"] == 100
