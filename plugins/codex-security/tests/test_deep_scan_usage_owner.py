from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from test_workbench_scan_usage import _event, _rollout, _state_graph
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
    owner = begun["usageOwner"]
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
    assert other["usageOwner"]["turnId"] == "later-turn"
    original = run_workbench(
        state, "get-scan", "--scan-id", begun["scanId"], environment=environment
    )["scan"]
    assert original["executionAttribution"]["owner"] == owner
