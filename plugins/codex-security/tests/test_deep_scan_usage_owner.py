from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
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


@pytest.mark.parametrize("migrated", [False, True])
@pytest.mark.parametrize("attempt", [False, True])
def test_migrated_owner_accounting_survives_first_worker_attempt(
    tmp_path: Path, migrated: bool, attempt: bool, workbench_api, monkeypatch
) -> None:
    from workbench_scan_usage import collect_scan_usage, scan_execution_attribution

    state = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    environment = {
        "CODEX_HOME": str(tmp_path / "codex"),
        "CODEX_SQLITE_HOME": str(tmp_path / "native"),
        "CODEX_STATE_DB": "",
    }
    timestamp = datetime.now(timezone.utc)
    parent = _rollout(
        tmp_path,
        "legacy-owner",
        [
            _event(timestamp, "turn_context", {"turn_id": "original-turn", "model": "gpt-5.6-sol"}),
        ],
    )
    _state_graph(environment, {"legacy-owner": parent}, [])
    begun = run_workbench(
        state,
        "begin-deep-scan",
        "--thread-id",
        "legacy-owner",
        "--target-path",
        str(target),
        "--scan-root",
        str(tmp_path / "scans"),
        environment=environment,
    )["deepScan"]
    database = state / "workbench.sqlite3"
    if migrated:
        # The usage-owner migration adds a nullable owner without an original turn binding.
        with sqlite3.connect(database) as connection:
            connection.execute("ALTER TABLE deep_scan_runs DROP COLUMN usage_owner_json")
            connection.execute(
                "DELETE FROM schema_migrations WHERE name = ?",
                ("bind original deep scan parent usage turn",),
            )
        run_workbench(
            state,
            "get-deep-scan",
            "--scan-id",
            begun["scanId"],
            "--thread-id",
            "legacy-owner",
            environment=environment,
        )
    if attempt:
        artifact = Path(begun["scanDir"]) / "artifacts" / "first-worker"
        artifact.mkdir(parents=True)
        prompt = artifact / "prompt.md"
        prompt.write_text("Review the synthetic target.\n")
        run_workbench(
            state,
            "upsert-deep-scan-worker",
            "--scan-id",
            begun["scanId"],
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
            environment=environment,
        )
    counted = datetime.fromisoformat(begun["createdAt"].replace("Z", "+00:00")) + timedelta(
        microseconds=1
    )
    _rollout(
        tmp_path,
        "legacy-owner",
        [
            _event(
                counted,
                "event_msg",
                {
                    "type": "task_started",
                    "turn_id": "original-turn",
                    "started_at": int(counted.timestamp()),
                },
            ),
            _event(counted, "turn_context", {"turn_id": "original-turn", "model": "gpt-5.6-sol"}),
            _token_event(counted, 100, 10),
        ],
        task_started_at=counted,
    )
    for name, value in environment.items():
        monkeypatch.setenv(name, value)
    with sqlite3.connect(database) as connection:
        connection.row_factory = sqlite3.Row
        scan = workbench_api["require_scan"](connection, begun["scanId"])
        attribution = scan_execution_attribution(connection, scan)
        assert bool(attribution.get("legacy")) is migrated
        usage = collect_scan_usage(connection, scan)
    assert usage["inputTokens"] == 100
    assert usage["outputTokens"] == 10
