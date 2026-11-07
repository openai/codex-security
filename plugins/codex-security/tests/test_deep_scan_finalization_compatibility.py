"""Selected finalization survives ownership recovery without restarting discovery."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest
from workbench_test_support import run_workbench


@pytest.mark.parametrize("legacy_version", [None, "deep-security-scan/v1", "deep-scan-mcp/v1"])
def test_new_workflow_default_preserves_existing_run_version(
    tmp_path: Path, legacy_version: str | None
) -> None:
    target = tmp_path / "target"
    target.mkdir()
    state = tmp_path / "state"
    created = run_workbench(
        state,
        "begin-deep-scan",
        "--thread-id",
        "fixture-thread",
        "--target-path",
        str(target),
        "--scan-root",
        str(tmp_path / "scans"),
        *(["--workflow-version", legacy_version] if legacy_version else []),
    )["deepScan"]
    expected_version = legacy_version or "deep-security-scan/v2"
    assert created["workflowVersion"] == expected_version
    resumed = run_workbench(
        state,
        "begin-deep-scan",
        "--scan-id",
        created["scanId"],
        "--thread-id",
        "fixture-thread",
    )["deepScan"]
    assert resumed["workflowVersion"] == expected_version
    assert resumed["createdAt"] == created["createdAt"]


def selected_scan(tmp_path: Path, version: int) -> tuple[Path, str, dict[str, object]]:
    target = tmp_path / "target"
    target.mkdir()
    state = tmp_path / "state"
    run = run_workbench(
        state,
        "begin-deep-scan",
        "--thread-id",
        "fixture-thread",
        "--target-path",
        str(target),
        "--scan-root",
        str(tmp_path / "scans"),
    )["deepScan"]
    selected = {
        "version": version,
        "resultPath": None,
        "resultSha256": None,
        "terminalReason": "capped",
        "omittedWorkerIds": [],
        "selectedAt": "2000-01-01T00:00:00Z",
    }
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        columns = {row[1] for row in connection.execute("PRAGMA table_info(deep_scan_runs)")}
        if "finalization_input_json" not in columns:
            connection.execute("ALTER TABLE deep_scan_runs ADD COLUMN finalization_input_json TEXT")
        connection.execute(
            "UPDATE deep_scan_runs SET workflow_version = 'deep-security-scan/v2', "
            "finalization_input_json = ?, phase = 'reducing', "
            "created_at = '2000-01-01T00:00:00Z', updated_at = '2000-01-01T00:00:00Z'",
            (json.dumps(selected),),
        )
    return state, str(run["scanId"]), selected


def test_claim_preserves_selected_finalization_without_discovery_recovery(tmp_path: Path) -> None:
    state, scan_id, selected = selected_scan(tmp_path, 1)
    claimed = run_workbench(
        state,
        "claim-deep-scan-coordinator",
        "--scan-id",
        scan_id,
        "--thread-id",
        "fixture-thread",
    )["deepScan"]
    assert claimed["finalizationInput"] == selected
    assert claimed["phase"] == "reducing"
    assert claimed["coordinatorGeneration"] == 2
    assert claimed["dispatchedCount"] == 0
    assert claimed["createdAt"] == "2000-01-01T00:00:00Z"


@pytest.mark.parametrize("command", ["begin-deep-scan", "claim-deep-scan-coordinator"])
def test_unsupported_selection_rejects_without_mutation(tmp_path: Path, command: str) -> None:
    state, scan_id, selected = selected_scan(tmp_path, 99)
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        before = "\n".join(connection.iterdump())
    rejected = run_workbench(
        state,
        command,
        "--scan-id",
        scan_id,
        "--thread-id",
        "fixture-thread",
        check=False,
    )
    assert rejected["returncode"] != 0
    assert "unsupported" in str(rejected["stderr"]).lower()
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        assert "\n".join(connection.iterdump()) == before
    observed = run_workbench(
        state,
        "get-deep-scan",
        "--scan-id",
        scan_id,
        "--thread-id",
        "fixture-thread",
    )["deepScan"]
    assert observed["finalizationInput"] == selected
