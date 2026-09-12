"""Compatibility checks use real persisted scans and preserve unsupported state."""

from __future__ import annotations

import json
import sqlite3
import uuid
from pathlib import Path

import pytest
from workbench_test_support import run_workbench


def snapshot(state_dir: Path) -> str:
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        return "\n".join(connection.iterdump())


@pytest.mark.parametrize("version", ["deep-security-scan/v1", "deep-scan-mcp/v1"])
def test_supported_workflows_keep_their_identity(tmp_path: Path, version: str) -> None:
    target = tmp_path / "target"
    target.mkdir()
    state = tmp_path / "state"
    begun = run_workbench(
        state,
        "begin-deep-scan",
        "--thread-id",
        "fixture-thread",
        "--target-path",
        str(target),
        "--scan-root",
        str(tmp_path / "scans"),
        "--workflow-version",
        version,
    )["deepScan"]
    claimed = run_workbench(
        state,
        "claim-deep-scan-coordinator",
        "--scan-id",
        str(begun["scanId"]),
        "--thread-id",
        "fixture-thread",
    )["deepScan"]
    assert claimed["workflowVersion"] == version
    assert claimed["schemaVersion"] == 1
    assert claimed["noNewStreak"] == begun["noNewStreak"]
    assert claimed["config"] == begun["config"]


@pytest.mark.parametrize("field,value", [("workflow_version", "future/v99")])
@pytest.mark.parametrize("operation", ["begin", "claim", "handoff"])
def test_unsupported_execution_does_not_mutate(
    tmp_path: Path,
    field: str,
    value: str | int,
    operation: str,
) -> None:
    target = tmp_path / "target"
    target.mkdir()
    state = tmp_path / "state"
    begun = run_workbench(
        state,
        "begin-deep-scan",
        "--thread-id",
        "fixture-thread",
        "--target-path",
        str(target),
        "--scan-root",
        str(tmp_path / "scans"),
    )["deepScan"]
    scan_id = str(begun["scanId"])
    if operation == "claim":
        artifact_dir = Path(str(begun["scanDir"])) / "artifacts" / "deep_discovery" / "worker"
        artifact_dir.mkdir(parents=True)
        prompt = artifact_dir / "prompt.md"
        prompt.write_text("Original discovery input")
        run_workbench(
            state,
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
            str(artifact_dir),
            "--attempt",
            "1",
        )
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.execute(
            f"UPDATE deep_scan_runs SET {field} = ?, updated_at = ?",
            (value, "2000-01-01T00:00:00Z"),
        )
        if operation == "handoff":
            connection.execute(
                "UPDATE scans SET deep_scan_owner_thread_id = NULL, recipe_json = '{}'"
            )
            connection.execute("UPDATE workspaces SET thread_id = NULL")
    before = snapshot(state)
    command = "claim-deep-scan-coordinator" if operation == "claim" else "begin-deep-scan"
    result = run_workbench(
        state,
        command,
        "--scan-id",
        scan_id,
        "--thread-id",
        "fixture-thread",
        *(["--model", "observer-model"] if operation != "claim" else []),
        check=False,
    )
    assert result["returncode"] != 0
    assert "unsupported" in str(result["stderr"]).lower()
    assert snapshot(state) == before
    if operation != "handoff":
        observed = run_workbench(
            state, "get-deep-scan", "--scan-id", scan_id, "--thread-id", "fixture-thread"
        )["deepScan"]
        assert (
            observed["workflowVersion" if field == "workflow_version" else "schemaVersion"] == value
        )
        assert snapshot(state) == before


@pytest.mark.parametrize("original", [None, "Original discovery context"])
def test_reader_honors_original_context_when_present(tmp_path: Path, original: str | None) -> None:
    target = tmp_path / "target"
    target.mkdir()
    state = tmp_path / "state"
    begun = run_workbench(
        state,
        "begin-deep-scan",
        "--thread-id",
        "fixture-thread",
        "--target-path",
        str(target),
        "--scan-root",
        str(tmp_path / "scans"),
    )["deepScan"]
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        columns = {row[1] for row in connection.execute("PRAGMA table_info(deep_scan_runs)")}
        if "discovery_user_context" not in columns:
            connection.execute("ALTER TABLE deep_scan_runs ADD COLUMN discovery_user_context TEXT")
        connection.execute("UPDATE deep_scan_runs SET discovery_user_context = ?", (original,))
        connection.execute("UPDATE scans SET user_context = 'Later discussion'")
    observed = run_workbench(
        state,
        "get-deep-scan",
        "--scan-id",
        str(begun["scanId"]),
        "--thread-id",
        "fixture-thread",
    )["deepScan"]
    assert observed["userContext"] == original


def test_unsupported_new_workflow_does_not_claim_registered_scan(tmp_path: Path) -> None:
    state = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    scan_dir = tmp_path / "scan"
    scan_dir.mkdir(mode=0o700)
    registered = run_workbench(
        state,
        "register-cli-scan",
        "--scan-dir",
        str(scan_dir),
        "--repository",
        str(target),
        "--registration-json-stdin",
        input_text=json.dumps(
            {
                "recipe": {
                    "config": {},
                    "mode": "deep",
                    "repository": str(target),
                    "target": {"kind": "repository", "paths": []},
                }
            }
        ),
    )
    before = snapshot(state)
    rejected = run_workbench(
        state,
        "begin-deep-scan",
        "--scan-id",
        str(registered["scanId"]),
        "--thread-id",
        "fixture-thread",
        "--workflow-version",
        "future/v99",
        check=False,
    )
    assert rejected["returncode"] != 0
    assert "unsupported" in str(rejected["stderr"]).lower()
    assert snapshot(state) == before
