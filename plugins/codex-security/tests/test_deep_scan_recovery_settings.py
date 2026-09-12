"""Original discovery input and observation remain stable across reconstruction."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest
from workbench_test_support import run_workbench


@pytest.mark.parametrize("original_context", [None, "Audit the original parser"])
def test_reconstruction_preserves_discovery_input_settings_and_deadline(
    tmp_path: Path,
    original_context: str | None,
) -> None:
    target = tmp_path / "target"
    target.mkdir()
    state = tmp_path / "state"
    codex_home = tmp_path / "home"
    config = codex_home / "codex-security" / "config.toml"
    config.parent.mkdir(parents=True)
    config.write_text("[deep_scan]\nworkers = 2\nmax_time_hours = 2.5\n")
    environment = {"CODEX_HOME": str(codex_home)}
    begun = run_workbench(
        state,
        "begin-deep-scan",
        "--thread-id",
        "fixture-thread",
        "--target-path",
        str(target),
        "--scan-root",
        str(tmp_path / "scans"),
        "--model",
        "original-model",
        "--reasoning-effort",
        "high",
        *(["--user-context-stdin"] if original_context is not None else []),
        input_text=original_context,
        environment=environment,
    )["deepScan"]
    scan_id = str(begun["scanId"])
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.execute("UPDATE scans SET user_context = 'Later discussion'")
        connection.execute("UPDATE deep_scan_runs SET updated_at = '2000-01-01T00:00:00Z'")
        before = "\n".join(connection.iterdump())
    config.write_text("[deep_scan]\nworkers = 8\nmax_time_hours = 12\n")
    joined = run_workbench(
        state,
        "begin-deep-scan",
        "--scan-id",
        scan_id,
        "--thread-id",
        "fixture-thread",
        "--model",
        "observer-model",
        "--reasoning-effort",
        "low",
        environment=environment,
    )["deepScan"]
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        assert "\n".join(connection.iterdump()) == before
        assert connection.execute("SELECT model, reasoning_effort FROM scans").fetchone() == (
            "original-model",
            "high",
        )
    recovered = run_workbench(
        state,
        "claim-deep-scan-coordinator",
        "--scan-id",
        scan_id,
        "--thread-id",
        "fixture-thread",
        environment=environment,
    )["deepScan"]
    for run in (joined, recovered):
        assert run["model"] == "original-model"
        assert run["reasoningEffort"] == "high"
        assert run["userContext"] == original_context
        assert run["createdAt"] == begun["createdAt"]
        assert run["config"] == begun["config"]
        assert run["workflowVersion"] == begun["workflowVersion"]


@pytest.mark.parametrize("workflow_version", ["deep-security-scan/v1", "deep-scan-mcp/v1"])
def test_supported_old_run_snapshots_context_on_upgrade(
    tmp_path: Path, workflow_version: str
) -> None:
    target = tmp_path / "target"
    target.mkdir()
    state = tmp_path / "state"
    begun = run_workbench(
        state,
        "begin-deep-scan",
        "--workflow-version",
        workflow_version,
        "--thread-id",
        "fixture-thread",
        "--target-path",
        str(target),
        "--scan-root",
        str(tmp_path / "scans"),
        "--user-context",
        "Legacy context",
    )["deepScan"]
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.execute("ALTER TABLE deep_scan_runs DROP COLUMN discovery_user_context")
        connection.execute("DELETE FROM schema_migrations WHERE version = 44")
    upgraded = run_workbench(
        state,
        "get-deep-scan",
        "--scan-id",
        str(begun["scanId"]),
        "--thread-id",
        "fixture-thread",
    )["deepScan"]
    assert upgraded["workflowVersion"] == workflow_version
    assert upgraded["userContext"] == "Legacy context"
    assert upgraded["config"] == begun["config"]
    assert upgraded["createdAt"] == begun["createdAt"]
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.execute("UPDATE scans SET user_context = 'Later discussion'")
    observed = run_workbench(
        state,
        "get-deep-scan",
        "--scan-id",
        str(begun["scanId"]),
        "--thread-id",
        "fixture-thread",
    )["deepScan"]
    assert observed["userContext"] == "Legacy context"
