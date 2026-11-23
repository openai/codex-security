"""Compatibility checks use real persisted scans and preserve unsupported state."""

from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
import uuid
from pathlib import Path

import pytest
from workbench_test_support import SCRIPT, run_workbench


def start_scan(tmp_path: Path, *args: str, version: str | None = None, **options):
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
        *(["--workflow-version", version] if version else []),
        *args,
        **options,
    )["deepScan"]
    return state, run


def owner_command(state, command, scan_id, *args, **options):
    return run_workbench(
        state, command, "--scan-id", scan_id, "--thread-id", "fixture-thread", *args, **options
    )


def snapshot(state_dir: Path) -> str:
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        return "\n".join(connection.iterdump())


def claim_requiring_original_settings(
    state: Path, scan_id: str
) -> subprocess.CompletedProcess[str]:
    # Exercise the private MCP requirement against both the parent and fixed
    # workbench, without adding a public CLI argument.
    return subprocess.run(
        [
            sys.executable,
            "-c",
            "\n".join(
                [
                    "import runpy, sys",
                    "script = sys.argv.pop(1)",
                    "main = runpy.run_path(script)['main']",
                    "namespace = main.__globals__",
                    "parse = namespace['parse_args']",
                    "def parse_with_requirement(*args, **kwargs):",
                    "    result = parse(*args, **kwargs)",
                    "    result.require_execution_settings = True",
                    "    return result",
                    "namespace['parse_args'] = parse_with_requirement",
                    "main()",
                ]
            ),
            str(SCRIPT),
            "claim-deep-scan-coordinator",
            "--scan-id",
            scan_id,
            "--thread-id",
            "fixture-thread",
        ],
        env={**os.environ, "CODEX_SECURITY_STATE_DIR": str(state)},
        capture_output=True,
        text=True,
        timeout=30,
    )


@pytest.mark.parametrize(
    "workflow,settings_version",
    [
        ("deep-security-scan/v1", 99),
        ("deep-scan-mcp/v1", 99),
        ("deep-security-scan/v2", 99),
        ("deep-security-scan/v2", None),
    ],
)
def test_missing_or_unsupported_settings_reject_before_takeover(
    tmp_path: Path, workflow: str, settings_version: int | None
) -> None:
    state, run = start_scan(tmp_path, version=workflow)
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE deep_scan_runs SET coordinator_generation = 2, "
            "phase = 'discovery', updated_at = '2000-01-01T00:00:00Z'"
        )
    settings_path = Path(run["scanDir"]) / "artifacts/deep_discovery/execution-settings.json"
    saved = None
    if settings_version is not None:
        settings_path.parent.mkdir(parents=True, exist_ok=True)
        saved = json.dumps(
            {
                "version": settings_version,
                "settings": {"codexPath": "/fixture/codex", "codexHome": "/fixture/home"},
            }
        ).encode()
        settings_path.write_bytes(saved)
        with sqlite3.connect(state / "workbench.sqlite3") as connection:
            connection.execute(
                "UPDATE deep_scan_runs SET execution_settings_json = ? WHERE scan_id = ?",
                (saved.decode(), run["scanId"]),
            )
    before = snapshot(state)
    result = claim_requiring_original_settings(state, run["scanId"])
    assert snapshot(state) == before, (
        "settings rejection must precede ownership and worker recovery"
    )
    assert result.returncode != 0
    assert "execution settings" in result.stderr
    assert (settings_path.read_bytes() if settings_path.exists() else None) == saved


@pytest.mark.parametrize("workflow", ["deep-security-scan/v1", "deep-scan-mcp/v1"])
def test_legacy_takeover_does_not_require_or_create_a_new_snapshot(
    tmp_path: Path, workflow: str
) -> None:
    state, run = start_scan(tmp_path, version=workflow)
    result = claim_requiring_original_settings(state, run["scanId"])
    assert result.returncode == 0, result.stderr
    observed = json.loads(result.stdout)["deepScan"]
    assert observed["workflowVersion"] == workflow
    assert observed["config"] == run["config"]
    assert not (Path(run["scanDir"]) / "artifacts/deep_discovery/execution-settings.json").exists()


@pytest.mark.parametrize("completion_only", [False, True])
def test_observation_and_selected_completion_do_not_require_worker_settings(
    tmp_path: Path, completion_only: bool
) -> None:
    state, run = start_scan(tmp_path)
    claim = owner_command(state, "claim-deep-scan-coordinator", run["scanId"])
    if completion_only:
        selection = {
            "version": 1,
            "resultPath": None,
            "resultSha256": None,
            "terminalReason": "capped",
            "omittedWorkerIds": [],
            "selectedAt": run["createdAt"],
        }
        with sqlite3.connect(state / "workbench.sqlite3") as connection:
            connection.execute(
                "UPDATE deep_scan_runs SET finalization_input_json = ?, "
                "updated_at = '2000-01-01T00:00:00Z'",
                (json.dumps(selection),),
            )
    before = snapshot(state)
    result = claim_requiring_original_settings(state, run["scanId"])
    assert result.returncode == 0, result.stderr
    observed = json.loads(result.stdout)
    if completion_only:
        assert observed["coordinatorDisposition"] == "adopted"
        assert observed["deepScan"]["finalizationInput"] == selection
    else:
        assert observed["coordinatorDisposition"] == "observing"
        assert (
            observed["deepScan"]["coordinatorGeneration"]
            == claim["deepScan"]["coordinatorGeneration"]
        )
        assert snapshot(state) == before


@pytest.mark.parametrize(
    "version", ["deep-security-scan/v1", "deep-scan-mcp/v1", "deep-security-scan/v2"]
)
def test_supported_workflows_keep_their_identity(tmp_path: Path, version: str) -> None:
    state, begun = start_scan(tmp_path, version=version)
    claimed = owner_command(state, "claim-deep-scan-coordinator", str(begun["scanId"]))["deepScan"]
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
    state, begun = start_scan(tmp_path)
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
    state, begun = start_scan(tmp_path)
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        columns = {row[1] for row in connection.execute("PRAGMA table_info(deep_scan_runs)")}
        if "discovery_user_context" not in columns:
            connection.execute("ALTER TABLE deep_scan_runs ADD COLUMN discovery_user_context TEXT")
        connection.execute(
            "UPDATE deep_scan_runs SET discovery_user_context = ?, discovery_user_context_json = NULL",
            (original,),
        )
        connection.execute("UPDATE scans SET user_context = 'Later discussion'")
    observed = owner_command(state, "get-deep-scan", str(begun["scanId"]))["deepScan"]
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


@pytest.mark.parametrize("legacy_version", [None, "deep-security-scan/v1", "deep-scan-mcp/v1"])
def test_new_workflow_default_preserves_existing_run_version(
    tmp_path: Path, legacy_version: str | None
) -> None:
    state, created = start_scan(tmp_path, version=legacy_version)
    expected_version = legacy_version or "deep-security-scan/v2"
    assert created["workflowVersion"] == expected_version
    resumed = owner_command(state, "begin-deep-scan", created["scanId"])["deepScan"]
    assert resumed["workflowVersion"] == expected_version
    assert resumed["createdAt"] == created["createdAt"]


def selected_scan(tmp_path: Path, version: int) -> tuple[Path, str, dict[str, object]]:
    state, run = start_scan(tmp_path)
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
    claimed = owner_command(state, "claim-deep-scan-coordinator", scan_id)["deepScan"]
    assert claimed["finalizationInput"] == selected
    assert claimed["phase"] == "reducing"
    assert claimed["coordinatorGeneration"] == 2
    assert claimed["dispatchedCount"] == 0
    assert claimed["createdAt"] == "2000-01-01T00:00:00Z"


@pytest.mark.parametrize("command", ["begin-deep-scan", "claim-deep-scan-coordinator"])
def test_unsupported_selection_rejects_without_mutation(tmp_path: Path, command: str) -> None:
    state, scan_id, selected = selected_scan(tmp_path, 99)
    before = snapshot(state)
    rejected = owner_command(state, command, scan_id, check=False)
    assert rejected["returncode"] != 0
    assert "unsupported" in str(rejected["stderr"]).lower()
    assert snapshot(state) == before
    observed = owner_command(state, "get-deep-scan", scan_id)["deepScan"]
    assert observed["finalizationInput"] == selected


@pytest.mark.parametrize("original_context", [None, "Audit the original parser"])
def test_reconstruction_preserves_discovery_input_settings_and_deadline(
    tmp_path: Path,
    original_context: str | None,
) -> None:
    codex_home = tmp_path / "home"
    config = codex_home / "codex-security" / "config.toml"
    config.parent.mkdir(parents=True)
    config.write_text("[deep_scan]\nworkers = 2\nmax_time_hours = 2.5\n")
    environment = {"CODEX_HOME": str(codex_home)}
    state, begun = start_scan(
        tmp_path,
        "--model",
        "original-model",
        "--reasoning-effort",
        "high",
        *(["--user-context-stdin"] if original_context is not None else []),
        input_text=original_context,
        environment=environment,
    )
    scan_id = str(begun["scanId"])
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.execute("UPDATE scans SET user_context = 'Later discussion'")
        connection.execute("UPDATE deep_scan_runs SET updated_at = '2000-01-01T00:00:00Z'")
        before = "\n".join(connection.iterdump())
    config.write_text("[deep_scan]\nworkers = 8\nmax_time_hours = 12\n")
    joined = owner_command(
        state,
        "begin-deep-scan",
        scan_id,
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
    recovered = owner_command(
        state,
        "claim-deep-scan-coordinator",
        scan_id,
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
    state, begun = start_scan(
        tmp_path, "--user-context", "Legacy context", version=workflow_version
    )
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.execute("ALTER TABLE deep_scan_runs DROP COLUMN discovery_user_context")
        connection.execute("UPDATE deep_scan_runs SET discovery_user_context_json = NULL")
        connection.execute(
            "DELETE FROM schema_migrations WHERE name = ?",
            ("preserve original deep scan discovery context",),
        )
    upgraded = owner_command(state, "get-deep-scan", begun["scanId"])["deepScan"]
    assert upgraded["workflowVersion"] == workflow_version
    assert upgraded["userContext"] == "Legacy context"
    assert upgraded["config"] == begun["config"]
    assert upgraded["createdAt"] == begun["createdAt"]
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.execute("UPDATE scans SET user_context = 'Later discussion'")
    observed = owner_command(state, "get-deep-scan", begun["scanId"])["deepScan"]
    assert observed["userContext"] == "Legacy context"
