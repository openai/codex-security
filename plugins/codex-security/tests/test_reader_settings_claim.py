"""Recorded settings are checked before an expired coordinator changes state."""

from __future__ import annotations

import datetime
import json
import sqlite3
import uuid
from pathlib import Path

import pytest
from workbench_test_support import run_workbench


def database_snapshot(state: Path) -> str:
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        return "\n".join(connection.iterdump())


@pytest.mark.parametrize(
    "version", ["deep-security-scan/v1", "deep-scan-mcp/v1", "deep-security-scan/v2"]
)
@pytest.mark.parametrize("saved", ["unsupported", "missing-home", "valid", "absent"])
@pytest.mark.parametrize("live", [False, True], ids=["expired-owner", "live-observer"])
def test_reader_checks_recorded_settings_before_adoption(
    tmp_path: Path, version: str, saved: str, live: bool
) -> None:
    state, target = tmp_path / "state", tmp_path / "target"
    target.mkdir()
    run = run_workbench(
        state,
        "begin-deep-scan",
        "--thread-id",
        "original-thread",
        "--target-path",
        str(target),
        "--scan-root",
        str(tmp_path / "scans"),
        "--workflow-version",
        "deep-security-scan/v1" if version == "deep-security-scan/v2" else version,
    )["deepScan"]
    scan_dir = Path(run["scanDir"])
    worker_dir = scan_dir / "artifacts" / "deep_discovery" / "worker"
    worker_dir.mkdir(parents=True)
    prompt = worker_dir / "prompt.md"
    prompt.write_text("Original discovery input")
    run_workbench(
        state,
        "upsert-deep-scan-worker",
        "--scan-id",
        run["scanId"],
        "--worker-id",
        str(uuid.uuid4()),
        "--kind",
        "discovery",
        "--status",
        "running",
        "--prompt-path",
        str(prompt),
        "--artifact-dir",
        str(worker_dir),
        "--attempt",
        "1",
    )
    path = worker_dir.parent / "execution-settings.json"
    if saved != "absent":
        settings = {"codexPath": "/fixture/codex", "codexHome": "/fixture/original-home"}
        if saved == "missing-home":
            del settings["codexHome"]
        path.write_text(
            json.dumps({"version": 99 if saved == "unsupported" else 1, "settings": settings})
        )
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.execute("UPDATE deep_scan_runs SET workflow_version = ?", (version,))
        if version == "deep-security-scan/v2" and saved != "absent":
            connection.execute(
                "UPDATE deep_scan_runs SET execution_settings_json = ?", (path.read_text(),)
            )
        connection.execute(
            "UPDATE deep_scan_runs SET coordinator_generation = 2, updated_at = ?",
            (
                datetime.datetime.now(datetime.timezone.utc).isoformat()
                if live
                else "2000-01-01T00:00:00Z",
            ),
        )
    before = database_snapshot(state)
    files = {
        item.relative_to(scan_dir): item.read_bytes()
        for item in scan_dir.rglob("*")
        if item.is_file()
    }
    rejects = version == "deep-security-scan/v2"
    result = run_workbench(
        state,
        "claim-deep-scan-coordinator",
        "--scan-id",
        run["scanId"],
        "--thread-id",
        "original-thread",
        check=not rejects,
    )
    if rejects:
        assert result["returncode"] != 0
        assert "newer version to resume execution" in result["stderr"]
        assert database_snapshot(state) == before
    else:
        observed = result
        assert observed["coordinatorDisposition"] == ("observing" if live else "adopted")
        assert observed["deepScan"]["workflowVersion"] == version
        if live:
            assert database_snapshot(state) == before
    assert {
        item.relative_to(scan_dir): item.read_bytes()
        for item in scan_dir.rglob("*")
        if item.is_file()
    } == files


@pytest.mark.parametrize("workflow", ["deep-security-scan/v1", "deep-security-scan/v2"])
@pytest.mark.parametrize("bound", [False, True])
def test_reader_private_settings_projection_preserves_public_output(
    tmp_path: Path, workflow: str, bound: bool
) -> None:
    import os
    import subprocess
    import sys

    from workbench_test_support import SCRIPT

    state, target = tmp_path / "state", tmp_path / "target"
    target.mkdir()
    run = run_workbench(
        state,
        "begin-deep-scan",
        "--thread-id",
        "reader-owner",
        "--target-path",
        str(target),
        "--scan-root",
        str(tmp_path / "scans"),
    )["deepScan"]
    settings = {
        "version": 1,
        "settings": {"codexPath": "/fixture/codex", "codexHome": "/fixture/original-home"},
    }
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        assert connection.execute(
            "SELECT execution_settings_json FROM deep_scan_runs"
        ).fetchone() == (None,), "the reader does not write creation settings"
        connection.execute(
            "UPDATE deep_scan_runs SET workflow_version = ?, execution_settings_json = ?",
            (workflow, json.dumps(settings) if bound else None),
        )
    before = database_snapshot(state)
    args = ["get-deep-scan", "--scan-id", run["scanId"], "--thread-id", "reader-owner"]
    public = run_workbench(state, *args)
    assert "executionSettings" not in public["deepScan"]
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import runpy, sys; script=sys.argv.pop(1); "
                "runpy.run_path(script)['main'](with_execution_settings=True)"
            ),
            str(SCRIPT),
            *args,
        ],
        env={**os.environ, "CODEX_SECURITY_STATE_DIR": str(state)},
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    private = json.loads(result.stdout)
    assert private["deepScan"].pop("executionSettings") == (settings if bound else None)
    assert private == public
    assert database_snapshot(state) == before
    assert not (Path(run["scanDir"]) / "artifacts/deep_discovery/execution-settings.json").exists()
