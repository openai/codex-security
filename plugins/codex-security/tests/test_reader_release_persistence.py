from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest
from test_workbench_deep_scan import commit_reducer, dispatch_discovery_worker, upsert_worker
from workbench_test_support import SCRIPT, run_workbench


def introduced_metadata(state: Path, scan_dir: Path) -> dict:
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.row_factory = sqlite3.Row
        tables = {
            row[0]
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        counts = {
            name: connection.execute(f"SELECT COUNT(*) FROM {name}").fetchone()[0]
            for name in (
                "deep_scan_attempts",
                "deep_scan_attempt_sessions",
                "deep_scan_merge_claims",
            )
            if name in tables
        }
        run = connection.execute("SELECT * FROM deep_scan_runs").fetchone()
        context = {
            name: run[name]
            for name in (
                "discovery_user_context",
                "usage_owner_json",
                "finalization_input_json",
                "execution_settings_json",
            )
            if name in run.keys()
        }
        inputs = list(connection.execute("SELECT * FROM deep_scan_dedup_inputs"))
        references = [
            {
                name: row[name]
                for name in ("result_manifest_path", "result_manifest_sha256", "attempt")
                if name in row.keys() and row[name] is not None
            }
            for row in inputs
        ]
    return {
        "tables": counts,
        "run": context,
        "input_references": [row for row in references if row],
        "accepted_copies": sorted(
            str(path.relative_to(scan_dir)) for path in scan_dir.rglob("checkpoints/*.json")
        ),
    }


@pytest.mark.parametrize("version", ["deep-security-scan/v1", "deep-scan-mcp/v1"])
def test_legacy_execution_defers_new_persistence(tmp_path: Path, version: str) -> None:
    state, home, target = tmp_path / "state", tmp_path / "codex", tmp_path / "target"
    target.mkdir()
    (home / "codex-security").mkdir(parents=True)
    (home / "codex-security/config.toml").write_text("[deep_scan]\nmax_time_hours = 3\n")
    run = run_workbench(
        state,
        "begin-deep-scan",
        "--thread-id",
        "reader-owner",
        "--target-path",
        str(target),
        "--scan-root",
        str(tmp_path / "scans"),
        "--workflow-version",
        version,
        "--user-context",
        "Review the supplied input.",
        environment={"CODEX_HOME": str(home)},
    )["deepScan"]
    scan_id, scan_dir = run["scanId"], Path(run["scanDir"])
    stages = {"begin": introduced_metadata(state, scan_dir)}
    workers = []
    for index in range(2):
        worker, prompt, artifacts, result = dispatch_discovery_worker(
            state,
            home,
            scan_id=scan_id,
            scan_dir=scan_dir,
            name=f"discovery-{index}",
            succeed=False,
        )
        upsert_worker(
            state,
            home,
            scan_id=scan_id,
            worker_id=worker,
            kind="discovery",
            status="running",
            prompt_path=prompt,
            artifact_dir=artifacts,
            attempt=2,
            thread_id=f"replacement-{index}",
        )
        result.write_text("{}\n")
        upsert_worker(
            state,
            home,
            scan_id=scan_id,
            worker_id=worker,
            kind="discovery",
            status="succeeded",
            prompt_path=prompt,
            artifact_dir=artifacts,
            attempt=2,
            thread_id=f"replacement-{index}",
            result_path=result,
        )
        workers.append(worker)
    stages["discovery"] = introduced_metadata(state, scan_dir)
    committed = commit_reducer(
        state,
        home,
        scan_id=scan_id,
        scan_dir=scan_dir,
        name="dedup-1",
        input_worker_ids=workers,
        new_findings_count=0,
    )
    stages["merge"] = introduced_metadata(state, scan_dir)
    assert committed["noNewStreak"] == 2
    assert [item["discoveryWorkerId"] for item in committed["dedupInputs"]] == workers
    assert all(
        item["mergeState"] == "merged"
        for item in committed["workers"]
        if item["kind"] == "discovery"
    )
    stopped = run_workbench(
        state,
        "fail-deep-scan",
        "--scan-id",
        scan_id,
        "--message",
        "Original reader stop.",
        environment={"CODEX_HOME": str(home)},
    )["deepScan"]
    stages["stop"] = introduced_metadata(state, scan_dir)
    assert stopped["status"] == "failed"
    assert "Original reader stop." in stopped["error"]
    assert stopped["workflowVersion"] == version
    assert stopped["createdAt"] == run["createdAt"]
    assert stopped["config"]["maxTimeHours"] == 3
    assert stopped["userContext"] == "Review the supplied input."
    print(json.dumps({"version": version, "stages": stages}, sort_keys=True))
    for stage in stages.values():
        assert all(count == 0 for count in stage["tables"].values()), stages
        assert all(value is None for value in stage["run"].values()), stages
        assert stage["input_references"] == [], stages
        assert stage["accepted_copies"] == [], stages


def test_upgraded_context_schema_rejects_creation_before_mutation(tmp_path: Path) -> None:
    state, target, next_target = tmp_path / "state", tmp_path / "target", tmp_path / "next"
    target.mkdir()
    next_target.mkdir()
    scan_root = tmp_path / "scans"
    environment = {"CODEX_HOME": str(tmp_path / "home")}
    run_workbench(
        state,
        "begin-deep-scan",
        "--thread-id",
        "reader-owner",
        "--target-path",
        str(target),
        "--scan-root",
        str(scan_root),
        environment=environment,
    )
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        # An upgraded database distinguishes captured NULL from an uncaptured legacy field.
        connection.execute("ALTER TABLE deep_scan_runs ADD COLUMN discovery_user_context TEXT")
        before = "\n".join(connection.iterdump())
    before_paths = sorted(str(path.relative_to(scan_root)) for path in scan_root.rglob("*"))
    rejected = run_workbench(
        state,
        "begin-deep-scan",
        "--thread-id",
        "reader-owner",
        "--target-path",
        str(next_target),
        "--scan-root",
        str(scan_root),
        "--user-context",
        "Explicit new review input.",
        check=False,
        environment=environment,
    )
    assert rejected["returncode"] != 0
    assert "newer version" in rejected["stderr"]
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        assert "\n".join(connection.iterdump()) == before
    assert sorted(str(path.relative_to(scan_root)) for path in scan_root.rglob("*")) == before_paths


def test_selected_replay_keeps_publication_path_validation(tmp_path: Path) -> None:
    state, target = tmp_path / "state", tmp_path / "target"
    target.mkdir()
    environment = {"CODEX_HOME": str(tmp_path / "home")}
    run = run_workbench(
        state,
        "begin-deep-scan",
        "--thread-id",
        "reader-owner",
        "--target-path",
        str(target),
        "--scan-root",
        str(tmp_path / "scans"),
        environment=environment,
    )["deepScan"]
    selection = {
        "version": 1,
        "resultPath": None,
        "resultSha256": None,
        "terminalReason": "capped",
        "omittedWorkerIds": [],
        "selectedAt": "2000-01-01T00:00:00Z",
    }
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE deep_scan_runs SET workflow_version = 'deep-security-scan/v2', "
            "finalization_input_json = ?, phase = 'terminal', "
            "created_at = '2000-01-01T00:00:00Z'",
            (json.dumps(selection),),
        )
        before = "\n".join(connection.iterdump())
    rejected = subprocess.run(
        [
            sys.executable,
            "-I",
            "-B",
            "-c",
            "import runpy,sys; p=sys.argv.pop(1); runpy.run_path(p)['main'](select_finalization=True)",
            str(SCRIPT),
            "finish-deep-scan",
            "--scan-id",
            run["scanId"],
            "--terminal-reason",
            "capped",
            "--manifest-path",
            str(Path(run["scanDir"]) / "wrong-manifest.json"),
        ],
        capture_output=True,
        text=True,
        input=json.dumps({"resultPath": None}),
        env={**os.environ, **environment, "CODEX_SECURITY_STATE_DIR": str(state)},
    )
    assert rejected.returncode != 0
    assert "parent manifest" in rejected.stderr
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        assert "\n".join(connection.iterdump()) == before
