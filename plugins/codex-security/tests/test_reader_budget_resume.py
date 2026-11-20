"""Budget recovery accepts and replays compatible selections through the reader CLI."""

from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
from argparse import Namespace
from functools import partial

import pytest
import workbench_test_support
from test_stopped_result_version_boundary import snapshot
from test_workbench_db import BUDGET_COST, BUDGET_WARNING, budget_scan_fixture


@pytest.fixture
def reader_command(workbench_api, monkeypatch, tmp_path):
    script = str(workbench_api["__file__"])
    monkeypatch.setattr(workbench_test_support, "SCRIPT", script)
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "home"))

    def run(state_dir, *args, program=None):
        launcher = [] if program is None else ["-c", program]
        return subprocess.run(
            [sys.executable, "-I", "-B", *launcher, script, *args],
            env={**os.environ, "CODEX_SECURITY_STATE_DIR": str(state_dir)},
            capture_output=True,
            text=True,
        )

    return run


def budget_snapshot(database, scan_dir):
    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT COUNT(*) FROM deep_scan_attempts").fetchone() == (0,)
        sessions = connection.execute("SELECT COUNT(*) FROM deep_scan_attempt_sessions")
        assert sessions.fetchone() == (0,)
        return snapshot(connection, scan_dir)


@pytest.mark.parametrize(
    "state",
    [
        "selected-budget",
        "legacy-finished",
        "parent-canceled",
        "stopping",
        "failed",
        "canceled",
        "unselected",
    ],
)
def test_reader_resume_consumes_saved_selection_without_writes(
    workbench_api, workbench_db, publication_scan, tmp_path, reader_command, state
):
    scan = publication_scan()
    thread = "a23e657b-c14c-4da7-bd20-baa9e7579390"
    workbench_api["set_scan_thread"](
        workbench_db, Namespace(scan_id=scan.scan_id, thread_id=thread)
    )
    selection = json.dumps(
        {
            "version": 1,
            "resultPath": None,
            "resultSha256": None,
            "terminalReason": "capped",
            "omittedWorkerIds": [],
            "selectedAt": scan.timestamp,
        }
    )
    with workbench_db:
        workbench_db.execute(
            "UPDATE deep_scan_runs SET status = ?, cancel_requested = ?, "
            "workflow_version = ?, finalization_input_json = ?",
            (
                "running"
                if state == "stopping"
                else state
                if state in {"failed", "canceled"}
                else "succeeded",
                int(state != "legacy-finished"),
                "deep-security-scan/v1" if state == "legacy-finished" else "deep-security-scan/v2",
                selection if state == "selected-budget" else None,
            ),
        )
        if state == "parent-canceled":
            workbench_db.execute("UPDATE scans SET canceled_at = ?", (scan.timestamp,))
    state_dir = tmp_path / "state"
    state_dir.mkdir(mode=0o700)
    with sqlite3.connect(state_dir / "workbench.sqlite3") as disk:
        workbench_db.backup(disk)
    before = snapshot(workbench_db, scan.scan_dir)
    result = reader_command(state_dir, "get-cli-scan-resume", "--scan-id", scan.scan_id)
    after = budget_snapshot(state_dir / "workbench.sqlite3", scan.scan_dir)
    assert after == before
    if state in {"selected-budget", "legacy-finished"}:
        assert result.returncode == 0, result.stderr
        assert json.loads(result.stdout)["scanId"] == scan.scan_id
        assert json.loads(result.stdout)["threadId"] == thread
    else:
        assert result.returncode != 0
        assert "cannot resume" in result.stderr


@pytest.mark.parametrize("cost_kind", ["full", "lower-bound", "invalid", "unexceeded", "ordinary"])
def test_reader_budget_cost_preserves_unknown_totals(reader_command, tmp_path, cost_kind):
    state_dir, _, scan_dir, scan_id, _ = budget_scan_fixture(tmp_path)
    database = state_dir / "workbench.sqlite3"
    cost = {
        "full": BUDGET_COST,
        "invalid": {"lowerBound": None},
        "unexceeded": {"lowerBound": {**BUDGET_COST, "estimatedUsd": 0.005}},
    }.get(cost_kind, {"lowerBound": BUDGET_COST})

    before = budget_snapshot(database, scan_dir)
    result = reader_command(
        state_dir,
        "complete-scan" if cost_kind == "ordinary" else "complete-budget-exhausted-scan",
        "--scan-id",
        scan_id,
        "--cost-json",
        json.dumps(cost),
        *([] if cost_kind == "ordinary" else ["--message", BUDGET_WARNING]),
    )
    after = budget_snapshot(database, scan_dir)
    if cost_kind in {"invalid", "unexceeded", "ordinary"}:
        assert result.returncode != 0
        assert after == before
        return
    assert result.returncode == 0, result.stderr
    public = json.loads(result.stdout)["scan"]
    with sqlite3.connect(database) as connection:
        status, saved = connection.execute("SELECT status, cost_json FROM scans").fetchone()
        assert connection.execute(
            "SELECT status, workflow_version, finalization_input_json FROM deep_scan_runs"
        ).fetchone() == ("succeeded", "deep-security-scan/v1", None)
    assert status == "complete"
    saved = json.loads(saved)
    assert saved["usage"]["coverage"] == "unavailable"
    if cost_kind == "lower-bound":
        assert "cost" not in public
        assert "cost" not in saved and "estimatedUsd" not in saved
    else:
        assert public["cost"] == BUDGET_COST
        assert saved["cost"] == BUDGET_COST
    manifest = json.loads((scan_dir / "scan-manifest.json").read_text())
    assert manifest["scan"]["sealedAt"]


@pytest.mark.parametrize(
    "state",
    [
        "retry",
        "changed-findings",
        "wrong-scan",
        "running-discovery",
        "canceled",
        "other-owner",
        "complete",
    ],
)
def test_reader_replays_sealed_budget_without_new_writer_state(reader_command, tmp_path, state):
    state_dir, _, scan_dir, scan_id, _ = budget_scan_fixture(tmp_path)
    command = partial(reader_command, state_dir)
    budget_args = [
        "complete-budget-exhausted-scan",
        "--scan-id",
        scan_id,
        "--cost-json",
        json.dumps(BUDGET_COST),
        "--message",
        BUDGET_WARNING,
    ]
    cut_program = """
import os, runpy, sys
script, *args = sys.argv[1:]
api = runpy.run_path(script, run_name="sealed_budget_test")
namespace = api["main"].__globals__
original = namespace["_write_prepared_scan_finalization"]
def after_seal(*args, **kwargs):
    original(*args, **kwargs)
    os._exit(86)
namespace["_write_prepared_scan_finalization"] = after_seal
sys.argv = [script, *args]
api["main"]()
"""
    cut = command(*budget_args, program=cut_program)
    assert cut.returncode == 86, cut.stderr
    manifest_path = scan_dir / "scan-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    assert manifest["scan"]["sealedAt"]
    assert manifest["scan"]["artifacts"]
    database = state_dir / "workbench.sqlite3"
    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT status, seal_manifest_digest FROM scans").fetchone() == (
            "running",
            None,
        )
        assert connection.execute(
            "SELECT status, workflow_version, finalization_input_json FROM deep_scan_runs"
        ).fetchone() == ("succeeded", "deep-security-scan/v1", None)

    if state == "changed-findings":
        path = scan_dir / "findings.json"
        findings = json.loads(path.read_text())
        findings["findings"].append({"title": "Changed after sealing"})
        path.write_text(json.dumps(findings))
    elif state == "wrong-scan":
        manifest["scan"]["id"] = "69078890-d24c-4416-a6fa-c286825bef88"
        manifest_path.write_text(json.dumps(manifest))
    elif state == "running-discovery":
        with sqlite3.connect(database) as connection:
            connection.execute("UPDATE deep_scan_runs SET status = 'running'")
    elif state == "other-owner":
        with sqlite3.connect(database) as connection:
            connection.execute(
                "UPDATE scans SET handoff_claim_token = 'a3292ae4-9b47-430f-8ed6-73ff73db575c'"
            )
    elif state == "canceled":
        result = command("cancel-scan", "--scan-id", scan_id)
        assert result.returncode == 0, result.stderr
    elif state == "complete":
        result = command(
            "complete-scan", "--scan-id", scan_id, "--cost-json", json.dumps(BUDGET_COST)
        )
        assert result.returncode == 0, result.stderr

    before = budget_snapshot(database, scan_dir)
    result = command(*budget_args)
    after = budget_snapshot(database, scan_dir)
    if state == "retry":
        assert result.returncode == 0, result.stderr
        assert after["files"] == before["files"]
        with sqlite3.connect(database) as connection:
            status, digest = connection.execute(
                "SELECT status, seal_manifest_digest FROM scans"
            ).fetchone()
        assert status == "complete"
        assert digest
    else:
        assert result.returncode != 0
        assert after == before


@pytest.mark.parametrize("budget_seal", [False, True])
def test_normal_seal_cannot_be_committed_as_budget_completion(
    workbench_api, workbench_db, publication_scan, budget_seal
):
    scan = publication_scan()
    with workbench_db:
        recipe = json.loads(workbench_db.execute("SELECT recipe_json FROM scans").fetchone()[0])
        recipe["maxCostUsd"] = 0.005
        workbench_db.execute("UPDATE scans SET recipe_json = ?", (json.dumps(recipe),))
    if budget_seal:
        row = workbench_db.execute("SELECT * FROM scans").fetchone()
        workbench_api["saved_results"].prepare_budget_draft(
            workbench_api["_WORKBENCH_DB_CONTEXT"], workbench_db, row, BUDGET_WARNING
        )
    workbench_api["complete_scan"](
        workbench_db,
        Namespace(scan_id=scan.scan_id, claim_token=None, cost_json=None),
        prepare_only=True,
    )
    assert workbench_db.execute("SELECT status FROM scans").fetchone()[0] == "running"
    before = snapshot(workbench_db, scan.scan_dir)
    args = Namespace(
        scan_id=scan.scan_id, cost_json=json.dumps(BUDGET_COST), message=BUDGET_WARNING
    )
    if budget_seal:
        workbench_api["complete_budget_exhausted_scan"](workbench_db, args)
        assert workbench_db.execute("SELECT status FROM scans").fetchone()[0] == "complete"
        coverage = json.loads((scan.scan_dir / "coverage.json").read_text())
        assert "completeness" not in coverage
        assert any(item["id"] == "scan-cost-limit" for item in coverage["deferred"])
    else:
        with pytest.raises(SystemExit, match="cost-limit"):
            workbench_api["complete_budget_exhausted_scan"](workbench_db, args)
    after = snapshot(workbench_db, scan.scan_dir)
    if not budget_seal:
        assert after["database"] == before["database"]
    assert after["files"] == before["files"]
