from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys

import pytest
import workbench_test_support
from test_workbench_db import BUDGET_COST, BUDGET_WARNING, budget_scan_fixture


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
def test_reader_replays_sealed_budget_without_new_writer_state(
    workbench_api, monkeypatch, tmp_path, state
):
    script = str(workbench_api["__file__"])
    monkeypatch.setattr(workbench_test_support, "SCRIPT", script)
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "home"))
    state_dir, _, scan_dir, scan_id, _ = budget_scan_fixture(tmp_path)
    environment = {**os.environ, "CODEX_SECURITY_STATE_DIR": str(state_dir)}
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
    cut = subprocess.run(
        [sys.executable, "-I", "-B", "-c", cut_program, script, *budget_args],
        env=environment,
        text=True,
        capture_output=True,
    )
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

    def command(*args):
        return subprocess.run(
            [sys.executable, "-I", "-B", script, *args],
            env=environment,
            text=True,
            capture_output=True,
        )

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

    def snapshot():
        with sqlite3.connect(database) as connection:
            assert connection.execute("SELECT COUNT(*) FROM deep_scan_attempts").fetchone() == (0,)
            assert connection.execute(
                "SELECT COUNT(*) FROM deep_scan_attempt_sessions"
            ).fetchone() == (0,)
            return list(connection.iterdump()), {
                path.relative_to(scan_dir): path.read_bytes()
                for path in scan_dir.rglob("*")
                if path.is_file()
            }

    before = snapshot()
    result = command(*budget_args)
    after = snapshot()
    if state == "retry":
        assert result.returncode == 0, result.stderr
        assert after[1] == before[1]
        with sqlite3.connect(database) as connection:
            status, digest = connection.execute(
                "SELECT status, seal_manifest_digest FROM scans"
            ).fetchone()
        assert status == "complete"
        assert digest
    else:
        assert result.returncode != 0
        assert after == before
