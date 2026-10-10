from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys

import pytest
import workbench_test_support
from test_workbench_db import BUDGET_COST, BUDGET_WARNING, budget_scan_fixture


@pytest.mark.parametrize("cost_kind", ["full", "lower-bound", "invalid", "unexceeded", "ordinary"])
def test_reader_budget_cost_preserves_unknown_totals(
    workbench_api, monkeypatch, tmp_path, cost_kind
):
    script = str(workbench_api["__file__"])
    monkeypatch.setattr(workbench_test_support, "SCRIPT", script)
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "home"))
    state_dir, _, scan_dir, scan_id, _ = budget_scan_fixture(tmp_path)
    database = state_dir / "workbench.sqlite3"
    cost = (
        BUDGET_COST
        if cost_kind == "full"
        else {
            "lowerBound": None
            if cost_kind == "invalid"
            else {**BUDGET_COST, "estimatedUsd": 0.005}
            if cost_kind == "unexceeded"
            else BUDGET_COST
        }
    )

    def snapshot():
        with sqlite3.connect(database) as connection:
            assert connection.execute("SELECT COUNT(*) FROM deep_scan_attempts").fetchone() == (0,)
            assert connection.execute(
                "SELECT COUNT(*) FROM deep_scan_attempt_sessions"
            ).fetchone() == (0,)
            return list(connection.iterdump()), {
                str(path.relative_to(scan_dir)): path.read_bytes()
                for path in scan_dir.rglob("*")
                if path.is_file()
            }

    before = snapshot()
    command = [
        sys.executable,
        "-I",
        "-B",
        script,
        "complete-scan" if cost_kind == "ordinary" else "complete-budget-exhausted-scan",
        "--scan-id",
        scan_id,
        "--cost-json",
        json.dumps(cost),
        *([] if cost_kind == "ordinary" else ["--message", BUDGET_WARNING]),
    ]
    result = subprocess.run(
        command,
        env={**os.environ, "CODEX_SECURITY_STATE_DIR": str(state_dir)},
        text=True,
        capture_output=True,
    )
    after = snapshot()
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
    if cost_kind == "lower-bound":
        assert "cost" not in public
        saved = json.loads(saved)
        assert "cost" not in saved and "estimatedUsd" not in saved
        assert saved["usage"]["coverage"] == "unavailable"
    else:
        assert public["cost"] == BUDGET_COST
        assert json.loads(saved) == BUDGET_COST
    manifest = json.loads((scan_dir / "scan-manifest.json").read_text())
    assert manifest["scan"]["sealedAt"]
