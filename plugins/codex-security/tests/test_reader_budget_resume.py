from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
from argparse import Namespace
from pathlib import Path

import pytest
from test_deep_scan_successful_publication import publication_scan as publication_scan
from test_stopped_result_version_boundary import snapshot


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
    workbench_api, workbench_db, publication_scan, tmp_path, state
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
    script = Path(workbench_api["__file__"])
    result = subprocess.run(
        [sys.executable, "-I", "-B", str(script), "get-cli-scan-resume", "--scan-id", scan.scan_id],
        env={
            **os.environ,
            "CODEX_SECURITY_STATE_DIR": str(state_dir),
            "CODEX_HOME": str(tmp_path / "home"),
        },
        capture_output=True,
        text=True,
    )
    with sqlite3.connect(state_dir / "workbench.sqlite3") as disk:
        after = snapshot(disk, scan.scan_dir)
        assert disk.execute("SELECT COUNT(*) FROM deep_scan_attempts").fetchone() == (0,)
        assert disk.execute("SELECT COUNT(*) FROM deep_scan_attempt_sessions").fetchone() == (0,)
    assert after == before
    if state in {"selected-budget", "legacy-finished"}:
        assert result.returncode == 0, result.stderr
        assert json.loads(result.stdout)["scanId"] == scan.scan_id
        assert json.loads(result.stdout)["threadId"] == thread
    else:
        assert result.returncode != 0
        assert "cannot resume" in result.stderr
