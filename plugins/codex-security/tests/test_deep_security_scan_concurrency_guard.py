from __future__ import annotations

import sqlite3
from pathlib import Path

from workbench_test_support import create_saved_git_workspace, run_workbench


def test_scan_context_reports_only_other_running_deep_scans(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    targets = {
        name: tmp_path / name for name in ("current", "other", "standard", "failed", "complete")
    }
    for target in targets.values():
        target.mkdir()

    workspaces = {
        name: create_saved_git_workspace(
            state_dir,
            target,
            mode="standard" if name == "standard" else "deep",
        )
        for name, target in targets.items()
    }
    scans = {
        name: run_workbench(
            state_dir,
            "start-scan",
            "--workspace-id",
            str(workspace["id"]),
        )
        for name, workspace in workspaces.items()
    }

    failed_scan_id = str(scans["failed"]["results"]["scanId"])
    other_scan_id = str(scans["other"]["results"]["scanId"])
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE scans SET handoff_status = 'delivered' WHERE id IN (?, ?)",
            (failed_scan_id, other_scan_id),
        )
    run_workbench(
        state_dir,
        "fail-scan",
        "--scan-id",
        failed_scan_id,
        "--message",
        "Stopped for the fixture.",
    )
    complete_scan_id = str(scans["complete"]["results"]["scanId"])
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.execute(
            """
            UPDATE scans
            SET status = 'complete', completed_at = updated_at
            WHERE id = ?
            """,
            (complete_scan_id,),
        )

    current_scan_id = str(scans["current"]["results"]["scanId"])
    context = run_workbench(state_dir, "get-scan", "--scan-id", current_scan_id)

    assert context["otherRunningDeepScans"] == [
        {
            "phase": "preflight",
            "scanId": other_scan_id,
            "startedAt": scans["other"]["results"]["updatedAt"],
            "targetPath": str(targets["other"].resolve()),
            "updatedAt": scans["other"]["results"]["updatedAt"],
        }
    ]

    run_workbench(
        state_dir,
        "fail-scan",
        "--scan-id",
        other_scan_id,
        "--message",
        "Stopped for the fixture.",
    )
    context = run_workbench(state_dir, "get-scan", "--scan-id", current_scan_id)
    assert context["otherRunningDeepScans"] == []
