from __future__ import annotations

import sqlite3
from pathlib import Path

from workbench_test_support import (
    create_saved_git_workspace,
    fail_scan,
    get_scan,
    start_scan_command,
)


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
        name: start_scan_command(state_dir, str(workspace["id"]))
        for name, workspace in workspaces.items()
    }

    failed_scan_id = str(scans["failed"]["results"]["scanId"])
    other_scan_id = str(scans["other"]["results"]["scanId"])
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE scans SET handoff_status = 'delivered' WHERE id IN (?, ?)",
            (failed_scan_id, other_scan_id),
        )
    fail_scan(state_dir, failed_scan_id, "Stopped for the fixture.")
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
    context = get_scan(state_dir, current_scan_id)

    assert context["otherRunningDeepScans"] == [
        {
            "phase": "preflight",
            "scanId": other_scan_id,
            "startedAt": scans["other"]["results"]["updatedAt"],
            "targetPath": str(targets["other"].resolve()),
            "updatedAt": scans["other"]["results"]["updatedAt"],
        }
    ]

    fail_scan(state_dir, other_scan_id, "Stopped for the fixture.")
    context = get_scan(state_dir, current_scan_id)
    assert context["otherRunningDeepScans"] == []
