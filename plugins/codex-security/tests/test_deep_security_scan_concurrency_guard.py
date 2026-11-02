from __future__ import annotations

import uuid
from argparse import Namespace
from pathlib import Path


def test_scan_context_reports_only_other_running_deep_scans(
    workbench_api, workbench_db, tmp_path: Path
) -> None:
    scans = {}
    for name, mode, status in (
        ("current", "deep", "running"),
        ("other", "deep", "running"),
        ("standard", "standard", "running"),
        ("failed", "deep", "failed"),
        ("complete", "deep", "complete"),
    ):
        target = tmp_path / name
        target.mkdir()
        workspace_id = str(uuid.uuid4())
        now = workbench_api["now"]()
        with workbench_db:
            workbench_db.execute(
                "INSERT INTO workspaces (id, target_path, default_mode, submitted, created_at, "
                "updated_at) VALUES (?, ?, ?, 1, ?, ?)",
                (workspace_id, str(target), mode, now, now),
            )
        scans[name] = workbench_api["start_scan"](
            workbench_db,
            Namespace(
                workspace_id=workspace_id,
                scan_root=str(tmp_path / "scans"),
                model=None,
                reasoning_effort=None,
            ),
        )["results"]
        if status != "running":
            with workbench_db:
                workbench_db.execute(
                    "UPDATE scans SET status = ?, completed_at = updated_at WHERE id = ?",
                    (status, scans[name]["scanId"]),
                )

    with workbench_db:
        workbench_db.execute(
            "UPDATE scans SET handoff_status = 'delivered' WHERE id IN (?, ?)",
            (scans["other"]["scanId"], scans["failed"]["scanId"]),
        )
    current = Namespace(scan_id=scans["current"]["scanId"], occurrence_id=None)
    other = scans["other"]
    assert workbench_api["get_scan"](workbench_db, current)["otherRunningDeepScans"] == [
        {
            "phase": "preflight",
            "scanId": other["scanId"],
            "startedAt": other["updatedAt"],
            "targetPath": str((tmp_path / "other").resolve()),
            "updatedAt": other["updatedAt"],
        }
    ]

    with workbench_db:
        workbench_db.execute(
            "UPDATE scans SET status = 'failed', completed_at = updated_at WHERE id = ?",
            (other["scanId"],),
        )
    assert workbench_api["get_scan"](workbench_db, current)["otherRunningDeepScans"] == []
