"""Check that scan context counts concurrent deep scans while excluding the current run."""

from __future__ import annotations

import uuid
from argparse import Namespace
from contextlib import closing
from pathlib import Path

import pytest
from workbench_test_support import (
    create_saved_workspace,
    load_script,
    save_workspace,
    start_scan_command,
)


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
            target_id = workbench_api["ensure_security_target"](workbench_db, str(target))
            workbench_db.execute(
                "INSERT INTO workspaces (id, target_id, target_path, default_mode, submitted, "
                "created_at, updated_at) VALUES (?, ?, ?, ?, 1, ?, ?)",
                (workspace_id, target_id, str(target), mode, now, now),
            )
        scans[name] = workbench_api["start_scan"](
            workbench_db,
            Namespace(
                workspace_id=workspace_id,
                workspace_version=workbench_api["workspace_confirmation_version"](
                    workbench_api["require_workspace"](workbench_db, workspace_id)
                ),
                scan_root=str(tmp_path / "scans"),
                confirmed_concurrent_scan_id=[scan["scanId"] for scan in scans.values()],
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


@pytest.fixture
def competing_workspace(tmp_path, monkeypatch):
    state = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    first = create_saved_workspace(state, target, thread_id="first", mode="deep")
    start_scan_command(state, first["id"])
    second = create_saved_workspace(state, target, thread_id="second", mode="deep")
    wb = load_script("workbench_db")
    monkeypatch.setenv("CODEX_SECURITY_STATE_DIR", str(state))
    monkeypatch.setattr(wb.deep_scan, "dependencies", lambda: wb)

    return wb, state, target, second["id"]


def test_pending_consent_skips_new_checkout_walks(competing_workspace, monkeypatch):
    wb, _, target, workspace_id = competing_workspace

    def unexpected_walk(*args, **kwargs):
        raise AssertionError("Walked the checkout before concurrent launch consent")

    monkeypatch.setattr(wb, "scan_target_identity", unexpected_walk)
    monkeypatch.setattr(wb, "scan_scope_file_count", unexpected_walk)
    monkeypatch.setattr(wb.deep_scan, "directory_snapshot_regular_file_count", unexpected_walk)
    with closing(wb.connect()) as connection:
        app = wb.start_scan(connection, Namespace(workspace_id=workspace_id))
        assert app["confirmationRequired"] and app["workspaceVersion"]
        request = Namespace(
            target_path=str(target),
            scope=".",
            user_context=None,
            project_config_path=None,
            join_only=False,
            confirmed_concurrent_scan_id=[],
        )
        direct = wb.deep_scan.begin_deep_scan_for_target(connection, request, "second")
        assert direct["confirmationRequired"]


def test_stale_confirmation_cannot_rejoin_a_changed_workspace(competing_workspace, monkeypatch):
    wb, state, target, workspace_id = competing_workspace
    args = Namespace(workspace_id=workspace_id, scan_root=None, model=None, reasoning_effort=None)
    original_count = wb.scan_scope_file_count

    def start_changed_scan(*args):
        save_workspace(state, workspace_id, str(target), ".", "standard")
        start_scan_command(state, workspace_id)
        return original_count(*args)

    with closing(wb.connect()) as connection:
        pending = wb.start_scan(connection, args)
        args.workspace_version = pending["workspaceVersion"]
        args.confirmed_concurrent_scan_id = [pending["otherRunningDeepScans"][0]["scanId"]]
        monkeypatch.setattr(wb, "scan_scope_file_count", start_changed_scan)
        # The competing scan arrives during preparation, then already exists on the retry.
        for _ in range(2):
            with pytest.raises(SystemExit, match="current workspace setup"):
                wb.start_scan(connection, args)
