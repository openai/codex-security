from __future__ import annotations

import uuid
from pathlib import Path

from workbench_test_support import (
    create_saved_workspace,
    run_workbench,
    start_delivered_scan,
    write_completed_contract,
)


def test_workbench_records_scan_failure(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    saved = create_saved_workspace(state_dir, target)
    started = run_workbench(
        state_dir,
        "start-scan",
        "--workspace-id",
        str(saved["id"]),
        "--scan-root",
        str(tmp_path / "scans"),
    )
    scan_id = str(started["results"]["scanId"])
    claim_token = str(uuid.uuid4())
    run_workbench(
        state_dir, "claim-handoff-delivery", "--scan-id", scan_id, "--claim-token", claim_token
    )
    failed = run_workbench(
        state_dir,
        "fail-scan",
        "--scan-id",
        scan_id,
        "--message",
        "Repository checkout became unavailable.",
        "--claim-token",
        claim_token,
    )
    assert failed["scan"]["progress"]["status"] == "failed"
    assert failed["scan"]["failureMessage"] == "Repository checkout became unavailable."

    delivered = run_workbench(
        state_dir, "mark-handoff-delivered", "--scan-id", scan_id, "--claim-token", claim_token
    )
    assert delivered["results"]["handoffStatus"] == "delivered"
    replayed = run_workbench(
        state_dir, "mark-handoff-delivered", "--scan-id", scan_id, "--claim-token", claim_token
    )
    assert replayed["results"]["handoffStatus"] == "delivered"


def test_workbench_cancels_running_scan_and_rejects_late_updates(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    thread_id = "thread-cancel-owner"
    saved = create_saved_workspace(state_dir, target, thread_id=thread_id)
    started = run_workbench(state_dir, "start-scan", "--workspace-id", str(saved["id"]))
    scan_id = str(started["results"]["scanId"])
    claim_token = str(uuid.uuid4())
    claimed = run_workbench(
        state_dir, "claim-handoff-delivery", "--scan-id", scan_id, "--claim-token", claim_token
    )
    assert claimed["results"]["handoffClaimToken"] == claim_token

    wrong_thread = run_workbench(
        state_dir,
        "cancel-scan",
        "--scan-id",
        scan_id,
        "--thread-id",
        "thread-cancel-other",
        check=False,
    )
    assert wrong_thread["returncode"] != 0
    assert "owning Codex thread" in str(wrong_thread["stderr"])

    canceled = run_workbench(
        state_dir, "cancel-scan", "--scan-id", scan_id, "--thread-id", thread_id
    )
    assert canceled["results"]["progress"]["status"] == "canceled"
    assert canceled["results"]["canceledAt"]
    assert canceled["results"]["handoffClaimToken"] == claim_token

    replayed = run_workbench(
        state_dir, "cancel-scan", "--scan-id", scan_id, "--thread-id", thread_id
    )
    assert replayed["results"]["canceledAt"] == canceled["results"]["canceledAt"]

    for command in (
        ("update-progress", "--phase", "discovery"),
        ("complete-scan",),
    ):
        rejected = run_workbench(
            state_dir,
            command[0],
            "--scan-id",
            scan_id,
            *command[1:],
            check=False,
        )
        assert rejected["returncode"] != 0

    delivered = run_workbench(
        state_dir,
        "mark-handoff-delivered",
        "--scan-id",
        scan_id,
        "--claim-token",
        claim_token,
        "--thread-id",
        thread_id,
    )
    assert delivered["results"]["progress"]["status"] == "canceled"
    assert delivered["results"]["handoffStatus"] == "delivered"

    restarted = start_delivered_scan(state_dir, "--workspace-id", str(saved["id"]))
    restarted_scan_id = str(restarted["results"]["scanId"])
    assert restarted_scan_id != scan_id
    assert restarted["results"]["progress"]["status"] == "running"
    previous_scan = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)
    assert previous_scan["scan"]["scanId"] == scan_id
    assert previous_scan["workspace"]["results"]["scanId"] == scan_id
    assert previous_scan["workspace"]["results"]["progress"]["status"] == "canceled"
    write_completed_contract(Path(str(restarted["results"]["scanDir"])), restarted_scan_id, target)
    run_workbench(state_dir, "complete-scan", "--scan-id", restarted_scan_id)
    rejected = run_workbench(
        state_dir,
        "cancel-scan",
        "--scan-id",
        restarted_scan_id,
        "--thread-id",
        thread_id,
        check=False,
    )
    assert rejected["returncode"] != 0
    assert "Only a running scan can be canceled" in str(rejected["stderr"])


def test_workbench_rejects_unconfirmed_cross_thread_handoff_delivery(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    thread_id = "thread-handoff-owner"
    saved = create_saved_workspace(state_dir, target, thread_id=thread_id)
    started = run_workbench(state_dir, "start-scan", "--workspace-id", str(saved["id"]))
    scan_id = str(started["results"]["scanId"])
    claim_token = str(uuid.uuid4())
    run_workbench(
        state_dir, "claim-handoff-delivery", "--scan-id", scan_id, "--claim-token", claim_token
    )

    wrong_thread = run_workbench(
        state_dir,
        "mark-handoff-delivered",
        "--scan-id",
        scan_id,
        "--claim-token",
        claim_token,
        "--thread-id",
        "thread-handoff-other",
        check=False,
    )
    assert wrong_thread["returncode"] != 0
    assert "owning Codex thread" in str(wrong_thread["stderr"])

    delivered = run_workbench(
        state_dir,
        "mark-handoff-delivered",
        "--scan-id",
        scan_id,
        "--claim-token",
        claim_token,
        "--thread-id",
        thread_id,
    )
    assert delivered["results"]["handoffStatus"] == "delivered"
    assert delivered["results"]["handoffClaimToken"] == claim_token

    wrong_replay = run_workbench(
        state_dir,
        "mark-handoff-delivered",
        "--scan-id",
        scan_id,
        "--claim-token",
        str(uuid.uuid4()),
        "--thread-id",
        thread_id,
        check=False,
    )
    assert wrong_replay["returncode"] != 0
    assert "owned by another continuation" in str(wrong_replay["stderr"])


def test_workbench_allows_user_confirmed_recovery_in_another_thread(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    saved = create_saved_workspace(state_dir, target, thread_id="thread-recovery-owner")
    started = run_workbench(state_dir, "start-scan", "--workspace-id", str(saved["id"]))
    scan_id = str(started["results"]["scanId"])
    claim_token = f"recovery_{uuid.uuid4()}"
    run_workbench(
        state_dir, "claim-handoff-delivery", "--scan-id", scan_id, "--claim-token", claim_token
    )

    delivered = run_workbench(
        state_dir,
        "mark-handoff-delivered",
        "--scan-id",
        scan_id,
        "--claim-token",
        claim_token,
        "--thread-id",
        "thread-recovery-confirmed",
    )

    assert delivered["results"]["handoffStatus"] == "delivered"
    assert delivered["results"]["handoffClaimToken"] == claim_token
