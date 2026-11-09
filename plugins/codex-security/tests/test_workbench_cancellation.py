"""Test scan ownership and coherent workbench responses when cancellation or replacement races a request."""

from __future__ import annotations

import argparse
import json
import uuid
from contextlib import closing
from pathlib import Path

import pytest
from workbench_test_support import (
    cancel_scan,
    create_saved_workspace,
    empty_target_paths,
    fail_scan,
    get_scan,
    load_script,
    mark_handoff_delivered,
    scan_claim_command,
    scan_command,
    start_delivered_scan,
    start_scan_command,
    write_completed_contract,
)


def test_get_scan_returns_consistent_progress_when_canceled_during_read(tmp_path, monkeypatch):
    workbench = load_script("workbench_db")
    state_dir, target = empty_target_paths(tmp_path)
    thread_id = "thread-cancel-owner"
    workspace = create_saved_workspace(state_dir, target, thread_id=thread_id)
    scan_id = start_scan_command(state_dir, workspace["id"])["results"]["scanId"]
    monkeypatch.setenv("CODEX_SECURITY_STATE_DIR", str(state_dir))
    backfill = workbench.backfill_legacy_finding_details

    def cancel_after_backfill(connection, scan):
        backfill(connection, scan)
        cancel_scan(state_dir, scan_id, thread_id)

    monkeypatch.setattr(workbench, "backfill_legacy_finding_details", cancel_after_backfill)
    with closing(workbench.connect(deferred=True)) as connection:
        result = workbench.get_scan(
            connection, argparse.Namespace(scan_id=scan_id, occurrence_id=None)
        )
    scan = result["scan"]
    assert scan["progress"]["status"] == scan["lifecycle"]["status"] == "canceled"
    assert scan["canceledAt"] == scan["lifecycle"]["finishedAt"]
    assert scan["canceledAt"] is not None


@pytest.mark.parametrize("rejoin", [False, True])
def test_start_scan_returns_selected_scan_when_replaced_before_response(
    tmp_path, monkeypatch, rejoin
):
    workbench = load_script("workbench_db")
    state_dir, target = empty_target_paths(tmp_path)
    thread_id = "thread-cancel-owner"
    workspace_id = create_saved_workspace(state_dir, target, thread_id=thread_id)["id"]
    if rejoin:
        start_scan_command(state_dir, workspace_id)
    monkeypatch.setenv("CODEX_SECURITY_STATE_DIR", str(state_dir))
    workspace_state = workbench.workspace_state
    replaced_id = None

    def replace_then_read(connection, workspace_id, **selection):
        nonlocal replaced_id
        replaced_id = workbench.require_workspace(connection, workspace_id)["active_scan_id"]
        cancel_scan(state_dir, replaced_id, thread_id)
        replacement = start_scan_command(state_dir, workspace_id)
        assert replacement["results"]["scanId"] != replaced_id
        return workspace_state(connection, workspace_id, **selection)

    monkeypatch.setattr(workbench, "workspace_state", replace_then_read)
    args = argparse.Namespace(
        workspace_id=workspace_id, scan_root=None, model=None, reasoning_effort=None
    )
    with closing(workbench.connect()) as connection:
        result = workbench.start_scan(connection, args)
    assert result["results"]["scanId"] == replaced_id
    assert result["results"]["progress"]["status"] == "canceled"


@pytest.mark.parametrize("app", [False, True])
def test_cancellation_identifies_committed_scan_when_workspace_has_replacement(
    tmp_path, monkeypatch, app
):
    workbench = load_script("workbench_db")
    state_dir, target = empty_target_paths(tmp_path)
    thread_id = "thread-cancel-owner"
    workspace_id = create_saved_workspace(state_dir, target, thread_id=thread_id)["id"]
    scan_id = start_scan_command(state_dir, workspace_id)["results"]["scanId"]
    monkeypatch.setenv("CODEX_SECURITY_STATE_DIR", str(state_dir))
    preserve = workbench.saved_results.preserve_stopped_results_after_transition
    replacement_id = None

    def start_replacement(db, connection, canceled_id):
        nonlocal replacement_id
        assert canceled_id == scan_id
        replacement_id = start_scan_command(state_dir, workspace_id)["results"]["scanId"]
        preserve(db, connection, canceled_id)

    monkeypatch.setattr(
        workbench.saved_results, "preserve_stopped_results_after_transition", start_replacement
    )
    with closing(workbench.connect()) as connection:
        canceled = workbench.saved_results.cancel_scan(
            workbench._WORKBENCH_DB_CONTEXT,
            connection,
            argparse.Namespace(scan_id=scan_id, thread_id=None if app else thread_id),
        )
    replay = (
        scan_command(state_dir, "cancel-scan", scan_id)
        if app
        else cancel_scan(state_dir, scan_id, thread_id)
    )
    assert replacement_id and replacement_id != scan_id
    for response in (canceled, replay):
        assert response["canceledScanId"] == scan_id
        assert response["results"]["scanId"] == (replacement_id if app else scan_id)
        assert response["results"]["progress"]["status"] == ("running" if app else "canceled")


def test_workbench_records_scan_failure(tmp_path: Path) -> None:
    state_dir, target = empty_target_paths(tmp_path)
    saved = create_saved_workspace(state_dir, target)
    started = start_scan_command(
        state_dir, str(saved["id"]), "--scan-root", str(tmp_path / "scans")
    )
    scan_id = str(started["results"]["scanId"])
    claim_token = str(uuid.uuid4())
    scan_claim_command(state_dir, "claim-handoff-delivery", scan_id, claim_token)
    failed = fail_scan(
        state_dir, scan_id, "Repository checkout became unavailable.", "--claim-token", claim_token
    )
    assert failed["scan"]["progress"]["status"] == "failed"
    assert failed["scan"]["failureMessage"] == "Repository checkout became unavailable."

    delivered = mark_handoff_delivered(state_dir, scan_id, claim_token)
    assert delivered["results"]["handoffStatus"] == "delivered"
    replayed = mark_handoff_delivered(state_dir, scan_id, claim_token)
    assert replayed["results"]["handoffStatus"] == "delivered"


def test_workbench_cancels_running_scan_and_rejects_late_updates(tmp_path: Path) -> None:
    state_dir, target = empty_target_paths(tmp_path)
    thread_id = "thread-cancel-owner"
    saved = create_saved_workspace(state_dir, target, thread_id=thread_id)
    started = start_scan_command(state_dir, str(saved["id"]))
    scan_id = str(started["results"]["scanId"])
    claim_token = str(uuid.uuid4())
    claimed = scan_claim_command(state_dir, "claim-handoff-delivery", scan_id, claim_token)
    assert claimed["results"]["handoffClaimToken"] == claim_token

    wrong_thread = cancel_scan(state_dir, scan_id, "thread-cancel-other", check=False)
    assert wrong_thread["returncode"] != 0
    assert "owning Codex thread" in str(wrong_thread["stderr"])

    cost = {
        "model": "synthetic-model",
        "inputTokens": 25,
        "cachedInputTokens": 0,
        "cacheWriteInputTokens": 0,
        "outputTokens": 1,
        "estimatedUsd": 0.001,
    }
    canceled = scan_command(
        state_dir, "cancel-scan", scan_id, "--thread-id", thread_id, "--cost-json", json.dumps(cost)
    )
    assert canceled["results"]["cost"] == cost
    assert canceled["results"]["progress"]["status"] == "canceled"
    assert canceled["results"]["canceledAt"]
    assert canceled["results"]["handoffClaimToken"] == claim_token

    replayed = cancel_scan(state_dir, scan_id, thread_id)
    assert replayed["results"]["cost"] == cost
    assert replayed["results"]["canceledAt"] == canceled["results"]["canceledAt"]

    for command in (
        ("update-progress", "--phase", "discovery"),
        ("complete-scan",),
    ):
        rejected = scan_command(state_dir, command[0], scan_id, *command[1:], check=False)
        assert rejected["returncode"] != 0

    delivered = mark_handoff_delivered(state_dir, scan_id, claim_token, "--thread-id", thread_id)
    assert delivered["results"]["progress"]["status"] == "canceled"
    assert delivered["results"]["handoffStatus"] == "delivered"

    restarted = start_delivered_scan(state_dir, str(saved["id"]))
    restarted_scan_id = str(restarted["scanId"])
    assert restarted_scan_id != scan_id
    assert restarted["progress"]["status"] == "running"
    previous_scan = get_scan(state_dir, scan_id)
    lifecycle = previous_scan["scan"]["lifecycle"]
    assert lifecycle["status"] == "canceled"
    assert lifecycle["finishedAt"] == canceled["results"]["canceledAt"]
    assert lifecycle["hasReportableFindings"] is None
    assert previous_scan["scan"]["scanId"] == scan_id
    assert previous_scan["workspace"]["results"]["scanId"] == scan_id
    assert previous_scan["workspace"]["results"]["progress"]["status"] == "canceled"
    write_completed_contract(Path(str(restarted["scanDir"])), restarted_scan_id, target)
    scan_command(state_dir, "complete-scan", restarted_scan_id)
    rejected = cancel_scan(state_dir, restarted_scan_id, thread_id, check=False)
    assert rejected["returncode"] != 0
    assert "Only a running scan can be canceled" in str(rejected["stderr"])


def test_workbench_rejects_unconfirmed_cross_thread_handoff_delivery(tmp_path: Path) -> None:
    state_dir, target = empty_target_paths(tmp_path)
    thread_id = "thread-handoff-owner"
    saved = create_saved_workspace(state_dir, target, thread_id=thread_id)
    started = start_scan_command(state_dir, str(saved["id"]))
    scan_id = str(started["results"]["scanId"])
    claim_token = str(uuid.uuid4())
    scan_claim_command(state_dir, "claim-handoff-delivery", scan_id, claim_token)

    wrong_thread = mark_handoff_delivered(
        state_dir, scan_id, claim_token, "--thread-id", "thread-handoff-other", check=False
    )
    assert wrong_thread["returncode"] != 0
    assert "owning Codex thread" in str(wrong_thread["stderr"])

    delivered = mark_handoff_delivered(state_dir, scan_id, claim_token, "--thread-id", thread_id)
    assert delivered["results"]["handoffStatus"] == "delivered"
    assert delivered["results"]["handoffClaimToken"] == claim_token

    wrong_replay = mark_handoff_delivered(
        state_dir, scan_id, str(uuid.uuid4()), "--thread-id", thread_id, check=False
    )
    assert wrong_replay["returncode"] != 0
    assert "owned by another continuation" in str(wrong_replay["stderr"])


def test_workbench_allows_user_confirmed_recovery_in_another_thread(tmp_path: Path) -> None:
    state_dir, target = empty_target_paths(tmp_path)
    saved = create_saved_workspace(state_dir, target, thread_id="thread-recovery-owner")
    started = start_scan_command(state_dir, str(saved["id"]))
    scan_id = str(started["results"]["scanId"])
    claim_token = f"recovery_{uuid.uuid4()}"
    scan_claim_command(state_dir, "claim-handoff-delivery", scan_id, claim_token)

    delivered = mark_handoff_delivered(
        state_dir, scan_id, claim_token, "--thread-id", "thread-recovery-confirmed"
    )

    assert delivered["results"]["handoffStatus"] == "delivered"
    assert delivered["results"]["handoffClaimToken"] == claim_token
