from __future__ import annotations

import sqlite3
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from workbench_test_support import create_saved_workspace, run_workbench


@pytest.mark.parametrize("mode", ("standard", "deep"))
def test_running_scan_context_is_owned_by_attached_continuation(tmp_path: Path, mode: str) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    original_thread_id = "original-thread"
    continuation_thread_id = "continuation-thread"
    saved = create_saved_workspace(state_dir, target, thread_id=original_thread_id, mode=mode)
    started = run_workbench(state_dir, "start-scan", "--workspace-id", str(saved["id"]))
    scan_id = str(started["results"]["scanId"])
    claim_token = str(uuid.uuid4())
    run_workbench(
        state_dir,
        "claim-handoff-delivery",
        "--scan-id",
        scan_id,
        "--claim-token",
        claim_token,
    )
    run_workbench(
        state_dir,
        "attach-scan-continuation-thread",
        "--scan-id",
        scan_id,
        "--claim-token",
        claim_token,
        "--thread-id",
        continuation_thread_id,
    )

    updated_context = "Prioritize password-reset token validation."
    updated = run_workbench(
        state_dir,
        "update-scan-context",
        "--scan-id",
        scan_id,
        "--thread-id",
        continuation_thread_id,
        "--claim-token",
        claim_token,
        "--user-context",
        updated_context,
    )
    assert updated["scan"]["userContext"] == updated_context
    assert updated["workspace"]["userContext"] == updated_context

    for rejected_thread_id in (original_thread_id, "unrelated-thread"):
        rejected_owner = run_workbench(
            state_dir,
            "update-scan-context",
            "--scan-id",
            scan_id,
            "--thread-id",
            rejected_thread_id,
            "--claim-token",
            claim_token,
            "--user-context",
            "Unauthorized replacement.",
            check=False,
        )
        assert rejected_owner["returncode"] != 0
        assert "current Codex thread" in str(rejected_owner["stderr"])

    rejected_claim = run_workbench(
        state_dir,
        "update-scan-context",
        "--scan-id",
        scan_id,
        "--thread-id",
        continuation_thread_id,
        "--claim-token",
        str(uuid.uuid4()),
        "--user-context",
        "Unauthorized replacement.",
        check=False,
    )
    assert rejected_claim["returncode"] != 0
    assert "owned by another continuation" in str(rejected_claim["stderr"])

    persisted = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)
    assert persisted["scan"]["userContext"] == updated_context
    assert persisted["workspace"]["userContext"] == updated_context


def test_workbench_serializes_concurrent_handoff_delivery(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    saved = create_saved_workspace(state_dir, target)
    started = run_workbench(state_dir, "start-scan", "--workspace-id", str(saved["id"]))
    scan_id = str(started["results"]["scanId"])
    claim_token = str(uuid.uuid4())
    run_workbench(
        state_dir, "claim-handoff-delivery", "--scan-id", scan_id, "--claim-token", claim_token
    )

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(
            executor.map(
                lambda _: run_workbench(
                    state_dir,
                    "mark-handoff-delivered",
                    "--scan-id",
                    scan_id,
                    "--claim-token",
                    claim_token,
                ),
                range(2),
            )
        )

    assert [result["results"]["handoffStatus"] for result in results] == [
        "delivered",
        "delivered",
    ]
    assert all(result["results"]["handoffClaimToken"] == claim_token for result in results)
    assert all(
        result["results"]["progress"]["phaseProgress"]
        == {"completed": 0, "total": 0, "unit": "checks"}
        for result in results
    )
    assert all(
        result["results"]["progress"]["preflightProgress"] == {"completed": 0, "total": 0}
        for result in results
    )


def test_deep_handoff_leaves_preflight_progress_to_coordinator(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    workspace_id = str(uuid.uuid4())
    run_workbench(
        state_dir,
        "create-workspace",
        "--workspace-id",
        workspace_id,
        "--target-path",
        str(target),
    )
    run_workbench(
        state_dir,
        "save-workspace",
        "--workspace-id",
        workspace_id,
        "--target-path",
        str(target),
        "--scope",
        ".",
        "--mode",
        "deep",
    )
    started = run_workbench(state_dir, "start-scan", "--workspace-id", workspace_id)
    scan_id = str(started["results"]["scanId"])
    claim_token = str(uuid.uuid4())
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
    )

    assert delivered["results"]["progress"]["phaseProgress"] == {
        "completed": 0,
        "total": 0,
        "unit": None,
    }
    assert delivered["results"]["progress"]["preflightProgress"] == {
        "completed": 0,
        "total": 0,
    }


def test_workbench_upgrade_keeps_preexisting_delivered_continuation_writable(
    tmp_path: Path,
) -> None:
    state_dir = tmp_path / "state"
    delivered_target = tmp_path / "delivered-target"
    pending_target = tmp_path / "pending-target"
    delivered_target.mkdir()
    pending_target.mkdir()
    delivered_workspace = create_saved_workspace(state_dir, delivered_target)
    pending_workspace = create_saved_workspace(state_dir, pending_target)
    delivered_scan = run_workbench(
        state_dir, "start-scan", "--workspace-id", str(delivered_workspace["id"])
    )
    pending_scan = run_workbench(
        state_dir, "start-scan", "--workspace-id", str(pending_workspace["id"])
    )
    delivered_scan_id = str(delivered_scan["results"]["scanId"])
    pending_scan_id = str(pending_scan["results"]["scanId"])
    delivered_token = str(uuid.uuid4())
    pending_token = str(uuid.uuid4())
    run_workbench(
        state_dir,
        "claim-handoff-delivery",
        "--scan-id",
        delivered_scan_id,
        "--claim-token",
        delivered_token,
    )
    run_workbench(
        state_dir,
        "mark-handoff-delivered",
        "--scan-id",
        delivered_scan_id,
        "--claim-token",
        delivered_token,
    )
    run_workbench(
        state_dir,
        "claim-handoff-delivery",
        "--scan-id",
        pending_scan_id,
        "--claim-token",
        pending_token,
    )
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.execute("DELETE FROM schema_migrations WHERE version = 18")

    run_workbench(state_dir, "database-info")

    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        assert connection.execute(
            "SELECT handoff_claim_token FROM scans WHERE id = ?", (delivered_scan_id,)
        ).fetchone() == (None,)
        assert connection.execute(
            "SELECT handoff_claim_token FROM scans WHERE id = ?", (pending_scan_id,)
        ).fetchone() == (pending_token,)
    updated = run_workbench(
        state_dir,
        "update-progress",
        "--scan-id",
        delivered_scan_id,
        "--phase",
        "discovery",
    )
    assert updated["scan"]["progress"]["phase"] == "discovery"


def test_workbench_handoff_claim_is_owned_by_one_token(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    saved = create_saved_workspace(state_dir, target)
    started = run_workbench(state_dir, "start-scan", "--workspace-id", str(saved["id"]))
    scan_id = str(started["results"]["scanId"])
    tokens = [str(uuid.uuid4()), str(uuid.uuid4())]
    with ThreadPoolExecutor(max_workers=2) as executor:
        claims = list(
            executor.map(
                lambda token: run_workbench(
                    state_dir,
                    "claim-handoff-delivery",
                    "--scan-id",
                    scan_id,
                    "--claim-token",
                    token,
                ),
                tokens,
            )
        )
    owners = {claim["results"]["handoffClaimToken"] for claim in claims}
    assert len(owners) == 1
    owner = owners.pop()
    non_owner = next(token for token in tokens if token != owner)
    wrong_release = run_workbench(
        state_dir,
        "release-handoff-delivery",
        "--scan-id",
        scan_id,
        "--claim-token",
        non_owner,
    )
    assert wrong_release["results"]["handoffClaimToken"] == owner
    wrong_delivery = run_workbench(
        state_dir,
        "mark-handoff-delivered",
        "--scan-id",
        scan_id,
        "--claim-token",
        non_owner,
        check=False,
    )
    assert "delivery could not be recorded" in str(wrong_delivery["stderr"])


def test_workbench_handoff_claim_only_allows_stale_takeover(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    saved = create_saved_workspace(state_dir, target)
    started = run_workbench(state_dir, "start-scan", "--workspace-id", str(saved["id"]))
    scan_id = str(started["results"]["scanId"])
    owner = str(uuid.uuid4())
    replacement = str(uuid.uuid4())
    run_workbench(state_dir, "claim-handoff-delivery", "--scan-id", scan_id, "--claim-token", owner)
    run_workbench(
        state_dir,
        "attach-scan-continuation-thread",
        "--scan-id",
        scan_id,
        "--claim-token",
        owner,
        "--thread-id",
        "stale-continuation",
    )
    live = run_workbench(
        state_dir,
        "claim-handoff-delivery",
        "--scan-id",
        scan_id,
        "--claim-token",
        replacement,
        "--take-over-stale",
    )
    assert live["results"]["handoffClaimToken"] == owner
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE scans SET handoff_claimed_at = ? WHERE id = ?",
            ("2000-01-01T00:00:00Z", scan_id),
        )
    stale = run_workbench(
        state_dir,
        "claim-handoff-delivery",
        "--scan-id",
        scan_id,
        "--claim-token",
        replacement,
        "--take-over-stale",
    )
    assert stale["results"]["handoffClaimToken"] == replacement
    assert stale["results"]["continuationThreadId"] is None
    for claim_token in (None, owner):
        rejected_update = run_workbench(
            state_dir,
            "update-progress",
            "--scan-id",
            scan_id,
            "--phase",
            "discovery",
            *(() if claim_token is None else ("--claim-token", claim_token)),
            check=False,
        )
        assert "owned by another continuation" in str(rejected_update["stderr"])
    attached = run_workbench(
        state_dir,
        "attach-scan-continuation-thread",
        "--scan-id",
        scan_id,
        "--claim-token",
        replacement,
        "--thread-id",
        "replacement-continuation",
    )
    assert attached["results"]["continuationThreadId"] == "replacement-continuation"
    delivered = run_workbench(
        state_dir,
        "mark-handoff-delivered",
        "--scan-id",
        scan_id,
        "--claim-token",
        replacement,
    )
    assert delivered["results"]["handoffClaimToken"] == replacement
    superseded_delivery = run_workbench(
        state_dir,
        "mark-handoff-delivered",
        "--scan-id",
        scan_id,
        "--claim-token",
        owner,
        check=False,
    )
    assert "owned by another continuation" in str(superseded_delivery["stderr"])


def test_workbench_attaches_one_continuation_thread_to_claimed_scan(
    tmp_path: Path,
) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    saved = create_saved_workspace(state_dir, target)
    started = run_workbench(state_dir, "start-scan", "--workspace-id", str(saved["id"]))
    scan_id = str(started["results"]["scanId"])
    claim_token = str(uuid.uuid4())
    run_workbench(
        state_dir, "claim-handoff-delivery", "--scan-id", scan_id, "--claim-token", claim_token
    )

    attached = run_workbench(
        state_dir,
        "attach-scan-continuation-thread",
        "--scan-id",
        scan_id,
        "--claim-token",
        claim_token,
        "--thread-id",
        "continuation-thread",
    )
    assert attached["results"]["continuationThreadId"] == "continuation-thread"

    delivered = run_workbench(
        state_dir,
        "mark-handoff-delivered",
        "--scan-id",
        scan_id,
        "--claim-token",
        claim_token,
        "--thread-id",
        "continuation-thread",
    )
    assert delivered["results"]["handoffStatus"] == "delivered"

    replayed = run_workbench(
        state_dir,
        "attach-scan-continuation-thread",
        "--scan-id",
        scan_id,
        "--claim-token",
        claim_token,
        "--thread-id",
        "continuation-thread",
    )
    assert replayed["results"]["continuationThreadId"] == "continuation-thread"

    wrong_token = run_workbench(
        state_dir,
        "attach-scan-continuation-thread",
        "--scan-id",
        scan_id,
        "--claim-token",
        str(uuid.uuid4()),
        "--thread-id",
        "continuation-thread",
        check=False,
    )
    assert "claim token" in str(wrong_token["stderr"])

    different_thread = run_workbench(
        state_dir,
        "attach-scan-continuation-thread",
        "--scan-id",
        scan_id,
        "--claim-token",
        claim_token,
        "--thread-id",
        "different-thread",
        check=False,
    )
    assert "another continuation" in str(different_thread["stderr"])


def test_workbench_allows_attached_continuation_thread_to_cancel_scan(
    tmp_path: Path,
) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    saved = create_saved_workspace(state_dir, target, thread_id="workspace-thread")
    started = run_workbench(state_dir, "start-scan", "--workspace-id", str(saved["id"]))
    scan_id = str(started["results"]["scanId"])
    claim_token = str(uuid.uuid4())
    run_workbench(
        state_dir, "claim-handoff-delivery", "--scan-id", scan_id, "--claim-token", claim_token
    )
    run_workbench(
        state_dir,
        "attach-scan-continuation-thread",
        "--scan-id",
        scan_id,
        "--claim-token",
        claim_token,
        "--thread-id",
        "continuation-thread",
    )

    canceled = run_workbench(
        state_dir,
        "cancel-scan",
        "--scan-id",
        scan_id,
        "--thread-id",
        "continuation-thread",
    )

    assert canceled["results"]["progress"]["status"] == "canceled"


def test_workbench_releases_attached_continuation_for_a_fresh_handoff(
    tmp_path: Path,
) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    saved = create_saved_workspace(state_dir, target)
    started = run_workbench(state_dir, "start-scan", "--workspace-id", str(saved["id"]))
    scan_id = str(started["results"]["scanId"])
    first_token = str(uuid.uuid4())
    second_token = str(uuid.uuid4())
    run_workbench(
        state_dir, "claim-handoff-delivery", "--scan-id", scan_id, "--claim-token", first_token
    )
    run_workbench(
        state_dir,
        "attach-scan-continuation-thread",
        "--scan-id",
        scan_id,
        "--claim-token",
        first_token,
        "--thread-id",
        "failed-continuation",
    )

    released = run_workbench(
        state_dir,
        "release-handoff-delivery",
        "--scan-id",
        scan_id,
        "--claim-token",
        first_token,
    )
    assert released["results"]["handoffClaimToken"] is None
    assert released["results"]["continuationThreadId"] is None

    run_workbench(
        state_dir, "claim-handoff-delivery", "--scan-id", scan_id, "--claim-token", second_token
    )
    attached = run_workbench(
        state_dir,
        "attach-scan-continuation-thread",
        "--scan-id",
        scan_id,
        "--claim-token",
        second_token,
        "--thread-id",
        "replacement-continuation",
    )

    assert attached["results"]["continuationThreadId"] == "replacement-continuation"


@pytest.mark.parametrize(
    ("command", "arguments"),
    (
        ("update-progress", ("--phase", "discovery")),
        ("complete-scan", ()),
        ("fail-scan", ("--message", "stale continuation stopped")),
    ),
)
def test_released_pending_handoff_rejects_tokenless_mutations(
    tmp_path: Path, command: str, arguments: tuple[str, ...]
) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    saved = create_saved_workspace(state_dir, target)
    started = run_workbench(state_dir, "start-scan", "--workspace-id", str(saved["id"]))
    scan_id = str(started["results"]["scanId"])
    claim_token = str(uuid.uuid4())
    run_workbench(
        state_dir, "claim-handoff-delivery", "--scan-id", scan_id, "--claim-token", claim_token
    )
    run_workbench(
        state_dir,
        "attach-scan-continuation-thread",
        "--scan-id",
        scan_id,
        "--claim-token",
        claim_token,
        "--thread-id",
        "released-continuation",
    )
    run_workbench(
        state_dir, "release-handoff-delivery", "--scan-id", scan_id, "--claim-token", claim_token
    )

    rejected = run_workbench(
        state_dir,
        command,
        "--scan-id",
        scan_id,
        *arguments,
        check=False,
        deliver_unclaimed_scan_before_mutation=False,
    )

    assert "owned by another continuation" in str(rejected["stderr"])
