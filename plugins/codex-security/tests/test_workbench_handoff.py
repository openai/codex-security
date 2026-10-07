from __future__ import annotations

import sqlite3
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from workbench_test_support import (
    attach_continuation,
    cancel_scan,
    create_saved_workspace,
    create_workspace,
    get_scan,
    mark_handoff_delivered,
    run_workbench,
    save_workspace,
    scan_claim_command,
    scan_command,
    start_scan_command,
    update_progress,
)


@pytest.mark.parametrize("mode", ("standard", "deep"))
def test_running_scan_context_is_owned_by_attached_continuation(tmp_path: Path, mode: str) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    original_thread_id = "original-thread"
    continuation_thread_id = "continuation-thread"
    saved = create_saved_workspace(state_dir, target, thread_id=original_thread_id, mode=mode)
    started = start_scan_command(state_dir, str(saved["id"]))
    scan_id = str(started["results"]["scanId"])
    claim_token = str(uuid.uuid4())
    scan_claim_command(state_dir, "claim-handoff-delivery", scan_id, claim_token)
    attach_continuation(state_dir, scan_id, claim_token, continuation_thread_id)

    updated_context = "Prioritize password-reset token validation."
    updated = scan_command(
        state_dir,
        "update-scan-context",
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
        rejected_owner = scan_command(
            state_dir,
            "update-scan-context",
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

    rejected_claim = scan_command(
        state_dir,
        "update-scan-context",
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

    persisted = get_scan(state_dir, scan_id)
    assert persisted["scan"]["userContext"] == updated_context
    assert persisted["workspace"]["userContext"] == updated_context


def test_workbench_serializes_concurrent_handoff_delivery(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    saved = create_saved_workspace(state_dir, target)
    started = start_scan_command(state_dir, str(saved["id"]))
    scan_id = str(started["results"]["scanId"])
    claim_token = str(uuid.uuid4())
    scan_claim_command(state_dir, "claim-handoff-delivery", scan_id, claim_token)

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(
            executor.map(
                lambda _: mark_handoff_delivered(state_dir, scan_id, claim_token),
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
    create_workspace(state_dir, workspace_id, "--target-path", str(target))
    save_workspace(state_dir, workspace_id, str(target), ".", "deep")
    started = start_scan_command(state_dir, workspace_id)
    scan_id = str(started["results"]["scanId"])
    claim_token = str(uuid.uuid4())
    scan_claim_command(state_dir, "claim-handoff-delivery", scan_id, claim_token)

    delivered = mark_handoff_delivered(state_dir, scan_id, claim_token)

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
    delivered_scan = start_scan_command(state_dir, str(delivered_workspace["id"]))
    pending_scan = start_scan_command(state_dir, str(pending_workspace["id"]))
    delivered_scan_id = str(delivered_scan["results"]["scanId"])
    pending_scan_id = str(pending_scan["results"]["scanId"])
    delivered_token = str(uuid.uuid4())
    pending_token = str(uuid.uuid4())
    scan_claim_command(state_dir, "claim-handoff-delivery", delivered_scan_id, delivered_token)
    mark_handoff_delivered(state_dir, delivered_scan_id, delivered_token)
    scan_claim_command(state_dir, "claim-handoff-delivery", pending_scan_id, pending_token)
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
    updated = update_progress(state_dir, delivered_scan_id, "--phase", "discovery")
    assert updated["scan"]["progress"]["phase"] == "discovery"


def test_workbench_handoff_claim_is_owned_by_one_token(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    saved = create_saved_workspace(state_dir, target)
    started = start_scan_command(state_dir, str(saved["id"]))
    scan_id = str(started["results"]["scanId"])
    tokens = [str(uuid.uuid4()), str(uuid.uuid4())]
    with ThreadPoolExecutor(max_workers=2) as executor:
        claims = list(
            executor.map(
                lambda token: scan_claim_command(
                    state_dir, "claim-handoff-delivery", scan_id, token
                ),
                tokens,
            )
        )
    owners = {claim["results"]["handoffClaimToken"] for claim in claims}
    assert len(owners) == 1
    owner = owners.pop()
    non_owner = next(token for token in tokens if token != owner)
    wrong_release = scan_claim_command(state_dir, "release-handoff-delivery", scan_id, non_owner)
    assert wrong_release["results"]["handoffClaimToken"] == owner
    wrong_delivery = mark_handoff_delivered(state_dir, scan_id, non_owner, check=False)
    assert "delivery could not be recorded" in str(wrong_delivery["stderr"])


def test_workbench_handoff_claim_only_allows_stale_takeover(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    saved = create_saved_workspace(state_dir, target)
    started = start_scan_command(state_dir, str(saved["id"]))
    scan_id = str(started["results"]["scanId"])
    owner = str(uuid.uuid4())
    replacement = str(uuid.uuid4())
    scan_claim_command(state_dir, "claim-handoff-delivery", scan_id, owner)
    attach_continuation(state_dir, scan_id, owner, "stale-continuation")
    live = scan_claim_command(
        state_dir, "claim-handoff-delivery", scan_id, replacement, "--take-over-stale"
    )
    assert live["results"]["handoffClaimToken"] == owner
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE scans SET handoff_claimed_at = ? WHERE id = ?",
            ("2000-01-01T00:00:00Z", scan_id),
        )
    stale = scan_claim_command(
        state_dir, "claim-handoff-delivery", scan_id, replacement, "--take-over-stale"
    )
    assert stale["results"]["handoffClaimToken"] == replacement
    assert stale["results"]["continuationThreadId"] is None
    for claim_token in (None, owner):
        rejected_update = update_progress(
            state_dir,
            scan_id,
            "--phase",
            "discovery",
            *(() if claim_token is None else ("--claim-token", claim_token)),
            check=False,
        )
        assert "owned by another continuation" in str(rejected_update["stderr"])
    attached = attach_continuation(state_dir, scan_id, replacement, "replacement-continuation")
    assert attached["results"]["continuationThreadId"] == "replacement-continuation"
    delivered = mark_handoff_delivered(state_dir, scan_id, replacement)
    assert delivered["results"]["handoffClaimToken"] == replacement
    superseded_delivery = mark_handoff_delivered(state_dir, scan_id, owner, check=False)
    assert "owned by another continuation" in str(superseded_delivery["stderr"])


def test_workbench_attaches_one_continuation_thread_to_claimed_scan(
    tmp_path: Path,
) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    saved = create_saved_workspace(state_dir, target)
    started = start_scan_command(state_dir, str(saved["id"]))
    scan_id = str(started["results"]["scanId"])
    claim_token = str(uuid.uuid4())
    scan_claim_command(state_dir, "claim-handoff-delivery", scan_id, claim_token)

    attached = attach_continuation(state_dir, scan_id, claim_token, "continuation-thread")
    assert attached["results"]["continuationThreadId"] == "continuation-thread"

    delivered = mark_handoff_delivered(
        state_dir, scan_id, claim_token, "--thread-id", "continuation-thread"
    )
    assert delivered["results"]["handoffStatus"] == "delivered"

    replayed = attach_continuation(state_dir, scan_id, claim_token, "continuation-thread")
    assert replayed["results"]["continuationThreadId"] == "continuation-thread"

    wrong_token = attach_continuation(
        state_dir, scan_id, str(uuid.uuid4()), "continuation-thread", check=False
    )
    assert "claim token" in str(wrong_token["stderr"])

    different_thread = attach_continuation(
        state_dir, scan_id, claim_token, "different-thread", check=False
    )
    assert "another continuation" in str(different_thread["stderr"])


def test_workbench_allows_attached_continuation_thread_to_cancel_scan(
    tmp_path: Path,
) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    saved = create_saved_workspace(state_dir, target, thread_id="workspace-thread")
    started = start_scan_command(state_dir, str(saved["id"]))
    scan_id = str(started["results"]["scanId"])
    claim_token = str(uuid.uuid4())
    scan_claim_command(state_dir, "claim-handoff-delivery", scan_id, claim_token)
    attach_continuation(state_dir, scan_id, claim_token, "continuation-thread")

    canceled = cancel_scan(state_dir, scan_id, "continuation-thread")

    assert canceled["results"]["progress"]["status"] == "canceled"


def test_workbench_releases_attached_continuation_for_a_fresh_handoff(
    tmp_path: Path,
) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    saved = create_saved_workspace(state_dir, target)
    started = start_scan_command(state_dir, str(saved["id"]))
    scan_id = str(started["results"]["scanId"])
    first_token = str(uuid.uuid4())
    second_token = str(uuid.uuid4())
    scan_claim_command(state_dir, "claim-handoff-delivery", scan_id, first_token)
    attach_continuation(state_dir, scan_id, first_token, "failed-continuation")

    released = scan_claim_command(state_dir, "release-handoff-delivery", scan_id, first_token)
    assert released["results"]["handoffClaimToken"] is None
    assert released["results"]["continuationThreadId"] is None

    scan_claim_command(state_dir, "claim-handoff-delivery", scan_id, second_token)
    attached = attach_continuation(state_dir, scan_id, second_token, "replacement-continuation")

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
    started = start_scan_command(state_dir, str(saved["id"]))
    scan_id = str(started["results"]["scanId"])
    claim_token = str(uuid.uuid4())
    scan_claim_command(state_dir, "claim-handoff-delivery", scan_id, claim_token)
    attach_continuation(state_dir, scan_id, claim_token, "released-continuation")
    scan_claim_command(state_dir, "release-handoff-delivery", scan_id, claim_token)

    rejected = scan_command(state_dir, command, scan_id, *arguments, check=False)

    assert "owned by another continuation" in str(rejected["stderr"])
    assert get_scan(state_dir, scan_id)["scan"]["handoffStatus"] == "pending"
