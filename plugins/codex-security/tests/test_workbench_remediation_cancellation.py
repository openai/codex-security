from __future__ import annotations

import subprocess
import uuid
from pathlib import Path

import pytest
from workbench_test_support import (
    RemediationRequest,
    empty_target_paths,
    run_workbench,
    start_saved_scan,
    write_completed_contract,
    write_remediation_patch,
)


@pytest.mark.parametrize("verification_started", [False, True])
def test_cancel_finding_remediation_request_restores_previous_state(
    tmp_path: Path, verification_started: bool
) -> None:
    state_dir, target = empty_target_paths(tmp_path)
    source = target / "source.txt"
    source.write_text("vulnerable\n")
    scan_id, scan_dir = start_saved_scan(state_dir, target, tmp_path / "scans")
    write_completed_contract(scan_dir, scan_id, target, relative_path=source.name)
    completed = run_workbench(state_dir, "complete-scan", "--scan-id", scan_id)["scan"]
    occurrence_id = str(completed["findings"][0]["occurrenceId"])

    canceled_request = RemediationRequest(state_dir, occurrence_id)
    canceled_token = str(uuid.uuid4())
    requested_initial = canceled_request.start(canceled_token)["scan"]
    canceled_initial = canceled_request.cancel(canceled_token)["scan"]
    assert canceled_initial["findings"][0]["remediationState"] == {"state": "idle"}
    assert canceled_initial["updatedAt"] > requested_initial["updatedAt"]
    replayed_cancel = canceled_request.cancel(canceled_token)["scan"]
    assert replayed_cancel["findings"][0]["remediationState"] == {"state": "idle"}

    request = RemediationRequest(state_dir, occurrence_id)
    generation_token = str(uuid.uuid4())
    request.start(generation_token)
    patch_path = scan_dir / "remediation.patch"
    write_remediation_patch(patch_path)
    generated = request.generate(generation_token, patch_path)["scan"]
    assert generated["findings"][0]["remediationState"]["state"] == "generated"

    replacement_request = RemediationRequest(state_dir, occurrence_id)
    replacement_token = str(uuid.uuid4())
    replacement_request.start(replacement_token)
    canceled_replacement = replacement_request.cancel(replacement_token)["scan"]
    restored = canceled_replacement["findings"][0]["remediationState"]
    assert restored["requestId"] == request.id
    assert restored["state"] == "generated"
    assert restored["pendingAction"] is None
    assert restored["patchPath"] == patch_path.name

    apply_token = str(uuid.uuid4())
    request.request_action(str(restored["version"]), "apply", apply_token)
    canceled_apply = request.cancel(apply_token)["scan"]
    restored_after_apply = canceled_apply["findings"][0]["remediationState"]
    assert restored_after_apply["state"] == "generated"
    assert restored_after_apply["pendingAction"] is None
    assert restored_after_apply["actionClaimToken"] is None

    apply_token = str(uuid.uuid4())
    apply_requested = request.request_action(
        str(restored_after_apply["version"]), "apply", apply_token
    )["scan"]
    subprocess.run(["git", "apply", "--no-index", str(patch_path)], cwd=target, check=True)
    applied = request.update(
        apply_token,
        str(apply_requested["findings"][0]["remediationState"]["version"]),
        "applied",
        "--base-revision",
        "unversioned",
    )["scan"]

    verify_token = str(uuid.uuid4())
    verify_requested = request.request_action(
        str(applied["findings"][0]["remediationState"]["version"]), "verify", verify_token
    )["scan"]["findings"][0]["remediationState"]
    if verification_started:
        request.mark_delivered(verify_token)
        verify_requested = request.update(
            verify_token,
            str(verify_requested["version"]),
            "verifying",
            "--base-revision",
            "unversioned",
        )["scan"]["findings"][0]["remediationState"]
    wrong_owner = run_workbench(
        state_dir,
        "cancel-finding-remediation-request",
        "--occurrence-id",
        occurrence_id,
        "--request-id",
        request.id,
        "--action-token",
        str(uuid.uuid4()),
        check=False,
    )
    assert wrong_owner["returncode"] != 0
    assert "owned by a different action token" in wrong_owner["stderr"]
    canceled_verify = request.cancel(verify_token)["scan"]
    restored_after_verify = canceled_verify["findings"][0]["remediationState"]
    assert restored_after_verify["state"] == "applied"
    assert restored_after_verify["pendingAction"] is None
    assert restored_after_verify["actionClaimToken"] is None
    assert restored_after_verify["actionClaimedAt"] is None
    assert restored_after_verify["actionDeliveredAt"] is None
    assert restored_after_verify["version"] == verify_requested["version"] + 1
    assert restored_after_verify["patchPath"] == patch_path.name
    assert restored_after_verify["patchDigest"] == verify_requested["patchDigest"]
    assert source.read_text() == "fixed\n"
    replayed_verify = request.cancel(verify_token)["scan"]["findings"][0]["remediationState"]
    assert replayed_verify == restored_after_verify

    stale_update = request.update(
        verify_token, str(verify_requested["version"]), "failed", check=False
    )
    assert stale_update["returncode"] != 0
    assert "This remediation request changed" in stale_update["stderr"]
    retried_verify = request.request_action(
        str(restored_after_verify["version"]), "verify", str(uuid.uuid4())
    )["scan"]["findings"][0]["remediationState"]
    assert retried_verify["pendingAction"] == "verify"
