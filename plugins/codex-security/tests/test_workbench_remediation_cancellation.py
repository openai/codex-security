from __future__ import annotations

import hashlib
import subprocess
import uuid
from pathlib import Path

import pytest
from workbench_test_support import (
    cancel_remediation_request,
    empty_target_paths,
    mark_remediation_delivered,
    request_remediation,
    request_remediation_action,
    run_workbench,
    set_remediation,
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

    canceled_request_id = str(uuid.uuid4())
    canceled_token = str(uuid.uuid4())
    requested_initial = request_remediation(
        state_dir, occurrence_id, canceled_request_id, canceled_token
    )["scan"]
    canceled_initial = cancel_remediation_request(
        state_dir, occurrence_id, canceled_request_id, canceled_token
    )["scan"]
    assert canceled_initial["findings"][0]["remediationState"] == {"state": "idle"}
    assert canceled_initial["updatedAt"] > requested_initial["updatedAt"]
    replayed_cancel = cancel_remediation_request(
        state_dir, occurrence_id, canceled_request_id, canceled_token
    )["scan"]
    assert replayed_cancel["findings"][0]["remediationState"] == {"state": "idle"}

    request_id = str(uuid.uuid4())
    generation_token = str(uuid.uuid4())
    request_remediation(state_dir, occurrence_id, request_id, generation_token)
    patch_path = scan_dir / "remediation.patch"
    write_remediation_patch(patch_path)
    generated = set_remediation(
        state_dir,
        occurrence_id,
        request_id,
        generation_token,
        "1",
        "generated",
        "--patch-path",
        patch_path.name,
        "--patch-digest",
        f"sha256:{hashlib.sha256(patch_path.read_bytes()).hexdigest()}",
    )["scan"]
    assert generated["findings"][0]["remediationState"]["state"] == "generated"

    replacement_request_id = str(uuid.uuid4())
    replacement_token = str(uuid.uuid4())
    request_remediation(state_dir, occurrence_id, replacement_request_id, replacement_token)
    canceled_replacement = cancel_remediation_request(
        state_dir, occurrence_id, replacement_request_id, replacement_token
    )["scan"]
    restored = canceled_replacement["findings"][0]["remediationState"]
    assert restored["requestId"] == request_id
    assert restored["state"] == "generated"
    assert restored["pendingAction"] is None
    assert restored["patchPath"] == patch_path.name

    apply_token = str(uuid.uuid4())
    request_remediation_action(
        state_dir, occurrence_id, request_id, str(restored["version"]), "apply", apply_token
    )
    canceled_apply = cancel_remediation_request(state_dir, occurrence_id, request_id, apply_token)[
        "scan"
    ]
    restored_after_apply = canceled_apply["findings"][0]["remediationState"]
    assert restored_after_apply["state"] == "generated"
    assert restored_after_apply["pendingAction"] is None
    assert restored_after_apply["actionClaimToken"] is None

    apply_token = str(uuid.uuid4())
    apply_requested = request_remediation_action(
        state_dir,
        occurrence_id,
        request_id,
        str(restored_after_apply["version"]),
        "apply",
        apply_token,
    )["scan"]
    subprocess.run(["git", "apply", "--no-index", str(patch_path)], cwd=target, check=True)
    applied = set_remediation(
        state_dir,
        occurrence_id,
        request_id,
        apply_token,
        str(apply_requested["findings"][0]["remediationState"]["version"]),
        "applied",
        "--base-revision",
        "unversioned",
    )["scan"]

    verify_token = str(uuid.uuid4())
    verify_requested = request_remediation_action(
        state_dir,
        occurrence_id,
        request_id,
        str(applied["findings"][0]["remediationState"]["version"]),
        "verify",
        verify_token,
    )["scan"]["findings"][0]["remediationState"]
    if verification_started:
        mark_remediation_delivered(state_dir, occurrence_id, request_id, verify_token)
        verify_requested = set_remediation(
            state_dir,
            occurrence_id,
            request_id,
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
        request_id,
        "--action-token",
        str(uuid.uuid4()),
        check=False,
    )
    assert wrong_owner["returncode"] != 0
    assert "owned by a different action token" in wrong_owner["stderr"]
    canceled_verify = cancel_remediation_request(
        state_dir, occurrence_id, request_id, verify_token
    )["scan"]
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
    replayed_verify = cancel_remediation_request(
        state_dir, occurrence_id, request_id, verify_token
    )["scan"]["findings"][0]["remediationState"]
    assert replayed_verify == restored_after_verify

    stale_update = set_remediation(
        state_dir,
        occurrence_id,
        request_id,
        verify_token,
        str(verify_requested["version"]),
        "failed",
        check=False,
    )
    assert stale_update["returncode"] != 0
    assert "This remediation request changed" in stale_update["stderr"]
    retried_verify = request_remediation_action(
        state_dir,
        occurrence_id,
        request_id,
        str(restored_after_verify["version"]),
        "verify",
        str(uuid.uuid4()),
    )["scan"]["findings"][0]["remediationState"]
    assert retried_verify["pendingAction"] == "verify"
