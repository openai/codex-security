from __future__ import annotations

import hashlib
import subprocess
import uuid
from pathlib import Path

from workbench_test_support import (
    cancel_remediation_request,
    request_remediation,
    request_remediation_action,
    run_workbench,
    set_remediation,
    start_saved_scan,
    write_completed_contract,
    write_remediation_patch,
)


def test_cancel_finding_remediation_request_restores_previous_state(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
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
    request_remediation_action(
        state_dir,
        occurrence_id,
        request_id,
        str(applied["findings"][0]["remediationState"]["version"]),
        "verify",
        verify_token,
    )
    canceled_verify = cancel_remediation_request(
        state_dir, occurrence_id, request_id, verify_token
    )["scan"]
    restored_after_verify = canceled_verify["findings"][0]["remediationState"]
    assert restored_after_verify["state"] == "applied"
    assert restored_after_verify["pendingAction"] is None
    assert restored_after_verify["actionClaimToken"] is None
