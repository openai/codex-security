from __future__ import annotations

import hashlib
import subprocess
import uuid
from pathlib import Path

from workbench_test_support import create_saved_workspace, run_workbench, write_completed_contract


def test_cancel_finding_remediation_request_restores_previous_state(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    source = target / "source.txt"
    source.write_text("vulnerable\n")
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
    scan_dir = Path(str(started["results"]["scanDir"]))
    write_completed_contract(scan_dir, scan_id, target, relative_path=source.name)
    completed = run_workbench(state_dir, "complete-scan", "--scan-id", scan_id)["scan"]
    occurrence_id = str(completed["findings"][0]["occurrenceId"])

    canceled_request_id = str(uuid.uuid4())
    canceled_token = str(uuid.uuid4())
    requested_initial = run_workbench(
        state_dir,
        "request-finding-remediation",
        "--occurrence-id",
        occurrence_id,
        "--request-id",
        canceled_request_id,
        "--action-token",
        canceled_token,
    )["scan"]
    canceled_initial = run_workbench(
        state_dir,
        "cancel-finding-remediation-request",
        "--occurrence-id",
        occurrence_id,
        "--request-id",
        canceled_request_id,
        "--action-token",
        canceled_token,
    )["scan"]
    assert canceled_initial["findings"][0]["remediationState"] == {"state": "idle"}
    assert canceled_initial["updatedAt"] > requested_initial["updatedAt"]
    replayed_cancel = run_workbench(
        state_dir,
        "cancel-finding-remediation-request",
        "--occurrence-id",
        occurrence_id,
        "--request-id",
        canceled_request_id,
        "--action-token",
        canceled_token,
    )["scan"]
    assert replayed_cancel["findings"][0]["remediationState"] == {"state": "idle"}

    request_id = str(uuid.uuid4())
    generation_token = str(uuid.uuid4())
    run_workbench(
        state_dir,
        "request-finding-remediation",
        "--occurrence-id",
        occurrence_id,
        "--request-id",
        request_id,
        "--action-token",
        generation_token,
    )
    patch_path = scan_dir / "remediation.patch"
    patch_path.write_text(
        "diff --git a/source.txt b/source.txt\n"
        "--- a/source.txt\n"
        "+++ b/source.txt\n"
        "@@ -1 +1 @@\n"
        "-vulnerable\n"
        "+fixed\n"
    )
    generated = run_workbench(
        state_dir,
        "set-finding-remediation",
        "--occurrence-id",
        occurrence_id,
        "--request-id",
        request_id,
        "--action-token",
        generation_token,
        "--expected-version",
        "1",
        "--state",
        "generated",
        "--patch-path",
        patch_path.name,
        "--patch-digest",
        f"sha256:{hashlib.sha256(patch_path.read_bytes()).hexdigest()}",
    )["scan"]
    assert generated["findings"][0]["remediationState"]["state"] == "generated"

    replacement_request_id = str(uuid.uuid4())
    replacement_token = str(uuid.uuid4())
    run_workbench(
        state_dir,
        "request-finding-remediation",
        "--occurrence-id",
        occurrence_id,
        "--request-id",
        replacement_request_id,
        "--action-token",
        replacement_token,
    )
    canceled_replacement = run_workbench(
        state_dir,
        "cancel-finding-remediation-request",
        "--occurrence-id",
        occurrence_id,
        "--request-id",
        replacement_request_id,
        "--action-token",
        replacement_token,
    )["scan"]
    restored = canceled_replacement["findings"][0]["remediationState"]
    assert restored["requestId"] == request_id
    assert restored["state"] == "generated"
    assert restored["pendingAction"] is None
    assert restored["patchPath"] == patch_path.name

    apply_token = str(uuid.uuid4())
    run_workbench(
        state_dir,
        "request-finding-remediation-action",
        "--occurrence-id",
        occurrence_id,
        "--request-id",
        request_id,
        "--expected-version",
        str(restored["version"]),
        "--action",
        "apply",
        "--action-token",
        apply_token,
    )
    canceled_apply = run_workbench(
        state_dir,
        "cancel-finding-remediation-request",
        "--occurrence-id",
        occurrence_id,
        "--request-id",
        request_id,
        "--action-token",
        apply_token,
    )["scan"]
    restored_after_apply = canceled_apply["findings"][0]["remediationState"]
    assert restored_after_apply["state"] == "generated"
    assert restored_after_apply["pendingAction"] is None
    assert restored_after_apply["actionClaimToken"] is None

    apply_token = str(uuid.uuid4())
    apply_requested = run_workbench(
        state_dir,
        "request-finding-remediation-action",
        "--occurrence-id",
        occurrence_id,
        "--request-id",
        request_id,
        "--expected-version",
        str(restored_after_apply["version"]),
        "--action",
        "apply",
        "--action-token",
        apply_token,
    )["scan"]
    subprocess.run(["git", "apply", "--no-index", str(patch_path)], cwd=target, check=True)
    applied = run_workbench(
        state_dir,
        "set-finding-remediation",
        "--occurrence-id",
        occurrence_id,
        "--request-id",
        request_id,
        "--action-token",
        apply_token,
        "--expected-version",
        str(apply_requested["findings"][0]["remediationState"]["version"]),
        "--state",
        "applied",
        "--base-revision",
        "unversioned",
    )["scan"]

    verify_token = str(uuid.uuid4())
    run_workbench(
        state_dir,
        "request-finding-remediation-action",
        "--occurrence-id",
        occurrence_id,
        "--request-id",
        request_id,
        "--expected-version",
        str(applied["findings"][0]["remediationState"]["version"]),
        "--action",
        "verify",
        "--action-token",
        verify_token,
    )
    canceled_verify = run_workbench(
        state_dir,
        "cancel-finding-remediation-request",
        "--occurrence-id",
        occurrence_id,
        "--request-id",
        request_id,
        "--action-token",
        verify_token,
    )["scan"]
    restored_after_verify = canceled_verify["findings"][0]["remediationState"]
    assert restored_after_verify["state"] == "applied"
    assert restored_after_verify["pendingAction"] is None
    assert restored_after_verify["actionClaimToken"] is None
