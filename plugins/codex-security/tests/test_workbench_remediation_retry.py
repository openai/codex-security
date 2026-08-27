from __future__ import annotations

import hashlib
import sqlite3
import subprocess
import uuid
from pathlib import Path
from typing import Any

from workbench_test_support import create_saved_workspace, run_workbench, write_completed_contract


def update_remediation(
    state_dir: Path,
    occurrence_id: str,
    request_id: str,
    action_token: str,
    expected_version: int,
    state: str,
    *extra: str,
) -> dict[str, Any]:
    result = run_workbench(
        state_dir,
        "set-finding-remediation",
        "--occurrence-id",
        occurrence_id,
        "--request-id",
        request_id,
        "--action-token",
        action_token,
        "--expected-version",
        str(expected_version),
        "--state",
        state,
        *extra,
    )
    return result["scan"]["findings"][0]["remediationState"]


def test_failed_remediation_steps_can_retry_or_regenerate(tmp_path: Path) -> None:
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

    request_id = str(uuid.uuid4())
    action_token = str(uuid.uuid4())
    run_workbench(
        state_dir,
        "request-finding-remediation",
        "--occurrence-id",
        occurrence_id,
        "--request-id",
        request_id,
        "--action-token",
        action_token,
    )
    run_workbench(
        state_dir,
        "mark-finding-remediation-delivered",
        "--occurrence-id",
        occurrence_id,
        "--request-id",
        request_id,
        "--action-token",
        action_token,
    )
    failed = update_remediation(
        state_dir,
        occurrence_id,
        request_id,
        action_token,
        1,
        "failed",
        "--summary",
        "Patch generation could not access the dependency registry.",
    )
    assert failed["pendingAction"] == "generate"
    assert failed["actionClaimToken"] is None
    assert failed["actionDeliveredAt"] is None

    closed = run_workbench(
        state_dir,
        "set-finding-triage",
        "--occurrence-id",
        occurrence_id,
        "--status",
        "closed",
        "--close-reason",
        "wont_fix",
        "--note",
        "Closing is allowed after the remediation worker has failed.",
    )["scan"]
    assert closed["findings"][0]["triage"]["status"] == "closed"
    run_workbench(
        state_dir,
        "set-finding-triage",
        "--occurrence-id",
        occurrence_id,
        "--status",
        "open",
    )

    resend_token = str(uuid.uuid4())
    resent = run_workbench(
        state_dir,
        "claim-finding-remediation-resend",
        "--occurrence-id",
        occurrence_id,
        "--request-id",
        request_id,
        "--action-token",
        resend_token,
    )["scan"]
    assert resent["findings"][0]["remediationState"]["actionClaimToken"] == resend_token
    delivered = run_workbench(
        state_dir,
        "mark-finding-remediation-delivered",
        "--occurrence-id",
        occurrence_id,
        "--request-id",
        request_id,
        "--action-token",
        resend_token,
    )["scan"]
    assert delivered["findings"][0]["remediationState"]["actionDeliveredAt"]
    canceled = run_workbench(
        state_dir,
        "cancel-finding-remediation-request",
        "--occurrence-id",
        occurrence_id,
        "--request-id",
        request_id,
        "--action-token",
        resend_token,
    )["scan"]["findings"][0]["remediationState"]
    assert canceled["state"] == "failed"
    assert canceled["pendingAction"] == "generate"
    assert canceled["actionClaimToken"] is None
    replayed = run_workbench(
        state_dir,
        "cancel-finding-remediation-request",
        "--occurrence-id",
        occurrence_id,
        "--request-id",
        request_id,
        "--action-token",
        resend_token,
    )["scan"]["findings"][0]["remediationState"]
    assert replayed == canceled

    resend_token = str(uuid.uuid4())
    run_workbench(
        state_dir,
        "claim-finding-remediation-resend",
        "--occurrence-id",
        occurrence_id,
        "--request-id",
        request_id,
        "--action-token",
        resend_token,
    )

    failed_request_id = request_id
    request_id = str(uuid.uuid4())
    action_token = str(uuid.uuid4())
    blocked = run_workbench(
        state_dir,
        "request-finding-remediation",
        "--occurrence-id",
        occurrence_id,
        "--request-id",
        request_id,
        "--action-token",
        action_token,
        check=False,
    )
    assert blocked["returncode"] != 0
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.execute(
            """
            UPDATE finding_remediation_attempts
            SET pending_action_claimed_at = ?
            WHERE request_id = ?
            """,
            ("2000-01-01T00:00:00Z", failed_request_id),
        )
    regenerated = run_workbench(
        state_dir,
        "request-finding-remediation",
        "--occurrence-id",
        occurrence_id,
        "--request-id",
        request_id,
        "--action-token",
        action_token,
    )["scan"]["findings"][0]["remediationState"]
    assert regenerated["state"] == "requested"

    patch_path = scan_dir / "remediation.patch"
    patch_path.write_text(
        "diff --git a/source.txt b/source.txt\n"
        "--- a/source.txt\n"
        "+++ b/source.txt\n"
        "@@ -1 +1 @@\n"
        "-vulnerable\n"
        "+fixed\n"
    )
    patch_digest = f"sha256:{hashlib.sha256(patch_path.read_bytes()).hexdigest()}"
    update_remediation(
        state_dir,
        occurrence_id,
        request_id,
        action_token,
        1,
        "generated",
        "--patch-path",
        patch_path.name,
        "--patch-digest",
        patch_digest,
    )

    apply_token = str(uuid.uuid4())
    run_workbench(
        state_dir,
        "request-finding-remediation-action",
        "--occurrence-id",
        occurrence_id,
        "--request-id",
        request_id,
        "--expected-version",
        "2",
        "--action",
        "apply",
        "--action-token",
        apply_token,
    )
    subprocess.run(["git", "apply", "--no-index", str(patch_path)], cwd=target, check=True)
    failed = update_remediation(
        state_dir,
        occurrence_id,
        request_id,
        apply_token,
        3,
        "failed",
        "--summary",
        "Patch application was interrupted after changing the checkout.",
    )
    assert failed["pendingAction"] == "apply"
    apply_retry_token = str(uuid.uuid4())
    run_workbench(
        state_dir,
        "claim-finding-remediation-resend",
        "--occurrence-id",
        occurrence_id,
        "--request-id",
        request_id,
        "--action-token",
        apply_retry_token,
    )
    applied = update_remediation(
        state_dir,
        occurrence_id,
        request_id,
        apply_retry_token,
        4,
        "applied",
        "--base-revision",
        "unversioned",
    )
    assert applied["state"] == "applied"
    assert applied["summary"] is None

    verify_token = str(uuid.uuid4())
    run_workbench(
        state_dir,
        "request-finding-remediation-action",
        "--occurrence-id",
        occurrence_id,
        "--request-id",
        request_id,
        "--expected-version",
        "5",
        "--action",
        "verify",
        "--action-token",
        verify_token,
    )
    run_workbench(
        state_dir,
        "mark-finding-remediation-delivered",
        "--occurrence-id",
        occurrence_id,
        "--request-id",
        request_id,
        "--action-token",
        verify_token,
    )
    update_remediation(
        state_dir,
        occurrence_id,
        request_id,
        verify_token,
        6,
        "verifying",
        "--base-revision",
        "unversioned",
    )
    failed = update_remediation(
        state_dir,
        occurrence_id,
        request_id,
        verify_token,
        7,
        "failed",
        "--summary",
        "Verification could not reach the dependency registry from the sandbox.",
    )
    assert failed["pendingAction"] == "verify"
    assert failed["actionClaimToken"] is None
    assert failed["actionDeliveredAt"] is None
    verify_retry_token = str(uuid.uuid4())
    run_workbench(
        state_dir,
        "claim-finding-remediation-resend",
        "--occurrence-id",
        occurrence_id,
        "--request-id",
        request_id,
        "--action-token",
        verify_retry_token,
    )
    delivered = run_workbench(
        state_dir,
        "mark-finding-remediation-delivered",
        "--occurrence-id",
        occurrence_id,
        "--request-id",
        request_id,
        "--action-token",
        verify_retry_token,
    )["scan"]["findings"][0]["remediationState"]
    assert delivered["actionDeliveredAt"]
    verified = update_remediation(
        state_dir,
        occurrence_id,
        request_id,
        verify_retry_token,
        8,
        "verified",
        "--base-revision",
        "unversioned",
        "--verification-summary",
        "Focused regression tests passed after permission was granted.",
    )
    assert verified["state"] == "verified"
    assert verified["summary"] is None
