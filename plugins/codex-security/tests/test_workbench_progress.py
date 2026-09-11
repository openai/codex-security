import json
from pathlib import Path

from workbench_test_support import create_saved_workspace, run_workbench, start_delivered_scan


def test_standard_scan_cannot_leave_discovery_with_open_review_receipts(
    tmp_path: Path,
) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    for index in range(4):
        (target / f"file-{index}.txt").write_text(f"fixture {index}\n")
    saved = create_saved_workspace(state_dir, target)
    started = start_delivered_scan(state_dir, "--workspace-id", str(saved["id"]))
    scan_id = str(started["results"]["scanId"])
    run_workbench(
        state_dir,
        "update-progress",
        "--scan-id",
        scan_id,
        "--phase",
        "discovery",
    )

    rejected = run_workbench(
        state_dir,
        "update-progress",
        "--scan-id",
        scan_id,
        "--phase",
        "validation",
        check=False,
    )

    assert rejected["returncode"] != 0
    assert "Standard scan per-file review receipts are incomplete" in str(rejected["stderr"])
    pending = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]
    assert pending["progress"]["phase"] == "discovery"
    assert pending["progress"]["coverage"] == {
        "closedRows": 0,
        "filesTotal": 4,
        "worklistRows": 4,
    }

    forged = run_workbench(
        state_dir,
        "update-progress",
        "--scan-id",
        scan_id,
        "--phase",
        "validation",
        "--review-items-total",
        "4",
        "--review-items-completed",
        "4",
        check=False,
    )

    assert forged["returncode"] != 0
    assert "per-file review receipts" in str(forged["stderr"])

    reviewed_file_args = [
        argument for index in range(4) for argument in ("--reviewed-file", f"file-{index}.txt")
    ]
    advanced = run_workbench(
        state_dir,
        "update-progress",
        "--scan-id",
        scan_id,
        "--phase",
        "validation",
        *reviewed_file_args,
    )
    assert advanced["scan"]["progress"]["phase"] == "validation"
    assert advanced["scan"]["progress"]["coverage"] == {
        "closedRows": 4,
        "filesTotal": 4,
        "worklistRows": 4,
    }


def test_standard_receipts_bind_content_and_roll_back_rejected_batches(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    (target / "first.py").write_text("first = 1\n")
    (target / "second.py").write_text("second = 2\n")
    saved = create_saved_workspace(state_dir, target)
    started = start_delivered_scan(state_dir, "--workspace-id", str(saved["id"]))
    scan_id = str(started["results"]["scanId"])
    run_workbench(state_dir, "update-progress", "--scan-id", scan_id, "--phase", "discovery")

    (target / "second.py").write_text("changed = 3\n")
    rejected = run_workbench(
        state_dir,
        "update-progress",
        "--scan-id",
        scan_id,
        "--reviewed-file",
        "first.py",
        "--reviewed-file",
        "second.py",
        check=False,
    )
    assert rejected["returncode"] != 0
    assert "no longer matches" in str(rejected["stderr"])
    scan = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]
    assert scan["progress"]["coverage"]["closedRows"] == 0

    (target / "second.py").write_text("second = 2\n")
    for _ in range(2):
        updated = run_workbench(
            state_dir,
            "update-progress",
            "--scan-id",
            scan_id,
            "--reviewed-file",
            "first.py",
            "--reviewed-file",
            "first.py",
        )
        assert updated["scan"]["progress"]["coverage"]["closedRows"] == 1

    (target / "late.py").write_text("not in the original inventory\n")
    unknown = run_workbench(
        state_dir,
        "update-progress",
        "--scan-id",
        scan_id,
        "--reviewed-file",
        "late.py",
        check=False,
    )
    assert unknown["returncode"] != 0
    assert "not in the authoritative scan scope" in str(unknown["stderr"])
    finished = run_workbench(
        state_dir,
        "update-progress",
        "--scan-id",
        scan_id,
        "--phase",
        "validation",
        "--reviewed-file",
        "second.py",
    )
    assert finished["scan"]["progress"]["coverage"] == {
        "closedRows": 2,
        "filesTotal": 2,
        "worklistRows": 2,
    }


def test_validation_clears_discovery_finding_count(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    saved = create_saved_workspace(state_dir, target)
    started = start_delivered_scan(state_dir, "--workspace-id", str(saved["id"]))
    scan_id = str(started["results"]["scanId"])

    discovery = run_workbench(
        state_dir,
        "update-progress",
        "--scan-id",
        scan_id,
        "--phase",
        "discovery",
        "--reportable-findings-count",
        "8",
    )
    assert discovery["scan"]["progress"]["candidates"] == {"reportable": 8}

    validation = run_workbench(
        state_dir,
        "update-progress",
        "--scan-id",
        scan_id,
        "--phase",
        "validation",
    )
    assert validation["scan"]["progress"]["candidates"] == {"reportable": 0}


def test_phase_progress_tracks_and_resets_phase_specific_receipts(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    saved = create_saved_workspace(state_dir, target)
    started = start_delivered_scan(state_dir, "--workspace-id", str(saved["id"]))
    scan_id = str(started["results"]["scanId"])

    discovery = run_workbench(
        state_dir,
        "update-progress",
        "--scan-id",
        scan_id,
        "--phase",
        "discovery",
        "--phase-items-total",
        "6",
        "--phase-items-completed",
        "2",
        "--phase-progress-unit",
        "review_receipts",
    )
    assert discovery["scan"]["progress"]["phaseProgress"] == {
        "completed": 2,
        "total": 6,
        "unit": "review_receipts",
    }

    validation = run_workbench(
        state_dir,
        "update-progress",
        "--scan-id",
        scan_id,
        "--phase",
        "validation",
    )
    assert validation["scan"]["progress"]["phaseProgress"] == {
        "completed": 0,
        "total": 0,
        "unit": None,
    }

    validation_progress = run_workbench(
        state_dir,
        "update-progress",
        "--scan-id",
        scan_id,
        "--phase-items-total",
        "3",
        "--phase-items-completed",
        "1",
        "--phase-progress-unit",
        "candidate_findings",
    )
    assert validation_progress["scan"]["progress"]["phaseProgress"] == {
        "completed": 1,
        "total": 3,
        "unit": "candidate_findings",
    }


def test_phase_progress_rejects_regression_within_one_phase(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    saved = create_saved_workspace(state_dir, target)
    started = start_delivered_scan(state_dir, "--workspace-id", str(saved["id"]))
    scan_id = str(started["results"]["scanId"])
    run_workbench(
        state_dir,
        "update-progress",
        "--scan-id",
        scan_id,
        "--phase-items-total",
        "3",
        "--phase-items-completed",
        "2",
        "--phase-progress-unit",
        "checks",
    )

    regressed = run_workbench(
        state_dir,
        "update-progress",
        "--scan-id",
        scan_id,
        "--phase-items-completed",
        "1",
        check=False,
    )
    assert regressed["returncode"] != 0
    assert "Completed phase items cannot decrease" in str(regressed["stderr"])


def test_preflight_issues_replace_and_remain_visible_after_preflight(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    saved = create_saved_workspace(state_dir, target)
    started = start_delivered_scan(state_dir, "--workspace-id", str(saved["id"]))
    scan_id = str(started["results"]["scanId"])
    blocked_issue = {
        "capability": "usable_worker_slots_6",
        "reason": "Only three usable worker slots are available.",
        "severity": "block",
        "status": "fail",
    }
    blocked = run_workbench(
        state_dir,
        "update-progress",
        "--scan-id",
        scan_id,
        "--phase-items-total",
        "4",
        "--phase-items-completed",
        "4",
        "--phase-progress-unit",
        "checks",
        "--preflight-issues-json",
        json.dumps([blocked_issue]),
    )
    assert blocked["scan"]["progress"]["preflightIssues"] == [blocked_issue]
    assert blocked["scan"]["progress"]["preflightProgress"] == {"completed": 4, "total": 4}

    clean = run_workbench(
        state_dir,
        "update-progress",
        "--scan-id",
        scan_id,
        "--preflight-issues-json",
        "[]",
    )
    assert clean["scan"]["progress"]["preflightIssues"] == []

    warning_issue = {
        "capability": "preferred_worker_slots_6",
        "reason": "The scan will continue with reduced parallelism.",
        "severity": "warn",
        "status": "fail",
    }
    ready = run_workbench(
        state_dir,
        "update-progress",
        "--scan-id",
        scan_id,
        "--phase-items-total",
        "4",
        "--phase-items-completed",
        "4",
        "--phase-progress-unit",
        "checks",
        "--preflight-issues-json",
        json.dumps([warning_issue]),
    )
    assert ready["scan"]["progress"]["preflightIssues"] == [warning_issue]
    assert ready["scan"]["progress"]["preflightProgress"] == {"completed": 4, "total": 4}

    advanced = run_workbench(
        state_dir,
        "update-progress",
        "--scan-id",
        scan_id,
        "--phase",
        "threat_model",
    )
    assert advanced["scan"]["progress"]["preflightIssues"] == [warning_issue]
    assert advanced["scan"]["progress"]["preflightProgress"] == {"completed": 4, "total": 4}

    rejected = run_workbench(
        state_dir,
        "update-progress",
        "--scan-id",
        scan_id,
        "--preflight-issues-json",
        "[]",
        check=False,
    )
    assert rejected["returncode"] != 0
    assert "only be updated during preflight" in str(rejected["stderr"])


def test_preflight_unknown_check_completes_only_after_clean_rerun(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    saved = create_saved_workspace(state_dir, target)
    started = start_delivered_scan(state_dir, "--workspace-id", str(saved["id"]))
    scan_id = str(started["results"]["scanId"])
    unknown_issue = {
        "capability": "delegated_workers",
        "reason": "The runtime did not report worker availability.",
        "severity": "warn",
        "status": "unknown",
    }

    incomplete = run_workbench(
        state_dir,
        "update-progress",
        "--scan-id",
        scan_id,
        "--phase-items-total",
        "4",
        "--phase-items-completed",
        "3",
        "--phase-progress-unit",
        "checks",
        "--preflight-issues-json",
        json.dumps([unknown_issue]),
    )
    assert incomplete["scan"]["progress"]["preflightProgress"] == {
        "completed": 3,
        "total": 4,
    }
    assert incomplete["scan"]["progress"]["preflightIssues"] == [unknown_issue]

    resolved = run_workbench(
        state_dir,
        "update-progress",
        "--scan-id",
        scan_id,
        "--phase-items-total",
        "4",
        "--phase-items-completed",
        "4",
        "--phase-progress-unit",
        "checks",
        "--preflight-issues-json",
        "[]",
    )
    assert resolved["scan"]["progress"]["preflightProgress"] == {
        "completed": 4,
        "total": 4,
    }
    assert resolved["scan"]["progress"]["preflightIssues"] == []


def test_preflight_issues_reject_non_displayable_severity(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    saved = create_saved_workspace(state_dir, target)
    started = start_delivered_scan(state_dir, "--workspace-id", str(saved["id"]))
    rejected = run_workbench(
        state_dir,
        "update-progress",
        "--scan-id",
        str(started["results"]["scanId"]),
        "--preflight-issues-json",
        json.dumps(
            [
                {
                    "capability": "optional_optimization",
                    "reason": "This suggestion is not an attention item.",
                    "severity": "suggest",
                    "status": "fail",
                }
            ]
        ),
        check=False,
    )
    assert rejected["returncode"] != 0
    assert "invalid severity or status" in str(rejected["stderr"])
