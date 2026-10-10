import json
from pathlib import Path

from workbench_test_support import (
    create_saved_workspace,
    start_delivered_scan,
    update_progress,
)


def test_validation_clears_discovery_finding_count(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    saved = create_saved_workspace(state_dir, target)
    started = start_delivered_scan(state_dir, "--workspace-id", str(saved["id"]))
    scan_id = str(started["results"]["scanId"])

    discovery = update_progress(
        state_dir, scan_id, "--phase", "discovery", "--reportable-findings-count", "8"
    )
    assert discovery["scan"]["progress"]["candidates"] == {"reportable": 8}

    validation = update_progress(state_dir, scan_id, "--phase", "validation")
    assert validation["scan"]["progress"]["candidates"] == {"reportable": 0}


def test_phase_progress_tracks_and_resets_phase_specific_receipts(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    saved = create_saved_workspace(state_dir, target)
    started = start_delivered_scan(state_dir, "--workspace-id", str(saved["id"]))
    scan_id = str(started["results"]["scanId"])

    discovery = update_progress(
        state_dir,
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

    validation = update_progress(state_dir, scan_id, "--phase", "validation")
    assert validation["scan"]["progress"]["phaseProgress"] == {
        "completed": 0,
        "total": 0,
        "unit": None,
    }

    validation_progress = update_progress(
        state_dir,
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
    update_progress(
        state_dir,
        scan_id,
        "--phase-items-total",
        "3",
        "--phase-items-completed",
        "2",
        "--phase-progress-unit",
        "checks",
    )

    regressed = update_progress(state_dir, scan_id, "--phase-items-completed", "1", check=False)
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
    blocked = update_progress(
        state_dir,
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

    clean = update_progress(state_dir, scan_id, "--preflight-issues-json", "[]")
    assert clean["scan"]["progress"]["preflightIssues"] == []

    warning_issue = {
        "capability": "preferred_worker_slots_6",
        "reason": "The scan will continue with reduced parallelism.",
        "severity": "warn",
        "status": "fail",
    }
    ready = update_progress(
        state_dir,
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

    advanced = update_progress(state_dir, scan_id, "--phase", "threat_model")
    assert advanced["scan"]["progress"]["preflightIssues"] == [warning_issue]
    assert advanced["scan"]["progress"]["preflightProgress"] == {"completed": 4, "total": 4}

    rejected = update_progress(state_dir, scan_id, "--preflight-issues-json", "[]", check=False)
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

    incomplete = update_progress(
        state_dir,
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

    resolved = update_progress(
        state_dir,
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
    rejected = update_progress(
        state_dir,
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
