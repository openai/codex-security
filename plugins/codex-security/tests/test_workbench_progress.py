import json
import sqlite3
from pathlib import Path

from workbench_test_support import (
    create_saved_workspace,
    empty_target_paths,
    start_delivered_scan,
    update_progress,
)


def test_progress_preserves_phase_receipts_until_validation(tmp_path: Path) -> None:
    state_dir, target = empty_target_paths(tmp_path)
    saved = create_saved_workspace(state_dir, target)
    started = start_delivered_scan(state_dir, "--workspace-id", str(saved["id"]))
    scan_id = str(started["results"]["scanId"])

    discovery = update_progress(
        state_dir,
        scan_id,
        "--phase",
        "discovery",
        "--reportable-findings-count",
        "8",
        "--phase-items-total",
        "6",
        "--phase-items-completed",
        "2",
        "--phase-progress-unit",
        "review_receipts",
    )
    assert discovery["scan"]["progress"]["candidates"] == {"reportable": 8}
    assert discovery["scan"]["progress"]["phaseProgress"] == {
        "completed": 2,
        "total": 6,
        "unit": "review_receipts",
    }

    regressed = update_progress(state_dir, scan_id, "--phase-items-completed", "1", check=False)
    assert regressed["returncode"] != 0
    assert "Completed phase items cannot decrease" in str(regressed["stderr"])

    validation = update_progress(state_dir, scan_id, "--phase", "validation")
    assert validation["scan"]["progress"]["candidates"] == {"reportable": 0}
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


def test_historical_preflight_issues_survive_progress_updates(tmp_path: Path) -> None:
    state_dir, target = empty_target_paths(tmp_path)
    saved = create_saved_workspace(state_dir, target)
    started = start_delivered_scan(state_dir, "--workspace-id", str(saved["id"]))
    scan_id = str(started["results"]["scanId"])
    issues = [
        {
            "capability": "delegated_workers",
            "reason": "Unavailable",
            "severity": "warn",
            "status": "fail",
        }
    ]
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE scan_progress SET preflight_issues_json = ? WHERE scan_id = ?",
            (json.dumps(issues), scan_id),
        )
    advanced = update_progress(state_dir, scan_id, "--phase", "threat_model")
    assert advanced["scan"]["progress"]["preflightIssues"] == issues
