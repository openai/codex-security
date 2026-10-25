import json
import sqlite3
from pathlib import Path

import pytest
from workbench_test_support import (
    create_saved_workspace,
    run_workbench,
    start_delivered_scan,
    update_progress,
)


@pytest.mark.parametrize("null_collections", [False, True])
def test_unresolved_count_preserves_progress_with_incomplete_canonical_drafts(
    tmp_path: Path, null_collections: bool
) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    saved = create_saved_workspace(state_dir, target)
    started = start_delivered_scan(state_dir, "--workspace-id", str(saved["id"]))
    scan_id = str(started["results"]["scanId"])
    scan_dir = Path(started["results"]["scanDir"])
    coverage = {
        "surfaces": None if null_collections else [None, "unfinished surface"],
        "explicitExclusions": None,
        "deferred": [
            None,
            "unfinished candidate",
            {
                "candidateId": "pending-parser-review",
                "reason": "The parser route needs validation.",
            },
        ],
    }
    findings = {
        "findings": None
        if null_collections
        else [None, "unfinished finding", {"provenance": None, "extensions": "unfinished"}]
    }
    coverage_path = scan_dir / "coverage.json"
    findings_path = scan_dir / "findings.json"
    coverage_path.write_text(json.dumps(coverage))
    findings_path.write_text(json.dumps(findings))

    current = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]
    updated = run_workbench(
        state_dir, "update-progress", "--scan-id", scan_id, "--phase", "discovery"
    )["scan"]
    history = run_workbench(state_dir, "list-scans")["scans"][0]

    for scan in (current, updated):
        assert scan["progress"]["status"] == "running"
        assert scan["progress"]["candidates"]["unresolved"] == 1
    assert history["progress"]["status"] == "running"
    assert "unresolved" not in history["progress"]["candidates"]
    assert updated["progress"]["phase"] == "discovery"
    assert json.loads(coverage_path.read_text()) == coverage
    assert json.loads(findings_path.read_text()) == findings


def test_usage_list_coverage_is_invalid(workbench_api):
    from workbench_validation import _valid_measured_scan_usage

    assert not _valid_measured_scan_usage(
        {"coverage": ["complete"], "source": "codex_rollout", "threadCount": 0}
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
    assert discovery["scan"]["progress"]["candidates"] == {"reportable": 8, "unresolved": 0}

    validation = update_progress(state_dir, scan_id, "--phase", "validation")
    assert validation["scan"]["progress"]["candidates"] == {"reportable": 0, "unresolved": 0}


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


def test_historical_preflight_issues_survive_progress_updates(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
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
