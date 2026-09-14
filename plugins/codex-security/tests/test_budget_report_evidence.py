from __future__ import annotations

import json
from argparse import Namespace

import pytest
from test_budget_selection_publication import accept_unmerged
from test_deep_scan_successful_publication import add_worker
from test_deep_scan_successful_publication import publication_scan as publication_scan
from test_workbench_db import BUDGET_COST


@pytest.mark.parametrize("accepted", [False, True], ids=["unfinished-audit", "accepted-unmerged"])
def test_empty_budget_report_does_not_deny_saved_validation(
    workbench_api, workbench_db, publication_scan, accepted
):
    scan = publication_scan()
    if accepted:
        evidence = accept_unmerged(workbench_db, scan)
    else:
        result = add_worker(workbench_db, scan, status="running")
        checkpoints = result.parent / "checkpoints"
        checkpoints.mkdir()
        evidence = checkpoints / ("a" * 64 + ".json")
        evidence.write_text(
            json.dumps(
                {
                    "scanId": scan.scan_id,
                    "complete": False,
                    "findings": scan.findings,
                    "coverage": {**scan.coverage, "completeness": "partial"},
                }
            )
        )
        (result.parent / "checkpoint-head.json").write_text(
            json.dumps({"checkpoint": evidence.name})
        )
    original = evidence.read_bytes()
    with workbench_db:
        recipe = json.loads(workbench_db.execute("SELECT recipe_json FROM scans").fetchone()[0])
        recipe["maxCostUsd"] = 0.005
        workbench_db.execute("UPDATE scans SET recipe_json = ?", (json.dumps(recipe),))
        workbench_db.execute(
            "UPDATE deep_scan_runs SET status = 'running', phase = 'discovery', "
            "workflow_version = 'deep-security-scan/v2', manifest_path = NULL, "
            "terminal_reason = NULL, completed_at = NULL"
        )
    for name in ("scan-manifest.json", "findings.json", "coverage.json"):
        (scan.scan_dir / name).unlink()

    workbench_api["complete_budget_exhausted_scan"](
        workbench_db,
        Namespace(scan_id=scan.scan_id, cost_json=json.dumps(BUDGET_COST), message=None),
    )
    assert evidence.read_bytes() == original
    assert json.loads(original)["findings"]
    assert json.loads((scan.scan_dir / "findings.json").read_text())["findings"] == []
    assert json.loads((scan.scan_dir / "coverage.json").read_text())["completeness"] == "partial"
    report = (scan.scan_dir / "report.md").read_text()
    assert "No findings were validated" not in report
    assert "No findings are included in this partial report." in report
    assert "Review the unresolved work in Open Questions And Follow Up." in report
