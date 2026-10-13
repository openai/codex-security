from __future__ import annotations

import json
from argparse import Namespace

import pytest
from test_deep_scan_successful_publication import publication_scan as publication_scan
from test_workbench_db import BUDGET_COST, BUDGET_WARNING


@pytest.mark.parametrize("budget_seal", [False, True])
def test_normal_seal_cannot_be_committed_as_budget_completion(
    workbench_api, workbench_db, publication_scan, budget_seal
):
    scan = publication_scan()
    with workbench_db:
        recipe = json.loads(workbench_db.execute("SELECT recipe_json FROM scans").fetchone()[0])
        recipe["maxCostUsd"] = 0.005
        workbench_db.execute("UPDATE scans SET recipe_json = ?", (json.dumps(recipe),))
    if budget_seal:
        row = workbench_db.execute("SELECT * FROM scans").fetchone()
        workbench_api["saved_results"].prepare_budget_draft(
            workbench_api["_WORKBENCH_DB_CONTEXT"], workbench_db, row, BUDGET_WARNING
        )
    workbench_api["complete_scan"](
        workbench_db,
        Namespace(scan_id=scan.scan_id, claim_token=None, cost_json=None),
        prepare_only=True,
    )
    assert workbench_db.execute("SELECT status FROM scans").fetchone()[0] == "running"
    files = {
        str(p.relative_to(scan.scan_dir)): p.read_bytes()
        for p in scan.scan_dir.rglob("*")
        if p.is_file()
    }
    database = list(workbench_db.iterdump())
    args = Namespace(
        scan_id=scan.scan_id, cost_json=json.dumps(BUDGET_COST), message=BUDGET_WARNING
    )
    if budget_seal:
        workbench_api["complete_budget_exhausted_scan"](workbench_db, args)
        assert workbench_db.execute("SELECT status FROM scans").fetchone()[0] == "complete"
        assert (
            json.loads((scan.scan_dir / "coverage.json").read_text())["completeness"] == "partial"
        )
    else:
        with pytest.raises(SystemExit, match="partial"):
            workbench_api["complete_budget_exhausted_scan"](workbench_db, args)
        assert list(workbench_db.iterdump()) == database
    assert {
        str(p.relative_to(scan.scan_dir)): p.read_bytes()
        for p in scan.scan_dir.rglob("*")
        if p.is_file()
    } == files
